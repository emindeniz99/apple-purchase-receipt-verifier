using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// Reads the JSON <c>aprv.wasm</c> answers with, and moves it into the
    /// public types. It decides nothing: a verdict is the module's, and this
    /// only reads it. An answer that does not have the shape the wire defines
    /// (0.7's canonical JSON) is an <see cref="AnswerException"/>, which the
    /// verifier reports as <see cref="VerificationReason.InternalError"/> with
    /// the exception as the cause. It is never guessed at. A member that
    /// appears twice counts once, with its last value.
    /// </summary>
    internal static class ModuleAnswers
    {
        /// <summary>A module answer that is not the wire's JSON, or a member of the wrong type.</summary>
        internal sealed class AnswerException : Exception
        {
            internal AnswerException(string message)
                : base(message)
            {
            }
        }

        private static readonly string[] ReceiptKeys =
        {
            "receipt_type", "app_item_id", "bundle_id", "bundle_id_bytes", "application_version",
            "opaque_value", "sha1_hash", "receipt_creation_date_ms", "download_id",
            "version_external_identifier", "in_app", "original_purchase_date_ms",
            "original_application_version", "expiration_date_ms", "unknown_attributes",
        };

        private static readonly string[] PurchaseKeys =
        {
            "quantity", "product_id", "transaction_id", "purchase_date_ms", "original_transaction_id",
            "original_purchase_date_ms", "expires_date_ms", "web_order_line_item_id",
            "cancellation_date_ms", "is_trial_period", "is_in_intro_offer_period", "unknown_attributes",
        };

        /// <summary>
        /// Checks <c>init</c>'s answer and returns the input length it states.
        /// <c>{"ok":true,"max_input_bytes":N}</c> passes, <c>N</c> being the most
        /// bytes of one input the module needs (docs/rust-core/DECISIONS.md
        /// R42): a longer input is cut to it, and the module answers TOO_LARGE
        /// for that. <c>{"ok":false,"message":"..."}</c> is the module refusing
        /// the configuration, which is the caller's roots. An accepting answer
        /// without a positive integer <c>N</c> comes from a module of another
        /// ABI version, and is not init's answer.
        /// </summary>
        /// <exception cref="ArgumentException">The module refused the roots.</exception>
        /// <exception cref="AnswerException">The answer is not init's.</exception>
        internal static int CheckInit(string answer)
        {
            string message;
            using (JsonDocument document = ParseObject(answer))
            {
                Dictionary<string, JsonElement> map = Members(document.RootElement);
                bool ok = Bool(map, "ok");
                if (ok)
                {
                    if (!map.TryGetValue("max_input_bytes", out JsonElement max)
                        || max.ValueKind != JsonValueKind.Number
                        || !max.TryGetInt32(out int maxInputBytes)
                        || maxInputBytes <= 0)
                    {
                        throw new AnswerException(
                            "init accepted the configuration but states no max_input_bytes: the module is of another ABI version");
                    }

                    RequireOnly(map, "ok", "max_input_bytes");
                    return maxInputBytes;
                }

                RequireOnly(map, "ok", "message");
                message = Str(map, "message");
            }

            throw new ArgumentException("the module refused the configured roots: " + message);
        }

        /// <summary>A <c>verify-receipt</c> answer as a result.</summary>
        internal static VerificationResult<ReceiptPayload> ReadReceipt(string answer)
        {
            using (JsonDocument document = ParseObject(answer))
            {
                Dictionary<string, JsonElement> map = Members(document.RootElement);
                if (Verdict(map, out VerificationReason reason, out string message))
                {
                    RequireOnly(map, "verified", "payload", "environment");
                    return VerificationResult<ReceiptPayload>.Ok(Receipt(Obj(map, "payload"), StatedEnvironment(map)));
                }

                return VerificationResult<ReceiptPayload>.Failed(reason, message, null);
            }
        }

        /// <summary>A <c>verify-signed-data</c> answer as a result.</summary>
        internal static VerificationResult<JsonPayload> ReadSignedData(string answer)
        {
            using (JsonDocument document = ParseObject(answer))
            {
                Dictionary<string, JsonElement> map = Members(document.RootElement);
                if (Verdict(map, out VerificationReason reason, out string message))
                {
                    RequireOnly(map, "verified", "payload", "environment");
                    return VerificationResult<JsonPayload>.Ok(JsonPayload.Create(Str(map, "payload"), StatedEnvironment(map)));
                }

                return VerificationResult<JsonPayload>.Failed(reason, message, null);
            }
        }

        private static bool Verdict(Dictionary<string, JsonElement> map, out VerificationReason reason, out string message)
        {
            reason = default;
            message = string.Empty;
            if (Bool(map, "verified"))
            {
                return true;
            }

            RequireOnly(map, "verified", "reason", "message");
            string token = Str(map, "reason");
            if (!VerificationReasonCodes.TryParse(token, out reason))
            {
                throw new AnswerException("the module answered a reason outside the eight: " + Printable(token));
            }

            message = Str(map, "message");
            return false;
        }

        /// <summary>
        /// A verified answer's <c>environment</c>, beside its payload:
        /// <c>"Production"</c>, <c>"Sandbox"</c> or <c>null</c>, the
        /// environment the module read (docs/rust-core/DECISIONS.md R42).
        /// </summary>
        private static AppleEnvironment? StatedEnvironment(Dictionary<string, JsonElement> map)
        {
            JsonElement value = map["environment"];
            if (value.ValueKind == JsonValueKind.Null)
            {
                return null;
            }

            if (value.ValueKind == JsonValueKind.String)
            {
                switch (Text(value))
                {
                    case "Production":
                        return AppleEnvironment.Production;
                    case "Sandbox":
                        return AppleEnvironment.Sandbox;
                }
            }

            throw new AnswerException("\"environment\" is not \"Production\", \"Sandbox\" or null");
        }

        private static ReceiptPayload Receipt(Dictionary<string, JsonElement> json, AppleEnvironment? environment)
        {
            RequireKeys(json, ReceiptKeys, "the receipt payload");
            List<InAppPurchase> inApp = new List<InAppPurchase>();
            foreach (JsonElement entry in Arr(json, "in_app"))
            {
                inApp.Add(Purchase(entry.ValueKind == JsonValueKind.Object
                    ? Members(entry)
                    : throw new AnswerException("an in_app entry is not an object")));
            }

            return new ReceiptPayload(
                OptStr(json, "receipt_type"),
                OptId(json, "app_item_id"),
                OptStr(json, "bundle_id"),
                OptBytes(json, "bundle_id_bytes"),
                OptStr(json, "application_version"),
                OptBytes(json, "opaque_value"),
                OptBytes(json, "sha1_hash"),
                OptLong(json, "receipt_creation_date_ms"),
                OptId(json, "download_id"),
                OptId(json, "version_external_identifier"),
                inApp,
                OptLong(json, "original_purchase_date_ms"),
                OptStr(json, "original_application_version"),
                OptLong(json, "expiration_date_ms"),
                Unknown(json),
                environment);
        }

        private static InAppPurchase Purchase(Dictionary<string, JsonElement> json)
        {
            RequireKeys(json, PurchaseKeys, "an in_app entry");
            return new InAppPurchase(
                OptLong(json, "quantity"),
                OptStr(json, "product_id"),
                OptStr(json, "transaction_id"),
                OptLong(json, "purchase_date_ms"),
                OptStr(json, "original_transaction_id"),
                OptLong(json, "original_purchase_date_ms"),
                OptLong(json, "expires_date_ms"),
                OptId(json, "web_order_line_item_id"),
                OptLong(json, "cancellation_date_ms"),
                OptBool(json, "is_trial_period"),
                OptBool(json, "is_in_intro_offer_period"),
                Unknown(json));
        }

        private static IReadOnlyDictionary<int, IReadOnlyList<byte[]>> Unknown(Dictionary<string, JsonElement> json)
        {
            Dictionary<string, JsonElement> map = Obj(json, "unknown_attributes");
            Dictionary<int, IReadOnlyList<byte[]>> attributes = new Dictionary<int, IReadOnlyList<byte[]>>(map.Count);
            foreach (KeyValuePair<string, JsonElement> entry in map)
            {
                if (!int.TryParse(entry.Key, NumberStyles.None, CultureInfo.InvariantCulture, out int type))
                {
                    throw new AnswerException("an unknown_attributes key is not a decimal attribute type");
                }

                if (entry.Value.ValueKind != JsonValueKind.Array)
                {
                    throw new AnswerException("an unknown_attributes value is not an array");
                }

                List<byte[]> values = new List<byte[]>();
                foreach (JsonElement value in entry.Value.EnumerateArray())
                {
                    values.Add(Base64(value.ValueKind == JsonValueKind.String
                        ? Text(value)
                        : throw new AnswerException("an unknown attribute is not a string")));
                }

                attributes[type] = values;
            }

            return attributes;
        }

        /// <summary>The answer as a document whose root is an object; the caller disposes it.</summary>
        private static JsonDocument ParseObject(string answer)
        {
            JsonDocument document;
            try
            {
                document = Json.Parse(answer);
            }
            catch (JsonException e)
            {
                throw new AnswerException("the module's answer is not JSON: " + e.Message);
            }

            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                document.Dispose();
                throw new AnswerException("the module's answer is not a JSON object");
            }

            return document;
        }

        /// <summary>
        /// An object's members by name; a name that appears twice keeps its
        /// last value. A name holding a <c>\u</c> escape of a lone surrogate
        /// parses but has no value, as in <see cref="Text"/>.
        /// </summary>
        private static Dictionary<string, JsonElement> Members(JsonElement json)
        {
            Dictionary<string, JsonElement> members = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (JsonProperty member in json.EnumerateObject())
            {
                string name;
                try
                {
                    name = member.Name;
                }
                catch (InvalidOperationException)
                {
                    throw new AnswerException("a member name in the module's answer is not valid UTF-16");
                }

                members[name] = member.Value;
            }

            return members;
        }

        /// <summary>A string's value. A <c>\u</c> escape of a lone surrogate parses but has no value.</summary>
        private static string Text(JsonElement json)
        {
            try
            {
                return json.GetString()!;
            }
            catch (InvalidOperationException)
            {
                throw new AnswerException("a string in the module's answer is not valid UTF-16");
            }
        }

        private static void RequireOnly(Dictionary<string, JsonElement> map, params string[] keys)
        {
            RequireKeys(map, keys, "the module's answer");
        }

        private static void RequireKeys(Dictionary<string, JsonElement> map, string[] keys, string what)
        {
            if (map.Count != keys.Length)
            {
                throw new AnswerException(what + " does not have the members the wire defines");
            }

            foreach (string key in keys)
            {
                if (!map.ContainsKey(key))
                {
                    throw new AnswerException(what + " has no \"" + key + "\" member");
                }
            }
        }

        private static bool Bool(Dictionary<string, JsonElement> map, string key) =>
            map.TryGetValue(key, out JsonElement value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? value.GetBoolean()
                : throw new AnswerException("\"" + key + "\" is missing or not a boolean");

        private static string Str(Dictionary<string, JsonElement> map, string key) =>
            map.TryGetValue(key, out JsonElement value) && value.ValueKind == JsonValueKind.String
                ? Text(value)
                : throw new AnswerException("\"" + key + "\" is missing or not a string");

        private static Dictionary<string, JsonElement> Obj(Dictionary<string, JsonElement> map, string key) =>
            map.TryGetValue(key, out JsonElement value) && value.ValueKind == JsonValueKind.Object
                ? Members(value)
                : throw new AnswerException("\"" + key + "\" is missing or not an object");

        private static JsonElement.ArrayEnumerator Arr(Dictionary<string, JsonElement> map, string key) =>
            map.TryGetValue(key, out JsonElement value) && value.ValueKind == JsonValueKind.Array
                ? value.EnumerateArray()
                : throw new AnswerException("\"" + key + "\" is missing or not an array");

        private static string? OptStr(Dictionary<string, JsonElement> map, string key)
        {
            JsonElement value = map[key];
            return value.ValueKind switch
            {
                JsonValueKind.Null => null,
                JsonValueKind.String => Text(value),
                _ => throw new AnswerException("\"" + key + "\" is not a string"),
            };
        }

        /// <summary>An integer that fits 64 bits: <c>1.0</c>, <c>1e3</c> and a 20-digit number are not.</summary>
        private static long? OptLong(Dictionary<string, JsonElement> map, string key)
        {
            JsonElement value = map[key];
            if (value.ValueKind == JsonValueKind.Null)
            {
                return null;
            }

            return value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out long number)
                ? number
                : throw new AnswerException("\"" + key + "\" is not an integer");
        }

        private static bool? OptBool(Dictionary<string, JsonElement> map, string key)
        {
            JsonElement value = map[key];
            return value.ValueKind switch
            {
                JsonValueKind.Null => null,
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                _ => throw new AnswerException("\"" + key + "\" is not a boolean"),
            };
        }

        private static long? OptId(Dictionary<string, JsonElement> map, string key)
        {
            string? text = OptStr(map, key);
            if (text is null)
            {
                return null;
            }

            return long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long id)
                ? id
                : throw new AnswerException("\"" + key + "\" is not a 64-bit id");
        }

        private static byte[]? OptBytes(Dictionary<string, JsonElement> map, string key)
        {
            string? text = OptStr(map, key);
            return text is null ? null : Base64(text);
        }

        private static byte[] Base64(string text)
        {
            try
            {
                return Convert.FromBase64String(text);
            }
            catch (FormatException)
            {
                throw new AnswerException("a byte field is not base64");
            }
        }

        private static string Printable(string token)
        {
            const int Limit = 40;
            System.Text.StringBuilder builder = new System.Text.StringBuilder();
            foreach (char c in token.Length > Limit ? token.Substring(0, Limit) : token)
            {
                builder.Append(c >= ' ' && c <= '~' ? c : '?');
            }

            return builder.ToString();
        }
    }
}
