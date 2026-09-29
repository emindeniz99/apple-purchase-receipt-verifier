using System;
using System.Collections.Generic;
using System.Globalization;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// Reads the JSON <c>aprv.wasm</c> answers with, and moves it into the
    /// public types. It decides nothing: a verdict is the module's, and this
    /// only reads it. An answer that does not have the shape the wire defines
    /// (0.7's canonical JSON) is an <see cref="AnswerException"/>, which the
    /// verifier reports as <see cref="VerificationReason.InternalError"/> with
    /// the exception as the cause. It is never guessed at.
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
        /// Checks <c>init</c>'s answer. <c>{"ok":true}</c> passes;
        /// <c>{"ok":false,"message":"..."}</c> is the module refusing the
        /// configuration, which is the caller's roots.
        /// </summary>
        /// <exception cref="ArgumentException">The module refused the roots.</exception>
        /// <exception cref="AnswerException">The answer is not init's.</exception>
        internal static void CheckInit(string answer)
        {
            OrderedMap map = ParseObject(answer);
            bool ok = Bool(map, "ok");
            if (ok)
            {
                RequireOnly(map, "ok");
                return;
            }

            RequireOnly(map, "ok", "message");
            throw new ArgumentException("the module refused the configured roots: " + Str(map, "message"));
        }

        /// <summary>A <c>verify-receipt</c> answer as a result.</summary>
        internal static VerificationResult<ReceiptPayload> ReadReceipt(string answer)
        {
            OrderedMap map = ParseObject(answer);
            if (Verdict(map, out VerificationReason reason, out string message))
            {
                RequireOnly(map, "verified", "payload");
                return VerificationResult<ReceiptPayload>.Ok(Receipt(Obj(map, "payload")));
            }

            return VerificationResult<ReceiptPayload>.Failed(reason, message, null);
        }

        /// <summary>A <c>verify-signed-data</c> answer as a result.</summary>
        internal static VerificationResult<JsonPayload> ReadSignedData(string answer)
        {
            OrderedMap map = ParseObject(answer);
            if (Verdict(map, out VerificationReason reason, out string message))
            {
                RequireOnly(map, "verified", "payload");
                return VerificationResult<JsonPayload>.Ok(JsonPayload.Create(Str(map, "payload")));
            }

            return VerificationResult<JsonPayload>.Failed(reason, message, null);
        }

        private static bool Verdict(OrderedMap map, out VerificationReason reason, out string message)
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

        private static ReceiptPayload Receipt(OrderedMap json)
        {
            RequireKeys(json, ReceiptKeys, "the receipt payload");
            List<InAppPurchase> inApp = new List<InAppPurchase>();
            foreach (object? entry in Arr(json, "in_app"))
            {
                inApp.Add(Purchase(entry as OrderedMap ?? throw new AnswerException("an in_app entry is not an object")));
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
                Unknown(json));
        }

        private static InAppPurchase Purchase(OrderedMap json)
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

        private static IReadOnlyDictionary<int, IReadOnlyList<byte[]>> Unknown(OrderedMap json)
        {
            OrderedMap map = Obj(json, "unknown_attributes");
            Dictionary<int, IReadOnlyList<byte[]>> attributes = new Dictionary<int, IReadOnlyList<byte[]>>(map.Count);
            foreach (KeyValuePair<string, object?> entry in map)
            {
                if (!int.TryParse(entry.Key, NumberStyles.None, CultureInfo.InvariantCulture, out int type))
                {
                    throw new AnswerException("an unknown_attributes key is not a decimal attribute type");
                }

                List<byte[]> values = new List<byte[]>();
                foreach (object? value in entry.Value as List<object?> ?? throw new AnswerException("an unknown_attributes value is not an array"))
                {
                    values.Add(Base64(value as string ?? throw new AnswerException("an unknown attribute is not a string")));
                }

                attributes[type] = values;
            }

            return attributes;
        }

        private static OrderedMap ParseObject(string answer)
        {
            try
            {
                return Json.ParseObject(answer, int.MaxValue);
            }
            catch (JsonException e)
            {
                throw new AnswerException("the module's answer is not a JSON object: " + e.Message);
            }
        }

        private static void RequireOnly(OrderedMap map, params string[] keys)
        {
            RequireKeys(map, keys, "the module's answer");
        }

        private static void RequireKeys(OrderedMap map, string[] keys, string what)
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

        private static bool Bool(OrderedMap map, string key) =>
            map.TryGetValue(key, out object? value) && value is bool flag
                ? flag
                : throw new AnswerException("\"" + key + "\" is missing or not a boolean");

        private static string Str(OrderedMap map, string key) =>
            map.TryGetValue(key, out object? value) && value is string text
                ? text
                : throw new AnswerException("\"" + key + "\" is missing or not a string");

        private static OrderedMap Obj(OrderedMap map, string key) =>
            map.TryGetValue(key, out object? value) && value is OrderedMap inner
                ? inner
                : throw new AnswerException("\"" + key + "\" is missing or not an object");

        private static List<object?> Arr(OrderedMap map, string key) =>
            map.TryGetValue(key, out object? value) && value is List<object?> list
                ? list
                : throw new AnswerException("\"" + key + "\" is missing or not an array");

        private static string? OptStr(OrderedMap map, string key)
        {
            object? value = map[key];
            return value is null ? null : value as string ?? throw new AnswerException("\"" + key + "\" is not a string");
        }

        private static long? OptLong(OrderedMap map, string key)
        {
            object? value = map[key];
            return value is null ? (long?)null : value is long number ? number : throw new AnswerException("\"" + key + "\" is not an integer");
        }

        private static bool? OptBool(OrderedMap map, string key)
        {
            object? value = map[key];
            return value is null ? (bool?)null : value is bool flag ? flag : throw new AnswerException("\"" + key + "\" is not a boolean");
        }

        private static long? OptId(OrderedMap map, string key)
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

        private static byte[]? OptBytes(OrderedMap map, string key)
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
