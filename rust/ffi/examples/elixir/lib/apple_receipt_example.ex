defmodule AppleReceiptExample do
  @moduledoc """
  Offline verification of Apple App Store payloads from Elixir, over the C
  ABI in `rust/ffi`.

  This is an example, not a package. It shows the shape a real Elixir client
  would take: a handle built once and shared, verification calls that return
  a decoded map, and a reason atom instead of a status number.

  A verifier is a reference to a native handle. It is immutable and safe to
  share between processes, and the garbage collector releases it, so there is
  nothing to close.

      {:ok, verifier} = AppleReceiptExample.jws_verifier("com.example.app", [:sandbox])
      {:ok, claims} = AppleReceiptExample.verify_transaction(verifier, jws)

  A failed verification is `{:error, reason, body}`, where `reason` is one of
  the eleven canonical tokens every port of this library shares and `body`
  also carries a short non-sensitive message. Match on the reason; never
  parse the message.
  """

  alias AppleReceiptExample.Json
  alias AppleReceiptExample.Native

  @environments %{production: 1, sandbox: 2, xcode: 4, local_testing: 8}

  # The 1..11 band is a verdict about the input; the 100+ band is a mistake
  # in the call itself and means nothing about the input was checked. Keeping
  # both as atoms keeps the distinction visible at the call site.
  @reasons %{
    1 => :invalid_jws_format,
    2 => :invalid_certificate,
    3 => :invalid_certificate_purpose,
    4 => :invalid_chain,
    5 => :invalid_signature,
    6 => :wrong_bundle_id,
    7 => :wrong_environment,
    8 => :wrong_app_apple_id,
    9 => :invalid_receipt_format,
    10 => :device_hash_mismatch,
    11 => :stale_payload,
    100 => :null_pointer,
    101 => :invalid_utf8,
    102 => :invalid_argument,
    103 => :panic,
    104 => :unknown_reason
  }

  @type verifier :: reference()
  @type outcome :: {:ok, map()} | {:error, atom() | integer(), map()}

  @doc "The version of the library behind the ABI."
  @spec version() :: binary()
  defdelegate version(), to: Native

  @doc """
  A verifier for Apple-signed JWS payloads.

  `environments` is a list of `:production`, `:sandbox`, `:xcode` or
  `:local_testing`, or the bitmask itself for a caller that already has one.
  Options are `:app_apple_id` (required to accept a Production
  `AppTransaction`), `:max_signed_age_secs` and `:roots`, a list of DER
  certificates that replaces the three bundled Apple roots.
  """
  @spec jws_verifier(binary(), [atom()] | non_neg_integer(), keyword()) ::
          {:ok, verifier()} | {:error, :invalid_argument}
  def jws_verifier(bundle_id, environments, options \\ []) do
    Native.jws_verifier_new(
      bundle_id,
      mask(environments),
      Keyword.get(options, :app_apple_id, 0),
      Keyword.get(options, :max_signed_age_secs, 0),
      Keyword.get(options, :roots, [])
    )
  end

  @doc "A verifier for legacy PKCS#7 app receipts. Takes the `:roots` option."
  @spec receipt_verifier(binary(), keyword()) :: {:ok, verifier()} | {:error, :invalid_argument}
  def receipt_verifier(bundle_id, options \\ []) do
    Native.receipt_verifier_new(bundle_id, Keyword.get(options, :roots, []))
  end

  @doc """
  A local `verifyReceipt` endpoint for `:production` or `:sandbox`. The
  choice drives the 21007/21008 routing. Takes the `:roots` option.
  """
  @spec endpoint(atom(), keyword()) :: {:ok, verifier()} | {:error, :invalid_argument}
  def endpoint(environment, options \\ []) do
    Native.endpoint_new(mask([environment]), Keyword.get(options, :roots, []))
  end

  @doc "Verifies a signed transaction, then checks bundle id and environment."
  @spec verify_transaction(verifier(), binary()) :: outcome()
  def verify_transaction(verifier, jws), do: decode(Native.verify_transaction(verifier, jws))

  @doc """
  Verifies a signed `AppTransaction`, then checks bundle id, environment and,
  in Production, the app Apple id.
  """
  @spec verify_app_transaction(verifier(), binary()) :: outcome()
  def verify_app_transaction(verifier, jws),
    do: decode(Native.verify_app_transaction(verifier, jws))

  @doc """
  Verifies the chain and signature only, and returns every claim. No claim is
  enforced, so the caller must check bundle id, environment and app Apple id
  itself. For renewal info and notification envelopes.
  """
  @spec verify_raw(verifier(), binary()) :: outcome()
  def verify_raw(verifier, jws), do: decode(Native.verify_raw(verifier, jws))

  @doc """
  Verifies a legacy app receipt in its raw DER form. With `:device_guid` set
  it also checks that attribute 5 equals
  `SHA1(guid <> opaqueValue <> bundleIdBytes)`.
  """
  @spec verify_receipt(verifier(), binary(), keyword()) :: outcome()
  def verify_receipt(verifier, der, options \\ []) do
    decode(Native.verify_receipt_der(verifier, der, Keyword.get(options, :device_guid, "")))
  end

  @doc "Verifies a legacy app receipt given as the base64 a client sends."
  @spec verify_receipt_base64(verifier(), binary(), keyword()) :: outcome()
  def verify_receipt_base64(verifier, receipt_base64, options \\ []) do
    decode(
      Native.verify_receipt_base64(
        verifier,
        receipt_base64,
        Keyword.get(options, :device_guid, "")
      )
    )
  end

  @doc """
  Handles one `verifyReceipt` request body and returns Apple's response body.

  The request is JSON, because that is what a client posts. Like Apple's own
  endpoint this never reports a verification failure through the tuple: the
  verdict is the `status` field inside the map. An `{:error, reason}` here
  means the call itself was malformed.
  """
  @spec verify_receipt_endpoint(verifier(), binary()) ::
          {:ok, map()} | {:error, atom() | integer()}
  def verify_receipt_endpoint(endpoint, request_json) do
    case Native.verify_receipt_endpoint_json(endpoint, request_json) do
      {:ok, body} -> {:ok, Json.decode!(body)}
      {:error, status} -> {:error, reason(status)}
    end
  end

  @doc "The reason atom for a status code from the ABI."
  @spec reason(integer()) :: atom() | integer()
  def reason(status), do: Map.get(@reasons, status, status)

  defp decode({:ok, json}), do: {:ok, Json.decode!(json)}
  defp decode({:error, status, json}), do: {:error, reason(status), Json.decode!(json)}

  defp mask(bits) when is_integer(bits), do: bits

  defp mask(environments) when is_list(environments) do
    Enum.reduce(environments, 0, fn name, acc ->
      case Map.fetch(@environments, name) do
        {:ok, bit} -> Bitwise.bor(acc, bit)
        :error -> raise ArgumentError, "unknown environment #{inspect(name)}"
      end
    end)
  end
end
