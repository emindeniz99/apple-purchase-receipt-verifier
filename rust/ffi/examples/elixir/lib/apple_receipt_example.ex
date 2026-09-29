defmodule AppleReceiptExample do
  @moduledoc """
  Offline verification of Apple App Store payloads from Elixir, over the C
  ABI in `rust/ffi`.

  This is an example, not a package. It shows the shape a real Elixir client
  would take: a verifier built once and shared, verification calls that
  return a decoded map, and a reason atom instead of a status number.

  A verifier is a reference to a native handle. It is immutable and safe to
  share between processes, and the garbage collector releases it, so there is
  nothing to close.

      {:ok, verifier} = AppleReceiptExample.verifier()
      {:ok, claims} = AppleReceiptExample.verify_signed_data(verifier, jws)

  A failed verification is `{:error, reason, body}`, where `reason` is one of
  the eight canonical tokens every port of this library shares and `body`
  also carries a short non-sensitive message. Match on the reason; never
  parse the message.
  """

  alias AppleReceiptExample.Native

  @environments %{production: 1, sandbox: 2}

  # The 1..99 band is a verdict about the input; the 100+ band is a mistake
  # in the call itself and means nothing about the input was checked. Keeping
  # both as atoms keeps the distinction visible at the call site.
  @reasons %{
    2 => :invalid_certificate,
    3 => :invalid_certificate_purpose,
    5 => :invalid_signature,
    12 => :internal_error,
    13 => :malformed,
    14 => :too_large,
    15 => :untrusted_chain,
    16 => :unreadable_payload,
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
  A verifier. Options are `:roots`, a list of DER certificates that replaces
  the three bundled Apple roots, and `:clock_unix_millis`, which pins the
  clock (for tests and conformance vectors; the system clock otherwise).

  The clock is read in two places: the certificate-validity instant when the
  input states no usable signing date, and the endpoint's `request_date`. No
  payload is rejected for its age: how old a signed payload may be is the
  caller's decision.
  """
  @spec verifier(keyword()) :: {:ok, verifier()} | {:error, :invalid_argument}
  def verifier(options \\ []) do
    Native.verifier_new(
      Keyword.get(options, :roots, []),
      Keyword.get(options, :clock_unix_millis)
    )
  end

  @doc """
  Verifies a legacy app receipt given as the base64 an app sends, and
  returns every field it carries. The caller compares `bundle_id` and
  anything else it grants on.
  """
  @spec verify_receipt(verifier(), binary()) :: outcome()
  def verify_receipt(verifier, receipt_base64),
    do: decode(Native.verify_receipt(verifier, receipt_base64))

  @doc """
  Verifies any Apple-signed compact JWS and returns its claims. No claim is
  enforced: the caller checks bundle id, environment and anything else.
  """
  @spec verify_signed_data(verifier(), binary()) :: outcome()
  def verify_signed_data(verifier, jws), do: decode(Native.verify_signed_data(verifier, jws))

  @doc """
  Handles one `verifyReceipt` request body as `:production` or `:sandbox`
  and returns Apple's response body.

  Like Apple's own endpoint this never reports a verification failure
  through the tuple: the verdict is the `status` field inside the map. An
  `{:error, reason}` here means the call itself was malformed.
  """
  @spec verify_receipt_endpoint(verifier(), atom(), binary()) ::
          {:ok, map()} | {:error, atom() | integer()}
  def verify_receipt_endpoint(verifier, environment, request_json) do
    code = Map.fetch!(@environments, environment)

    case Native.verify_receipt_endpoint(verifier, code, request_json) do
      {:ok, body} -> {:ok, decode_json!(body)}
      {:error, status} -> {:error, reason(status)}
    end
  end

  @doc "The reason atom for a status code from the ABI."
  @spec reason(integer()) :: atom() | integer()
  def reason(status), do: Map.get(@reasons, status, status)

  @doc """
  Decodes one JSON document the ABI handed back. A member name that repeats
  in an object keeps its last value.

  A JWS payload comes back exactly as signed, so a repeated member, such as
  two `signedDate`s, reaches the caller intact. The verifier reads the last
  one, as `JSON.parse` does, and judges the chain at that instant.
  `JSON.decode!/1` keeps the first, which would hand the caller a different
  `signedDate` from the one the signature was checked against. Each object's
  members arrive in reverse document order, so building the map from them
  re-reversed lets the last one win.
  """
  @spec decode_json!(binary()) :: term()
  def decode_json!(text) do
    case JSON.decode(text, :ok, object_finish: &last_member_wins/2) do
      {decoded, :ok, ""} ->
        decoded

      {_decoded, :ok, rest} ->
        raise ArgumentError, "trailing content after the JSON: #{inspect(rest)}"

      {:error, reason} ->
        raise ArgumentError, "not JSON: #{inspect(reason)}"
    end
  end

  defp last_member_wins(members, outer), do: {members |> Enum.reverse() |> Map.new(), outer}

  @doc """
  The verified payload of a document a verify call answered,
  `{"verified":true,"payload":...}`: a receipt's payload is an object, and
  a JWS's is a JSON string holding the signed text, exactly, which is
  decoded in turn.
  """
  @spec payload!(binary()) :: term()
  def payload!(document) do
    case decode_json!(document) do
      %{"verified" => true, "payload" => signed} when is_binary(signed) -> decode_json!(signed)
      %{"verified" => true, "payload" => payload} -> payload
      other -> raise ArgumentError, "not a verified document: #{inspect(other)}"
    end
  end

  defp decode({:ok, json}), do: {:ok, payload!(json)}

  # A mistake in the call (status 100 and above) comes with no document.
  defp decode({:error, status, ""}), do: {:error, reason(status), %{}}

  defp decode({:error, status, json}),
    do: {:error, reason(status), json |> decode_json!() |> Map.delete("verified")}
end
