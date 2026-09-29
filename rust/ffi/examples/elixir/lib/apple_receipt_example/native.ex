defmodule AppleReceiptExample.Native do
  @moduledoc """
  The raw NIF surface, one function per entry point in `c_src/aprv_nif.c`.

  Nothing here is idiomatic on purpose: arguments are the integers and
  binaries the C ABI takes, and the return values are what the shim builds.
  `AppleReceiptExample` is the layer that makes them pleasant. Call this
  module directly only when you want to see the boundary.

  Every function below is replaced by its native implementation when the
  shared object loads. The bodies that raise are what a caller hits if it
  did not, which is a build problem rather than a runtime one, so they say
  so instead of returning an error tuple.
  """

  @on_load :load_nif

  @doc false
  def load_nif do
    :erlang.load_nif(:filename.join(:code.priv_dir(:apple_receipt_example), ~c"aprv_nif"), 0)
  end

  @doc "The library version, from `aprv_version`."
  @spec version() :: binary()
  def version, do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  `aprv_verifier_new`. `roots` is a list of DER certificates, or `[]` for the
  three bundled Apple roots; `clock_unix_millis` pins the clock, and `nil`
  reads the system clock.
  """
  @spec verifier_new([binary()], integer() | nil) ::
          {:ok, reference()} | {:error, :invalid_argument}
  def verifier_new(_roots, _clock_unix_millis), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  `aprv_verify_receipt_bytes`: the base64 receipt an app sends, as bytes.
  The binary is the document `aprv.wasm` answers,
  `{"verified":true,"payload":...}` or
  `{"verified":false,"reason":...,"message":...}`; it is empty for a status
  of 100 or above, a mistake in the call.
  """
  @spec verify_receipt(reference(), binary()) ::
          {:ok, binary()} | {:error, integer(), binary()}
  def verify_receipt(_verifier, _receipt_base64), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  `aprv_verify_signed_data_bytes`: any Apple-signed compact JWS, as bytes.
  The same document as `verify_receipt/2`; a verified payload is a JSON
  string holding the signed text, exactly.
  """
  @spec verify_signed_data(reference(), binary()) ::
          {:ok, binary()} | {:error, integer(), binary()}
  def verify_signed_data(_verifier, _jws), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  `aprv_verify_receipt_endpoint_bytes`. The Apple verdict is a field of the
  body, so `{:error, status}` here means the call itself was malformed.
  """
  @spec verify_receipt_endpoint(reference(), non_neg_integer(), binary()) ::
          {:ok, binary()} | {:error, integer()}
  def verify_receipt_endpoint(_verifier, _environment, _request_json),
    do: :erlang.nif_error(:nif_not_loaded)
end
