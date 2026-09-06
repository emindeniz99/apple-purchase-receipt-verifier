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
  `aprv_verifier_new_jws`, `aprv_verifier_new_jws_with_roots` when `roots` is
  a non-empty list of DER certificates, or
  `aprv_verifier_new_jws_with_roots_and_clock` when `clock_unix_millis` is an
  integer rather than `nil`.

  `nil` is the ABI's NULL clock pointer: the system clock, which is what the
  other two constructors read. Pinning an instant is for conformance vectors
  and tests.
  """
  @spec jws_verifier_new(
          binary(),
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer(),
          [binary()],
          integer() | nil
        ) :: {:ok, reference()} | {:error, :invalid_argument}
  def jws_verifier_new(
        _bundle_id,
        _environments,
        _app_apple_id,
        _max_signed_age_secs,
        _roots,
        _clock_unix_millis
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  `aprv_verifier_new_receipt`, or the `_with_roots` variant.

  There is no clock argument because the ABI has none here: an injected clock
  must never be able to accept an expired chain.
  """
  @spec receipt_verifier_new(binary(), [binary()]) ::
          {:ok, reference()} | {:error, :invalid_argument}
  def receipt_verifier_new(_bundle_id, _roots), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  `aprv_endpoint_new`, the `_with_roots` variant, or
  `aprv_endpoint_new_with_roots_and_clock` when `clock_unix_millis` is an
  integer. `nil` reads the system clock.
  """
  @spec endpoint_new(non_neg_integer(), [binary()], integer() | nil) ::
          {:ok, reference()} | {:error, :invalid_argument}
  def endpoint_new(_environment, _roots, _clock_unix_millis),
    do: :erlang.nif_error(:nif_not_loaded)

  @doc "`aprv_verify_transaction`."
  @spec verify_transaction(reference(), binary()) ::
          {:ok, binary()} | {:error, integer(), binary()}
  def verify_transaction(_verifier, _jws), do: :erlang.nif_error(:nif_not_loaded)

  @doc "`aprv_verify_app_transaction`."
  @spec verify_app_transaction(reference(), binary()) ::
          {:ok, binary()} | {:error, integer(), binary()}
  def verify_app_transaction(_verifier, _jws), do: :erlang.nif_error(:nif_not_loaded)

  @doc "`aprv_verify_raw`."
  @spec verify_raw(reference(), binary()) :: {:ok, binary()} | {:error, integer(), binary()}
  def verify_raw(_verifier, _jws), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  `aprv_verify_receipt_der`, or the `_with_device_guid` variant when `guid`
  is not empty.
  """
  @spec verify_receipt_der(reference(), binary(), binary()) ::
          {:ok, binary()} | {:error, integer(), binary()}
  def verify_receipt_der(_verifier, _der, _guid), do: :erlang.nif_error(:nif_not_loaded)

  @doc "`aprv_verify_receipt_base64`, or the `_with_device_guid` variant."
  @spec verify_receipt_base64(reference(), binary(), binary()) ::
          {:ok, binary()} | {:error, integer(), binary()}
  def verify_receipt_base64(_verifier, _receipt_base64, _guid),
    do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  `aprv_verify_receipt_endpoint_json`. The Apple verdict is a field of the
  body, so `{:error, status}` here means the call itself was malformed.
  """
  @spec verify_receipt_endpoint_json(reference(), binary()) ::
          {:ok, binary()} | {:error, integer()}
  def verify_receipt_endpoint_json(_endpoint, _request_json),
    do: :erlang.nif_error(:nif_not_loaded)
end
