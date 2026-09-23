defmodule ConformanceTest do
  @moduledoc """
  Drives `fixtures/cases.json` — the normative cross-language conformance
  vectors — through the C ABI from Elixir, over the NIF shim.

      node tools/gen-cases-manifest.mjs rust/ffi/target/manifest
      mix test

  It reads the same flat manifest the C++ harness reads, for the same reason
  the C++ harness needs one: resolving fixture ids, checking their digests,
  decoding the codecs and computing the environment bitmask is work the
  generator already does once for every consumer that is not the Rust
  library itself. Reusing it keeps this file about the boundary.

  Both this and `rust/ffi/examples/cpp/conformance.cpp` run every case and
  skip none, except the `decodeBase64` groups: they call a port's base64
  decoders directly, the ABI exposes none, and the manifest marks them
  `abiUnreachable`, so they are counted and never passed. After the run,
  every case id in the manifest must have run or been counted. The twelve
  that pin a clock go through
  `aprv_verifier_new_jws_with_roots_and_clock` and
  `aprv_endpoint_new_with_roots_and_clock`, which take the instant itself
  rather than a callback; the generator has already parsed it to epoch
  milliseconds. A case the manifest marks unsupported fails the run rather
  than being counted away.
  """

  use ExUnit.Case, async: false

  alias AppleReceiptExample, as: Aprv

  @manifest_dir System.get_env("APRV_MANIFEST_DIR") ||
                  Path.expand("../../../target/manifest", __DIR__)

  @reason_codes %{
    "INVALID_JWS_FORMAT" => :invalid_jws_format,
    "INVALID_CERTIFICATE" => :invalid_certificate,
    "INVALID_CERTIFICATE_PURPOSE" => :invalid_certificate_purpose,
    "INVALID_CHAIN" => :invalid_chain,
    "INVALID_SIGNATURE" => :invalid_signature,
    "WRONG_BUNDLE_ID" => :wrong_bundle_id,
    "WRONG_ENVIRONMENT" => :wrong_environment,
    "WRONG_APP_APPLE_ID" => :wrong_app_apple_id,
    "INVALID_RECEIPT_FORMAT" => :invalid_receipt_format,
    "DEVICE_HASH_MISMATCH" => :device_hash_mismatch,
    "STALE_PAYLOAD" => :stale_payload
  }

  test "the version crosses the boundary" do
    assert Aprv.version() =~ ~r/^\d+\.\d+\.\d+/
  end

  test "the shared conformance vectors" do
    cases = read_manifest()
    assert cases != [], "the manifest held no cases"

    IO.puts("apple-purchase-receipt-verifier #{Aprv.version()} — C ABI conformance over NIFs")

    pinned_clocks = Enum.count(cases, &(get(&1, "clockUnixMillis") != nil))

    {failures, passed, skipped, checked_fields, ran, unreachable} =
      Enum.reduce(cases, {[], 0, 0, 0, MapSet.new(), MapSet.new()}, &tally/2)

    IO.puts(
      "#{passed} passed, #{length(failures)} failed, #{skipped} skipped " <>
        "(#{pinned_clocks} pin a clock, and every one of them ran)"
    )

    IO.puts("#{checked_fields} expected fields checked here, nested paths left to conformance.py")

    IO.puts(
      "#{MapSet.size(unreachable)} decodeBase64 groups not reachable: the ABI exposes no base64 decoder"
    )

    assert failures == [],
           Enum.map_join(Enum.reverse(failures), "\n", fn {id, why} -> "FAIL  #{id}: #{why}" end)

    # Coverage self-check: every case id the manifest lists, one per case in
    # cases.json, ran or was counted as unreachable, compared id by id.
    missing =
      cases
      |> Enum.map(&get(&1, "id"))
      |> Enum.reject(&(MapSet.member?(ran, &1) or MapSet.member?(unreachable, &1)))

    assert missing == [],
           "#{length(missing)} of #{length(cases)} cases did not run: #{Enum.join(missing, ", ")}"
  end

  # One case into the running totals. A decodeBase64 group is counted as
  # unreachable and never passed: it calls a port's base64 decoders directly,
  # and the ABI exposes none.
  defp tally(kase, {failures, passed, skipped, fields, ran, unreachable}) do
    id = get(kase, "id")
    fields = fields + length(all(kase, "field"))

    cond do
      get(kase, "abiUnreachable") != nil ->
        {failures, passed, skipped, fields, ran, MapSet.put(unreachable, id)}

      get(kase, "unsupported") != nil ->
        # Nothing is skipped any more. A case the manifest cannot express
        # for this ABI is a finding, not a smaller run.
        why = "the manifest marks it unsupported (#{inspect(get(kase, "unsupported"))})"
        {[{id, why} | failures], passed, skipped + 1, fields, ran, unreachable}

      true ->
        ran = MapSet.put(ran, id)

        case run_and_check(kase) do
          :ok -> {failures, passed + 1, skipped, fields, ran, unreachable}
          {:error, why} -> {[{id, why} | failures], passed, skipped, fields, ran, unreachable}
        end
    end
  end

  # --- the manifest -------------------------------------------------------

  # Each line is TAB-separated `key=value` pairs, the key being what precedes
  # the first `=`, and a repeated key is a list. A case is kept as that list
  # of pairs rather than a map so repetition survives.
  defp read_manifest do
    path = Path.join(@manifest_dir, "cases.tsv")

    if not File.exists?(path) do
      flunk("cannot read #{path} — run: node tools/gen-cases-manifest.mjs #{@manifest_dir}")
    end

    path
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.map(fn line ->
      Enum.map(String.split(line, "\t"), fn part ->
        [key, value] = String.split(part, "=", parts: 2)
        {key, value}
      end)
    end)
  end

  defp get(kase, key, fallback \\ nil) do
    case List.keyfind(kase, key, 0) do
      {^key, value} -> value
      nil -> fallback
    end
  end

  defp all(kase, key), do: for({^key, value} <- kase, do: value)

  defp integer(kase, key), do: String.to_integer(get(kase, key, "0"))

  # --- one case -----------------------------------------------------------

  defp run_and_check(kase) do
    with {:ok, outcome} <- run_case(kase) do
      check(kase, outcome)
    end
  end

  defp run_case(kase) do
    roots = Enum.map(all(kase, "root"), &File.read!/1)
    input = File.read!(get(kase, "input"))
    guid = decode_hex(get(kase, "deviceGuidHex", ""))
    # nil is the ABI's NULL clock pointer: the system clock, which is what a
    # case that pins none must be answered at.
    clock = clock_millis(kase)

    case get(kase, "op") do
      operation when operation in ~w(verifyTransaction verifyAppTransaction verifyRaw) ->
        with {:ok, verifier} <-
               open(
                 Aprv.jws_verifier(
                   get(kase, "bundleId"),
                   # already computed by the generator, so passed as the mask
                   integer(kase, "envs"),
                   app_apple_id: integer(kase, "appAppleId"),
                   max_signed_age_secs: integer(kase, "maxSignedAgeSecs"),
                   roots: roots,
                   clock_unix_millis: clock
                 ),
                 "aprv_verifier_new_jws refused the configuration"
               ) do
          {:ok,
           case operation do
             "verifyTransaction" -> Aprv.verify_transaction(verifier, input)
             "verifyAppTransaction" -> Aprv.verify_app_transaction(verifier, input)
             "verifyRaw" -> Aprv.verify_raw(verifier, input)
           end}
        end

      operation
      when operation in ~w(verifyReceipt verifyReceiptBase64) and clock == nil ->
        with {:ok, verifier} <-
               open(
                 Aprv.receipt_verifier(get(kase, "bundleId"), roots: roots),
                 "aprv_verifier_new_receipt refused the configuration"
               ) do
          {:ok,
           case operation do
             "verifyReceipt" ->
               Aprv.verify_receipt(verifier, input, device_guid: guid)

             "verifyReceiptBase64" ->
               Aprv.verify_receipt_base64(verifier, input, device_guid: guid)
           end}
        end

      "verifyReceiptEndpoint" ->
        environment = if integer(kase, "endpointEnv") == 1, do: :production, else: :sandbox

        with {:ok, endpoint} <-
               open(
                 Aprv.endpoint(environment, roots: roots, clock_unix_millis: clock),
                 "aprv_endpoint_new refused the configuration"
               ) do
          case Aprv.verify_receipt_endpoint(endpoint, File.read!(get(kase, "request"))) do
            # The endpoint never reports a verdict through the return value:
            # the Apple status code is a field of the body it answers.
            {:ok, body} ->
              {:ok, {:ok, body}}

            {:error, reason} ->
              {:error, "the endpoint call itself failed with #{inspect(reason)}"}
          end
        end

      operation when operation in ~w(verifyReceipt verifyReceiptBase64) ->
        # The receipt verifier takes no clock in any port: an injected one
        # must never be able to accept an expired chain. A case pinning one
        # here would be a change to the vectors, so it fails.
        {:error, "the receipt verifier has no clock seam, but the case pins one"}

      operation ->
        {:error, "no adapter for operation #{operation}"}
    end
  end

  # The generator parsed the case's ISO-8601 `clock` to epoch milliseconds, so
  # nothing here reads a timestamp.
  defp clock_millis(kase) do
    case get(kase, "clockUnixMillis") do
      nil -> nil
      text -> String.to_integer(text)
    end
  end

  defp open({:ok, handle}, _message), do: {:ok, handle}
  defp open({:error, :invalid_argument}, message), do: {:error, message}

  # --- expectations -------------------------------------------------------

  defp check(kase, outcome) do
    case get(kase, "expect") do
      "error" -> check_error(kase, outcome)
      "ok" -> check_ok(kase, outcome)
    end
  end

  defp check_error(kase, outcome) do
    token = get(kase, "reason")
    wanted = Map.get(@reason_codes, token)

    cond do
      wanted == nil ->
        {:error, "unknown expected reason #{token}"}

      match?({:error, ^wanted, _}, outcome) ->
        # The status is the contract; the token in the body must agree.
        {:error, _, body} = outcome

        if body["reason"] == token,
          do: :ok,
          else: {:error, "the error body does not name #{token}: #{inspect(body)}"}

      true ->
        {:error, "reason: expected #{token}, got #{inspect(outcome)}"}
    end
  end

  defp check_ok(_kase, {:error, reason, body}) do
    {:error, "expected success, got #{inspect(reason)} #{inspect(body)}"}
  end

  defp check_ok(kase, {:ok, payload}) do
    Enum.find_value(all(kase, "field"), :ok, fn field ->
      case check_field(payload, field) do
        :ok -> nil
        {:error, why} -> {:error, why}
      end
    end)
  end

  # `<path>~><tag>:<text>`, the tag being `s` (string), `n` (number) or `z`
  # (absent or null). The generator only emits top-level scalars and
  # `<array>.length`; the nested paths it drops are checked by
  # rust/ffi/tests/conformance.py, which reads cases.json directly.
  defp check_field(payload, field) do
    [path, tagged] = String.split(field, "~>", parts: 2)
    <<tag::utf8, ?:, wanted::binary>> = tagged

    {key, length?} =
      if String.ends_with?(path, ".length"),
        do: {String.replace_suffix(path, ".length", ""), true},
        else: {path, false}

    found = Map.get(payload, key, :missing)

    cond do
      tag == ?z and found in [:missing, nil] -> :ok
      tag == ?z -> {:error, "#{path}: expected absent, got #{inspect(found)}"}
      found == :missing -> {:error, "#{path}: expected #{wanted}, got nothing"}
      length? and not is_list(found) -> {:error, "#{path}: #{key} is not an array"}
      length? -> compare(path, length(found), String.to_integer(wanted))
      tag == ?s -> compare(path, found, wanted)
      tag == ?n -> compare(path, found, number(wanted))
    end
  end

  defp compare(_path, found, wanted) when found == wanted, do: :ok

  defp compare(path, found, wanted),
    do: {:error, "#{path}: expected #{inspect(wanted)}, got #{inspect(found)}"}

  defp number(text) do
    if String.contains?(text, [".", "e", "E"]),
      do: String.to_float(text),
      else: String.to_integer(text)
  end

  defp decode_hex(""), do: ""
  defp decode_hex(text), do: Base.decode16!(text, case: :mixed)
end
