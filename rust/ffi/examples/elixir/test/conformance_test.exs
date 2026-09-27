defmodule ConformanceTest do
  @moduledoc """
  Drives `fixtures/cases.json`, the normative cross-language conformance
  vectors, through the C ABI from Elixir, over the NIF shim.

      node tools/gen-cases-manifest.mjs rust/ffi/target/manifest
      mix test

  It reads the same flat manifest the C++ harness reads, for the same reason
  the C++ harness needs one: resolving fixture ids, checking their digests,
  decoding the codecs and computing the environment bitmask is work the
  generator already does once for every consumer that is not the Rust
  library itself. Reusing it keeps this file about the boundary.

  Both this and `rust/ffi/examples/cpp/conformance.cpp` run every case in
  `fixtures/cases.json` and skip none, except the `decodeBase64` groups:
  they call a port's base64 decoders directly, the ABI exposes none, and the
  manifest marks them `abiUnreachable`, so they are counted and never passed.
  After the run, every case id in the manifest must have run or been counted.
  A case that pins a clock passes the instant to `aprv_verifier_new`; the
  generator has already parsed it to epoch milliseconds. A case the manifest
  marks unsupported fails the run rather than being counted away.
  """

  use ExUnit.Case, async: false

  alias AppleReceiptExample, as: Aprv
  alias AppleReceiptExample.Native

  @manifest_dir System.get_env("APRV_MANIFEST_DIR") ||
                  Path.expand("../../../target/manifest", __DIR__)

  @reason_codes %{
    "MALFORMED" => :malformed,
    "TOO_LARGE" => :too_large,
    "INVALID_SIGNATURE" => :invalid_signature,
    "UNTRUSTED_CHAIN" => :untrusted_chain,
    "INVALID_CERTIFICATE" => :invalid_certificate,
    "INVALID_CERTIFICATE_PURPOSE" => :invalid_certificate_purpose,
    "UNREADABLE_PAYLOAD" => :unreadable_payload,
    "INTERNAL_ERROR" => :internal_error
  }

  test "the version crosses the boundary" do
    assert Aprv.version() =~ ~r/^\d+\.\d+\.\d+/
  end

  # The verifier judges a JWS at its last `signedDate`, and the payload comes
  # back with every repetition intact. A decoder that kept the first would
  # report a signing date the chain was never checked against.
  test "a repeated member keeps its last value, as the verifier reads it" do
    assert Aprv.decode_json!(~s({"signedDate":1,"n":{"k":1,"k":2},"signedDate":2})) ==
             %{"signedDate" => 2, "n" => %{"k" => 2}}
  end

  test "the shared conformance vectors" do
    cases = read_manifest()
    assert cases != [], "the manifest held no cases"

    IO.puts("apple-purchase-receipt-verifier #{Aprv.version()}: C ABI conformance over NIFs")

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
    fields = fields + length(all(kase, "field")) + length(all(kase, "length"))

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
      flunk("cannot read #{path}; run: node tools/gen-cases-manifest.mjs #{@manifest_dir}")
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

  # --- one case -----------------------------------------------------------

  defp run_and_check(kase) do
    with {:ok, outcome} <- timed(kase) do
      check(kase, outcome)
    end
  end

  # A maxMillis budget (the denial-of-service cases): one warm-up run of the
  # same case, then the timed run whose outcome is checked.
  defp timed(kase) do
    case get(kase, "maxMillis") do
      nil ->
        run_case(kase)

      budget ->
        run_case(kase)
        {micros, result} = :timer.tc(fn -> run_case(kase) end)
        millis = div(micros, 1000)

        if millis > String.to_integer(budget),
          do: {:error, "took #{millis} ms, over the #{budget} ms budget"},
          else: result
    end
  end

  # `{:ok, {:ok, raw_json}}`, `{:ok, {:error, status, raw_json}}`, or
  # `{:error, why}` when the case could not be run at all. The raw text is
  # kept for the failure messages.
  defp run_case(kase) do
    roots = Enum.map(all(kase, "root"), &File.read!/1)

    with {:ok, verifier} <- open(Native.verifier_new(roots, clock_millis(kase))) do
      case get(kase, "op") do
        "verifyReceipt" ->
          {:ok, Native.verify_receipt(verifier, File.read!(get(kase, "input")))}

        "verifySignedData" ->
          {:ok, Native.verify_signed_data(verifier, File.read!(get(kase, "input")))}

        "verifyReceiptEndpoint" ->
          environment = String.to_integer(get(kase, "endpointEnv"))

          case Native.verify_receipt_endpoint(
                 verifier,
                 environment,
                 File.read!(get(kase, "request"))
               ) do
            # The endpoint never reports a verdict through the return value:
            # the Apple status code is a field of the body it answers.
            {:ok, body} -> {:ok, {:ok, body}}
            {:error, status} -> {:error, "the endpoint call itself failed with #{status}"}
          end

        operation ->
          {:error, "no adapter for operation #{operation}"}
      end
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

  defp open({:ok, handle}), do: {:ok, handle}

  defp open({:error, :invalid_argument}),
    do: {:error, "aprv_verifier_new refused the configuration"}

  # --- expectations -------------------------------------------------------

  defp check(kase, outcome) do
    case get(kase, "expect") do
      "oneof" -> check_one_of(kase, outcome)
      "error" -> check_error(kase, outcome)
      expect when expect in ["ok", "body"] -> check_ok(kase, outcome)
    end
  end

  # A listed-outcome case: "ok" or the reason must be listed. A panic answers
  # INTERNAL_ERROR, which no list holds.
  defp check_one_of(kase, outcome) do
    allowed =
      kase |> get("oneOf") |> String.split("|") |> Enum.map(&Map.get(@reason_codes, &1, :ok))

    got =
      case outcome do
        {:error, status, _json} -> Aprv.reason(status)
        {:ok, _json} -> :ok
      end

    if got in allowed,
      do: :ok,
      else: {:error, "expected one of #{get(kase, "oneOf")}, got #{inspect(got)}"}
  end

  defp check_error(kase, outcome) do
    token = get(kase, "reason")
    wanted = Map.get(@reason_codes, token)

    case outcome do
      {:error, status, json} ->
        body = Aprv.decode_json!(json)

        cond do
          wanted == nil -> {:error, "unknown expected reason #{token}"}
          Aprv.reason(status) != wanted -> {:error, "reason: expected #{token}, got #{json}"}
          # The status is the contract; the token in the body must agree.
          body["reason"] != token -> {:error, "the error body does not name #{token}: #{json}"}
          true -> :ok
        end

      {:ok, json} ->
        {:error, "reason: expected #{token}, but it verified: #{json}"}
    end
  end

  defp check_ok(_kase, {:error, status, json}) do
    {:error, "expected success, got #{inspect(Aprv.reason(status))} #{json}"}
  end

  defp check_ok(kase, {:ok, json}) do
    payload = Aprv.decode_json!(json)

    to_json =
      case get(kase, "toJson") do
        nil ->
          :ok

        path ->
          # Same value, not same bytes; === keeps 1 and 1.0 apart.
          if Aprv.decode_json!(File.read!(path)) === payload,
            do: :ok,
            else: {:error, "toJson value differs: got #{json}"}
      end

    checks =
      Enum.map(all(kase, "length"), &check_length(payload, &1)) ++
        Enum.map(all(kase, "field"), &check_field(payload, &1))

    Enum.find([to_json | checks], :ok, &(&1 != :ok))
  end

  defp check_length(payload, entry) do
    ["/" <> key, wanted] = String.split(entry, "~>", parts: 2)
    found = Map.get(payload, key)

    if is_list(found),
      do: compare("/" <> key, length(found), String.to_integer(wanted)),
      else: {:error, "/#{key}: not an array"}
  end

  # `<pointer>~><tag>:<text>`, the tag being `s` (string), `n` (number), `b`
  # (true or false) or `z` (absent or null). The generator only emits
  # top-level pointers; the nested ones it drops are checked by
  # rust/ffi/tests/conformance.py, which reads cases.json directly.
  defp check_field(payload, field) do
    ["/" <> key, tagged] = String.split(field, "~>", parts: 2)
    <<tag::utf8, ?:, wanted::binary>> = tagged
    path = "/" <> key
    found = Map.get(payload, key, :missing)

    cond do
      tag == ?z and found in [:missing, nil] -> :ok
      tag == ?z -> {:error, "#{path}: expected absent, got #{inspect(found)}"}
      found == :missing -> {:error, "#{path}: expected #{wanted}, got nothing"}
      tag == ?s -> compare(path, found, wanted)
      tag == ?b -> compare(path, found, wanted == "true")
      tag == ?n -> compare(path, found, number(wanted))
    end
  end

  # Numbers compare by value (1722945600000.0 equals 1722945600000), and
  # integers exactly, since the decoder keeps every integer's digits.
  defp compare(_path, found, wanted) when found == wanted, do: :ok

  defp compare(path, found, wanted),
    do: {:error, "#{path}: expected #{inspect(wanted)}, got #{inspect(found)}"}

  defp number(text) do
    if String.contains?(text, [".", "e", "E"]) do
      {value, ""} = Float.parse(text)
      value
    else
      String.to_integer(text)
    end
  end
end
