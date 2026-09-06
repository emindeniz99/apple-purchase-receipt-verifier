defmodule AppleReceiptExample.Json do
  @moduledoc """
  A small JSON reader, so the example has no dependencies.

  The C ABI hands back one UTF-8 JSON document per call, and Elixir 1.14 on
  OTP 25 has nothing in its standard library that reads one: `JSON` arrived
  in Elixir 1.18 and `:json` in OTP 27. A real application picks Jason or
  the newer runtime; an example that fetched a package from Hex to show an
  FFI call would be teaching the wrong thing, so it reads the document here.

  It covers what this ABI emits and nothing more: objects with binary keys,
  arrays, strings, integers, floats, booleans and null. Duplicate keys take
  the last value.
  """

  @doc "The decoded document, or `{:error, message}`."
  @spec decode(binary()) :: {:ok, term()} | {:error, String.t()}
  def decode(document) when is_binary(document) do
    with {:ok, value, rest} <- value(skip_space(document)) do
      case skip_space(rest) do
        "" -> {:ok, value}
        trailing -> {:error, "trailing data at " <> preview(trailing)}
      end
    end
  end

  @doc "As `decode/1`, raising on a malformed document."
  @spec decode!(binary()) :: term()
  def decode!(document) do
    case decode(document) do
      {:ok, value} -> value
      {:error, message} -> raise ArgumentError, "invalid JSON: " <> message
    end
  end

  defp skip_space(<<c, rest::binary>>) when c in [?\s, ?\t, ?\n, ?\r], do: skip_space(rest)
  defp skip_space(rest), do: rest

  defp value(<<?{, rest::binary>>), do: object(skip_space(rest), %{})
  defp value(<<?[, rest::binary>>), do: array(skip_space(rest), [])
  defp value(<<?", rest::binary>>), do: string(rest, [])
  defp value(<<"true", rest::binary>>), do: {:ok, true, rest}
  defp value(<<"false", rest::binary>>), do: {:ok, false, rest}
  defp value(<<"null", rest::binary>>), do: {:ok, nil, rest}
  defp value(<<c, _::binary>> = input) when c == ?- or (c >= ?0 and c <= ?9), do: number(input)
  defp value(input), do: {:error, "expected a value at " <> preview(input)}

  defp object(<<?}, rest::binary>>, acc), do: {:ok, acc, rest}

  defp object(<<?", rest::binary>>, acc) do
    with {:ok, key, rest} <- string(rest, []),
         <<?:, rest::binary>> <- skip_space(rest),
         {:ok, value, rest} <- value(skip_space(rest)) do
      case skip_space(rest) do
        <<?,, rest::binary>> -> object(skip_space(rest), Map.put(acc, key, value))
        <<?}, rest::binary>> -> {:ok, Map.put(acc, key, value), rest}
        other -> {:error, "expected , or } at " <> preview(other)}
      end
    else
      {:error, message} -> {:error, message}
      other when is_binary(other) -> {:error, "expected : at " <> preview(other)}
    end
  end

  defp object(input, _acc), do: {:error, "expected a key at " <> preview(input)}

  defp array(<<?], rest::binary>>, acc), do: {:ok, Enum.reverse(acc), rest}

  defp array(input, acc) do
    with {:ok, value, rest} <- value(input) do
      case skip_space(rest) do
        <<?,, rest::binary>> -> array(skip_space(rest), [value | acc])
        <<?], rest::binary>> -> {:ok, Enum.reverse([value | acc]), rest}
        other -> {:error, "expected , or ] at " <> preview(other)}
      end
    end
  end

  defp string(<<?", rest::binary>>, acc),
    do: {:ok, IO.iodata_to_binary(Enum.reverse(acc)), rest}

  defp string(<<?\\, ?u, a, b, c, d, rest::binary>>, acc) do
    case Integer.parse(<<a, b, c, d>>, 16) do
      {code, ""} -> escaped_codepoint(code, rest, acc)
      _ -> {:error, "malformed \\u escape"}
    end
  end

  defp string(<<?\\, c, rest::binary>>, acc) do
    case c do
      ?" -> string(rest, [?" | acc])
      ?\\ -> string(rest, [?\\ | acc])
      ?/ -> string(rest, [?/ | acc])
      ?b -> string(rest, [?\b | acc])
      ?f -> string(rest, [?\f | acc])
      ?n -> string(rest, [?\n | acc])
      ?r -> string(rest, [?\r | acc])
      ?t -> string(rest, [?\t | acc])
      _ -> {:error, "unknown escape \\" <> <<c>>}
    end
  end

  defp string(<<c::utf8, rest::binary>>, acc), do: string(rest, [<<c::utf8>> | acc])
  defp string(<<>>, _acc), do: {:error, "unterminated string"}
  defp string(input, _acc), do: {:error, "invalid UTF-8 at " <> preview(input)}

  # A codepoint above the basic plane is written as a surrogate pair, and the
  # halves are meaningless on their own.
  defp escaped_codepoint(high, <<?\\, ?u, a, b, c, d, rest::binary>>, acc)
       when high in 0xD800..0xDBFF do
    case Integer.parse(<<a, b, c, d>>, 16) do
      {low, ""} when low in 0xDC00..0xDFFF ->
        string(rest, [<<0x10000 + (high - 0xD800) * 0x400 + (low - 0xDC00)::utf8>> | acc])

      _ ->
        {:error, "malformed surrogate pair"}
    end
  end

  defp escaped_codepoint(code, _rest, _acc) when code in 0xD800..0xDFFF,
    do: {:error, "unpaired surrogate"}

  defp escaped_codepoint(code, rest, acc), do: string(rest, [<<code::utf8>> | acc])

  defp number(input) do
    length = number_length(input, 0)
    text = binary_part(input, 0, length)
    rest = binary_part(input, length, byte_size(input) - length)

    parsed =
      if String.contains?(text, [".", "e", "E"]),
        do: Float.parse(text),
        else: Integer.parse(text)

    case parsed do
      {number, ""} -> {:ok, number, rest}
      _ -> {:error, "malformed number " <> text}
    end
  end

  defp number_length(<<c, rest::binary>>, taken)
       when c in [?+, ?-, ?., ?e, ?E] or (c >= ?0 and c <= ?9),
       do: number_length(rest, taken + 1)

  defp number_length(_input, taken), do: taken

  defp preview(input), do: inspect(binary_part(input, 0, min(byte_size(input), 24)))
end
