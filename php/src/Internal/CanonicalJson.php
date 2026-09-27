<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

/**
 * Writes the canonical JSON of {@see \EminDeniz99\ApplePurchaseReceiptVerifier\ReceiptPayload::toJson()},
 * the form every port must produce byte for byte (docs/design/0.7-api.md,
 * "Our JSON"): no whitespace, keys in the order the caller writes them, and
 * strings escaped exactly as ECMAScript's `JSON.stringify` escapes them —
 * `"` and `\` as `\"` and `\\`, the short escapes `\b \f \n \r \t`, every
 * other character below U+0020 as a lowercase `\u00xx`, and nothing else
 * (`/` and non-ASCII, U+2028 and U+2029 included, are written raw).
 *
 * Written by hand rather than through `json_encode()` so the escaping is
 * pinned here rather than to a runtime flag: `json_encode()` always escapes
 * `/` and non-ASCII characters unless told otherwise, and has no flag for
 * "escape only what JSON requires."
 *
 * @internal
 */
final class CanonicalJson
{
    private const HEX = '0123456789abcdef';

    private const SHORT_ESCAPES = [
        '"' => '\\"',
        '\\' => '\\\\',
        "\x08" => '\\b',
        "\x0c" => '\\f',
        "\n" => '\\n',
        "\r" => '\\r',
        "\t" => '\\t',
    ];

    /** A JSON string literal for `$value`, its bytes taken as UTF-8. */
    public static function quote(string $value): string
    {
        $out = '"';
        $length = strlen($value);
        $i = 0;
        while ($i < $length) {
            $byte = $value[$i];
            $escape = self::SHORT_ESCAPES[$byte] ?? null;
            if ($escape !== null) {
                $out .= $escape;
                ++$i;
                continue;
            }
            $ord = ord($byte);
            if ($ord < 0x20) {
                $out .= '\\u00' . self::HEX[($ord >> 4) & 0xF] . self::HEX[$ord & 0xF];
                ++$i;
                continue;
            }
            // Everything else, including a multi-byte UTF-8 sequence, is
            // copied through raw: only control characters and the two
            // quoting characters above are ever escaped.
            $out .= $byte;
            ++$i;
        }

        return $out . '"';
    }

    private array $parts = [];

    private function key(string $key): void
    {
        if ($this->parts !== []) {
            $this->parts[] = ',';
        }
        $this->parts[] = self::quote($key) . ':';
    }

    public function string(string $key, ?string $value): self
    {
        $this->key($key);
        $this->parts[] = $value === null ? 'null' : self::quote($value);

        return $this;
    }

    public function number(string $key, ?int $value): self
    {
        $this->key($key);
        $this->parts[] = $value === null ? 'null' : (string) $value;

        return $this;
    }

    /** A 64-bit id, written as a JSON string so JavaScript readers do not round it. */
    public function id(string $key, ?int $value): self
    {
        return $this->string($key, $value === null ? null : (string) $value);
    }

    public function bool(string $key, ?bool $value): self
    {
        $this->key($key);
        $this->parts[] = $value === null ? 'null' : ($value ? 'true' : 'false');

        return $this;
    }

    public function bytes(string $key, ?string $value): self
    {
        return $this->string($key, $value === null ? null : base64_encode($value));
    }

    /** `$rawJson` is inserted verbatim as the value; the caller already built it. */
    public function raw(string $key, string $rawJson): self
    {
        $this->key($key);
        $this->parts[] = $rawJson;

        return $this;
    }

    /**
     * `{"9": ["<base64>", ...], "13": [...]}`: keys in ascending numeric
     * order, each key's values in the order the list holds them.
     *
     * @param array<int, list<string>> $attributes
     */
    public function attributes(string $key, array $attributes): self
    {
        $this->key($key);
        ksort($attributes, SORT_NUMERIC);
        $parts = ['{'];
        $first = true;
        foreach ($attributes as $type => $values) {
            if (!$first) {
                $parts[] = ',';
            }
            $first = false;
            $parts[] = self::quote((string) $type) . ':[';
            foreach ($values as $j => $value) {
                if ($j > 0) {
                    $parts[] = ',';
                }
                $parts[] = self::quote(base64_encode($value));
            }
            $parts[] = ']';
        }
        $parts[] = '}';
        $this->parts[] = implode('', $parts);

        return $this;
    }

    public function build(): string
    {
        return '{' . implode('', $this->parts) . '}';
    }
}
