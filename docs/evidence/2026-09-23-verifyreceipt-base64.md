# How Apple's verifyReceipt reads receipt-data base64

Measured 2026-09-23. This note is the evidence behind the `receipt-data`
rule in THREAT-MODEL.md §3.8 and the "Receipt base64" paragraph of
`fixtures/cases.json`.

## Result

Apple's verifyReceipt accepts `receipt-data` only when it is standard-alphabet
base64 (`[A-Za-z0-9+/]`) carrying exactly the canonical `=` padding for its
data length, with nothing else in the string. The one freedom it allows is the
unused low bits of the last data character: a string with those bits set is
decoded like the canonical one.

## Method

- Four genuine receipts: two production, two sandbox.
- Each receipt was sent to both endpoints, `buy.itunes.apple.com` and
  `sandbox.itunes.apple.com`, once in its canonical spelling and once in each
  spelling below. Every spelling differs from the canonical string in one way
  only, so the spelling is the only thing that can move the answer.
- The first seventeen spellings were run twice, with identical results. The
  rest were added in later passes the same day and run once.
- Reading the status: 0, 21007 (a sandbox receipt sent to production) and
  21008 (a production receipt sent to sandbox) all mean Apple decoded the
  base64 and reached the receipt. 21002 means Apple refused `receipt-data` as
  malformed.
- Every spelling got the same verdict on every receipt it applies to, on both
  endpoints, with two expected exceptions. One receipt's length needs no
  padding, so for it "padding omitted" is the canonical string itself, and
  "base64 characters after the padding" is valid base64 of the receipt plus
  three bytes (see "Bytes after the receipt" below). The under-padding
  spelling exists only for the two receipts that need two `=`.

## Spelling by spelling

| Spelling | Apple | Verdict |
|---|---|---|
| Canonical | 0 / 21007 / 21008 | decoded |
| Unused low bits of the last data character set (`QR==` for `QQ==`) | 0 / 21007 / 21008 | decoded |
| Padding omitted | 21002 | refused |
| base64url alphabet, padded | 21002 | refused |
| base64url alphabet, unpadded | 21002 | refused |
| CRLF every 64 characters | 21002 | refused |
| CRLF every 76 characters | 21002 | refused |
| LF every 64 characters | 21002 | refused |
| LF every 76 characters | 21002 | refused |
| One trailing LF | 21002 | refused |
| Trailing CRLF | 21002 | refused |
| One leading space | 21002 | refused |
| A space inside | 21002 | refused |
| A tab inside | 21002 | refused |
| Leading and trailing whitespace | 21002 | refused |
| A junk character inside | 21002 | refused |
| Junk after the padding | 21002 | refused |
| Base64 characters after the padding | 21002 | refused |
| One `=` more than canonical | 21002 | refused |
| Two `=` more than canonical | 21002 | refused |
| One `=` fewer than canonical | 21002 | refused |
| Both alphabets in one string | 21002 | refused |
| Impossible length (data of 4n+1 characters), padded | 21002 | refused |
| Impossible length, unpadded | 21002 | refused |
| Empty string | 21002 | refused |
| Canonical followed by 100,000 newlines | 21002 | refused |

## Around the string

Sent once each, on two of the receipts, both endpoints:

| Request | Apple | Verdict |
|---|---|---|
| `data:application/pkcs7-mime;base64,` prefix | 21002 | refused |
| Byte-order mark (U+FEFF) before the string | 21002 | refused |
| No-break space (U+00A0) inside | 21002 | refused |
| `+` and `/` percent-encoded | 21002 | refused |
| JSON `\/` escapes, as PHP's `json_encode` writes them | 0 / 21008 | decoded |
| A JSON `\u` escape for one character | 0 / 21008 | decoded |
| An extra unknown field beside `receipt-data` | 0 / 21008 | decoded |
| `receipt-data` null, a number, an array, or missing | 21002 | refused |
| `receipt-data` twice, a bad value first and the genuine one last | 0 / 21008 | decoded |

JSON escapes are undone by the JSON parser before the base64 rule sees the
string, so they are not spellings of the base64 at all. The duplicate key shows
Apple keeping the last value; what each port does with a duplicate key is not
pinned by this rule.

## Bytes after the receipt

Also measured, on all four receipts and both endpoints: appending bytes to the
receipt's DER and base64-encoding the result canonically. One zero byte, three
zero bytes, one `A`, 100 arbitrary bytes, an ASN.1 NULL and a second copy of
the whole receipt were all decoded. Apple reads the first complete value and
ignores what follows.

The ports refuse this on purpose (THREAT-MODEL.md §3.7): no genuine client can
produce it, since `appStoreReceiptURL` yields the exact file, and refusing it
keeps one receipt to one byte string. It is the one place the library is
deliberately stricter than Apple.

## The Python equivalence

Python's `base64.b64decode(s, validate=True)` gave the same decoded-or-refused
answer as Apple on every spelling in the table.

It is not the whole rule on its own, though. Measured with synthetic strings on
this repository's supported Pythons, `validate=True` decodes `""` on every
version, and before 3.13 it also accepts surplus `=` after a full group
(`AAAA=` and `AAAA==` on 3.10 to 3.12; `==` and `AAA==` as well on 3.10). The
Python port therefore checks the shape and the length itself before calling it,
as every other port does in front of its own decoder.

## What each port's standard decoder does alone

The ports were measured against 107 synthetic spellings covering every row of
the table, at three padding lengths, plus a few edge shapes (`====`, `QQ=A`,
data after padding, non-ASCII). Each standard decoder was run alone and then
behind the shape check the port now uses. Behind the check, all nine agree with
the rule on all 107. Alone, each one departs from it somewhere:

| Port | Decoder | Alone, it also accepts | Alone, it refuses |
|---|---|---|---|
| Java | `Base64.getDecoder()` | omitted padding, `""` | nothing the rule accepts |
| Node | `Buffer.from(s, 'base64')` | almost anything: it skips what it does not know | nothing the rule accepts |
| Python | `b64decode(validate=True)` | `""`; surplus `=` before 3.13 | nothing the rule accepts |
| Go | `base64.StdEncoding` | CR and LF anywhere, `""` | nothing (its `Strict()` variant refuses the trailing bits) |
| Ruby | `unpack1("m0")` (`strict_decode64`) | `""` | the trailing bits Apple accepts, so the port uses `"m"` behind the check |
| PHP | `base64_decode($s, true)` | space, tab, CR and LF anywhere, omitted padding, `""` | nothing the rule accepts |
| .NET | `Convert.FromBase64String` | space, tab, CR and LF anywhere, `""` | nothing (`System.Buffers.Text.Base64` refuses the trailing bits) |
| Rust | `base64` crate, default `STANDARD` engine | `""` | the trailing bits, so the port configures `decode_allow_trailing_bits` |
| Swift (Linux) | `Data(base64Encoded:)` | surplus `=`, `""` | nothing the rule accepts |

The shape check each port adds is the same one: a non-empty length that is a
multiple of four, and only the standard alphabet before at most two trailing
`=`. Together those leave exactly the canonical padding.

## Limits

- No receipt content, size or identifier is recorded here, and none is
  committed anywhere in the repository. The conformance cases pin the rule on
  the public sandbox receipt already under `fixtures/`.
- Four receipts, two per environment. The rule held identically on all of
  them, but that is the extent of the sample.
- Of Unicode whitespace, only U+00A0 and U+FEFF were sent to Apple (both
  refused). The rule refuses the rest anyway, since it is outside the alphabet.
- Swift was measured on Linux only. Darwin's Foundation is a different
  implementation; the shape check in front of it is what keeps the two
  platforms on the same answer.
