# Java implementation notes

Reasoning behind a few Java guards, kept out of the source so the code
carries one line of why. The rules themselves are in `0.7-api.md`; the
BouncyCastle behaviours to re-check on an upgrade are in `java/README.md`.

## Measuring input in UTF-8 bytes (`Utf8Length`)

Apple counts its limits in bytes on the wire. A Java `String` holds UTF-16
code units, so `length()` under-counts any character above U+007F, and
`getBytes(UTF_8)` would copy up to three bytes per character of an input
that is being refused for its size.

Two shortcuts decide almost every call: every UTF-16 unit costs at least one
byte, so more units than the limit is over it; every unit costs at most
three bytes (a surrogate pair is two units and four bytes), so three times
the units within the limit is within it. Only a string between the two is
walked, and the walk stops once the count passes the limit.

A lone surrogate counts as three bytes: what it takes in CESU-8 and WTF-8,
and never less than any encoder emits for it (`getBytes(UTF_8)` writes one
`?`). It cannot arrive from the wire, where a decoder turns invalid bytes
into U+FFFD, itself three bytes.

## The endpoint body is read from one char array

Given a `String` longer than 32,768 characters, Jackson wraps it in a
`StringReader` and reads it in chunks, and a string value longer than a
chunk goes through a slow character-at-a-time path. `receipt-data` is such a
value for any receipt with more than a handful of purchases, and reading it
that way took longer than decoding it. `Endpoint.receiptData` hands Jackson
`toCharArray()` instead.

Apple has no status for a body that is not JSON; 21002 is the closest, and
it is what a JSON object without usable `receipt-data` gets anyway.

## JSON reader constraints are stated, not inherited

Jackson 2.15 and later default the nesting depth to 1000, but a host BOM that
pins an older Jackson 2 links cleanly and silently loses that guard. So
`BoundedJson` states every bound it relies on, the two Jackson defaults
included, and the 2.16 API it needs makes an older Jackson fail at
`Verifier.create` instead of running with guards it believes it set.

## Why the receipt caps what it does before decoding

- The base64 receipt is capped before it is decoded: decoding allocates
  three quarters of the input again and the CMS parse allocates in
  proportion to the DER, none of it behind a signature, so an input large
  enough to exhaust the heap would otherwise leave as an `OutOfMemoryError`
  instead of a result.
- The embedded-certificate count is checked before any entry is decoded. A
  cross-signed mesh (layers of certificates that each name several valid
  issuers) costs a backtracking path builder 2^layers; the chain-length
  bound already cuts that off, and the count bound does not rely on it.
