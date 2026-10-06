# Java implementation notes

Reasoning behind a few Java guards, kept out of the source so the code
carries one line of why. The rules themselves are in `0.7-api.md`; the
BouncyCastle behaviours to re-check on an upgrade are in `java/README.md`.

## Measuring input in UTF-8 bytes (`Utf8Length`)

Apple counts its limits in bytes on the wire. A Java `String` holds UTF-16
code units, so `length()` under-counts any character above U+007F.
`Utf8Length` checks the units first: every unit is at least one byte, so
more units than the limit is over it, and nothing is copied. Otherwise it
encodes with `getBytes(UTF_8)` and compares, a copy of at most three times
the limit.

Until 2026-10-06 it walked the string instead of encoding it, to save that
copy. Graal's JIT in Oracle GraalVM 21 miscompiled the walk
(docs/evidence/2026-10-06-graalvm21-utf8-length.md), and the owner chose
the simpler form (Q84).

A lone surrogate counts the one `?` that `getBytes` writes, which is what
the `-wasm` artifact sends the core. It cannot arrive from the wire, where
a decoder turns invalid bytes into U+FFFD.

## The endpoint body is read from one char array

Given a `String` longer than 32,768 characters, Jackson wraps it in a
`StringReader` and reads it in chunks, and a string value longer than a
chunk goes through a slow character-at-a-time path. `receipt-data` is such a
value for any receipt with more than a handful of purchases, and reading it
that way took longer than decoding it. `Endpoint.receiptData` hands Jackson
`toCharArray()` instead.

Apple has no status for a body that is not JSON; 21002 is the closest, and
it is what a JSON object without usable `receipt-data` gets anyway.

## JSON reader constraints are Jackson's defaults

The readers use Jackson's default `StreamReadConstraints`: nesting 1,000,
member names 50,000 characters, numbers 1,000 characters. The size caps run before the parse
and sit below Jackson's string and document limits, so they bound a
document's length. Jackson keeps the nesting context on the heap and the
readers skip what they do not read with `skipChildren`, so depth costs no
stack; until 2026-10-05 `BoundedJson` set a depth of 64 and restated the
other two, which bought nothing over these defaults. Two things are
still the library's: `JsonFields.factory` builds the constraints with
`StreamReadConstraints.builder()` rather than inheriting them, so a host's
process-wide `overrideDefaultStreamReadConstraints` cannot change a
verdict; and `Verifier.create` reads the 2.16 name bound, so a host BOM
that pins an older Jackson 2, which would link and read with fewer bounds
(2.15 has no name bound, 2.14 none at all), fails there instead.

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
