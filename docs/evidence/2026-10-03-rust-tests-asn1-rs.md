# The Rust tests' BER reader on asn1-rs (2026-10-03)

**Question.** The Rust core's negative tests open a valid receipt, break
one thing and re-encode it. They opened it with the core's pre-OpenSSL
reader, kept in `rust/tests/common/der.rs` for the tests alone. Can
`asn1-rs` replace that reader without changing what any test reads or
asserts, and how much hand-written BER/DER code is left? This carries out
the owner's decision Q18 of 2026-10-02 (docs/rust-core/DECISIONS.md R43).

**Versions.** Before `453fc7b`, after `befcfae` (commits `b57a39e`, the
reader, and `befcfae`, the writer). rustc 1.98.1 (`rust/rust-toolchain.toml`)
and 1.85.0 for the floor check, `asn1-rs` 0.7.2, cargo-deny 0.20.2. Scripts
and commands are in `2026-10-03-rust-tests-asn1-rs/`.

## The dependency

`asn1-rs` 0.7.2, MIT OR Apache-2.0, `rust-version` 1.68, the parser under
`x509-parser`. It reads BER: indefinite lengths, end-of-contents markers,
constructed strings. 0.8 is in beta (0.8.0-beta.2), so 0.7.2 is the
current release. It is a `[dev-dependencies]` entry of
`apple-purchase-receipt-verifier` only:

- `cargo tree -e normal -p apple-purchase-receipt-verifier` lists no
  `asn1-rs`, and `cargo tree -e normal,build --workspace --target all`
  neither; `cargo tree -e all -i asn1-rs` reaches it only through the
  core's dev-dependencies.
- It adds 8 lockfile packages: `asn1-rs`, `asn1-rs-derive`,
  `asn1-rs-impl`, `displaydoc`, `minimal-lexical`, `nom` 7.1.3,
  `rusticata-macros`, `synstructure`. Their licences are MIT, or MIT OR
  Apache-2.0, all on `deny.toml`'s list; `cargo deny check` passes
  (advisories, bans, licenses, sources).
- `cargo +1.85.0 check --locked --tests -p apple-purchase-receipt-verifier`
  builds, so the CI leg on the floor keeps building the tests.

The `der` crate was not tried: it reads DER only, and Apple's and Xcode's
receipts are BER. 124 of the `*.der`, `*.b64` and Xcode receipt files
under `fixtures/` start with an indefinite-length `SEQUENCE` (`30 80`),
the two Xcode receipts under `fixtures/apple-official/xcode/` among them.

## What the tests needed from the reader

`count.sh` counts 15 calls into the reader outside `tests/common/`
(`parse_exact`, `parse_cms`, `certificate_identity`) in
`envelope_bounds.rs`, `receipt_negative.rs`, `unauthenticated_key_cost.rs`
and `common/mod.rs`, plus `CmsBuilder::from_shared()` everywhere, which
reads the shared receipt through `parse_cms`. Every one needs the same
four things: parse one value and refuse trailing bytes; walk to a child
by index; take a node's exact TLV (`full`) or its value octets
(`contents`); and join a constructed `OCTET STRING`'s chunks (the CMS
`eContent`). None needs the reader to re-encode: the tests write their
output with the DER writer in `common/mod.rs`, and a malformed form
(a wrong length, an indefinite length, a missing end-of-contents, a
retagged value) is written as bytes in the test that states it.

`tests/common/ber.rs` keeps the same `Tlv` shape over `asn1-rs`'s `Any`:
`Any::from_ber` reads each header and length and finds the end of an
indefinite value; the file keeps the slices and reads each constructed
value's content into children. Two things stay hand-written there:

- Joining a constructed `OCTET STRING`. `asn1-rs` 0.7.2's `OctetString`
  returns the raw content of the constructed form, chunk headers
  included; it does not join.
- Converting the header back to one identifier octet, which the tests
  compare against `tag::` constants. An identifier longer than one octet
  is refused; no fixture has one.

## Same trees, same bytes

`reader_probe.rs` hashes, for every input, each node's identifier,
constructed bit, `full`, `contents` and child count in preorder, every
joined `OCTET STRING` value, and the `parse_cms` output; and it hashes
the writer's output over every length from 0 to 70,000 octets in steps of
7 plus the length-form boundaries, every one-octet identifier, eleven
integers, and six OIDs one by one. Run against both trees:

| | before | after |
|---|---|---|
| inputs read | 264 | 264 |
| parsed | 255 | 260 |
| refused | 9 | 4 |
| writer hash | equal | equal |
| `CmsBuilder::from_shared().build()` | equal | equal |

All 255 inputs both trees parse give the same tree and CMS hash.

The four refused by both are inputs that are not one value: an empty
file, a receipt cut at 200 bytes, a receipt with a trailing byte, and a
base64 file with trailing zeros. The five the old reader refused and
`asn1-rs` reads are the `*-33.der` depth fixtures (certificate
parameters, CRL, digest algorithms, unsigned context tags, envelope). The
old reader kept the library's former depth cap of 32; no test reads those
files with the test reader, and the core's own cap is tested in
`envelope_bounds.rs` against OpenSSL, unchanged.

Of the OIDs, five encode the same. `asn1-rs` refuses `2.999.1`
(`FirstComponentsTooLarge`: the first two arcs above one octet), which
the hand-written encoder wrote as `06 03 88 37 01`. No test uses such an
OID; `der_oid` would panic on one rather than write it wrongly.

## Lines of hand-written BER/DER code under `rust/tests`

From `count.sh` (all lines / code lines, comments and blanks excluded):

| file | before `453fc7b` | after `befcfae` |
|---|---|---|
| reader: `common/der.rs`, then `common/ber.rs` | 391 / 283 | 108 / 72 |
| DER writer section of `common/mod.rs` | 45 / 37 | 64 / 46 |
| total | 436 / 320 | 172 / 118 |

The writer section grew because the 16 identifier constants (`tag::`)
moved into it from `der.rs`. Its encoding code went from 27 lines in
`der()` and `der_int()` (length octets, `INTEGER` trimming), plus
`encode_oid` in `der.rs`, to `der()` building an `asn1-rs` `Header`,
`der_int()` calling `u64`'s `ToDer`, and `der_oid()` parsing an `Oid`. `der.rs` also held `decode_oid`, which nothing
called. `common/cms.rs`, the CMS walk over the reader, kept its shape
(81 to 84 lines: imports).

## Tests

`cargo test -p apple-purchase-receipt-verifier -- --list` prints the same
668 tests before and after (byte-identical list). The full run passes
667 and ignores 1 before and after, test by test the same outcome. No
test's input changed: the probe shows the builder and writer produce the
same bytes, and no test was dropped or weakened.

## Where this stops holding

- `asn1-rs` 0.7.2. 0.8 changes the API (it is in beta); a bump re-runs
  the probe.
- The probe covers the fixtures as committed at `453fc7b`. A new fixture
  with a multi-octet identifier or a nesting the tests read with
  `parse_exact` would need the reader extended, not the test weakened.
