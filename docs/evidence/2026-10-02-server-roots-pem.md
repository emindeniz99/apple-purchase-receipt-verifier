# aprv-server's roots file through the `pem` crate (2026-10-02)

**Question.** Can `aprv-server` hand the PEM blocks of its `--roots` file
to a library instead of its own line reader, and still give every file
the same DER, so `GET /v1/info` reports the same fingerprints to the Java
and PHP clients? This feeds the owner's Q10 decision (b) and DECISIONS.md
R39's amendment.

**Versions.** `pem` 4.0.0 (MIT, 2026-07-28), on the `base64` 0.23.1 the
server already linked, Rust 1.98.1, the OpenSSL 3.0.13 CLI for the inputs, base
commit `e0016b1`. Code and commands are in `2026-10-02-server-roots-pem/`.

## Which library

The server does not link OpenSSL (`rust/server/Cargo.lock` names no
OpenSSL crate; Wasmtime, axum and tokio are its large dependencies), so
the core's
`Certificate::all_from_pem` would have meant a native OpenSSL in a binary
that is otherwise static Rust. `pem` decodes PEM framing and base64 only,
adds one crate to `rust/server/Cargo.lock`, and parses no certificate,
which keeps the server outside certificate parsing (ARCHITECTURE.md §7.7).

## What the server keeps

The file is not plain PEM: base64 lines, `#` comments and blank lines sit
between blocks, and `pem::parse_many` skips any text outside a block. So
the server still splits the file into lines and decides where a block
starts and ends; `pem::parse` reads each block whole, matching the END
label to the BEGIN label and decoding the base64. Three checks keep the
old refusals where `pem` is more lenient:

- Blank lines inside a block are dropped before parsing. `pem` reads text
  before a blank line as RFC 1421 headers; the old reader joined the lines.
- Whitespace inside a body line is refused. `pem` strips all whitespace
  from the body; the old reader's strict base64 refused it.
- A delimiter line is five dashes, a label with no dash in it, and five
  dashes. `pem::parse` ignores what follows the END line's first closing
  dashes (`-----END CERTIFICATE-----x-----`); the old reader refused the
  line. A first version checked only the line's last five characters, and
  a review found the two inputs that passed it.

A `CERTIFICATE` label and a non-empty body are checked after parsing, as
before.

## Results

`make-inputs.sh` writes 31 files: the three `certs/` roots as PEM (LF and
CRLF) and as base64 lines, an indented block, a block with a blank line, a
mixed file, Apple's six test PKI files from `fixtures/`, and 19 malformed
files (no END, a private key, mismatched labels, an empty body, bad base64,
whitespace in the body, text after the dashes, a dash-ended tail, a stray delimiter, a nested
BEGIN, RFC 1421 headers). Both readers give the same DER list for every
file that reads and refuse every file that does not: `same 31, diff 0`.
Refusal messages differ in wording (`pem`'s own error text, and a private
key block is refused at its END line instead of its BEGIN line).

End to end, an `aprv serve --roots` built from this tree, given
`apple-bundle.pem`, reports at `GET /v1/info` the three fingerprints in
`DEFAULT_ROOT_SHA256` with `source: configured`; the server's unit tests
`a_pem_bundle_of_the_apple_roots_reads_back_to_their_der` and
`a_pem_file_and_its_base64_line_have_one_fingerprint` pin the same.

## Limits

The comparison covers the inputs above, not every byte string. Five of the
six `fixtures/` PEM files are `openssl x509 -text` dumps and both readers
refuse them at line 1.
