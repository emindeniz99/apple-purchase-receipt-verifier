# The OpenSSL core against the 0.7 core, row by row (2026-09-29)

**Question.** The Rust core moved its ASN.1, X.509, CMS and signature work
from its own readers and RustCrypto to an OpenSSL 4.0.2 adapter
(`rust/openssl/`). Which answers changed, why, and does the vendored build
answer exactly as a build against a prebuilt OpenSSL does? This feeds the
review of the migration branch and step 1.2 (the vendored OpenSSL).

**Method.** One runner (`2026-09-29-openssl-core-parity/runner/`) takes each
ABI v1 call of the five request corpora (153 `cases`, 811 `hostile`, 22
`algorithms`, 193 `substrate`: 1,179 rows, plus 5,000 `fuzz` mutants) and
answers it with the 0.7 public API only: `verify_receipt`,
`verify_signed_data`, `verify_receipt_endpoint`, with the call's roots and
pinned clock. It is built three times: against the pre-migration core
(rust/ at the parent of the migration commit, RustCrypto), and against the
OpenSSL core linked to a prebuilt static OpenSSL 4.0.2 (`OPENSSL_DIR`) and
to the vendored one (openssl-src 400.0.1+4.0.2). The OpenSSL rows are then
compared with the pre-migration rows exactly, and with two reference row
sets from earlier spikes (the round-4 template build over the old C ABI,
and ABI v1 under Node) on the verdict alone, since those trees predate the
0.7 reason taxonomy.

**Versions.** rustc 1.98.1; OpenSSL 4.0.2 (tarball sha256
`736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8`, built
`no-shared no-module no-dso no-engine no-autoload-config
--openssldir=/nonexistent/aprv-openssl`); openssl-src 400.0.1+4.0.2 with
`OPENSSL_CONFIG_DIR=/nonexistent/aprv-openssl`; openssl 0.10.81,
openssl-sys 0.9.117 (one manifest line patched, `rust/vendor/`).

## Results

**Vendored against prebuilt: identical.** 6,179 of 6,179 rows are byte
for byte the same (`results/openssl-dir-vs-vendored.txt`).

**Pre-migration against OpenSSL** (`results/old-vs-openssl.txt`,
`results/reason-changes.txt`): 3,064 rows identical; 2,971 differ only in
the message of the same reason; 138 change the refusal reason; 5 change the
verdict; 1 differs in a configuration error's message. No row that verified
before is refused now.

The five verdict changes, all JWS, all refused before as `UNTRUSTED_CHAIN`
and verified now:

| Row | Why |
|---|---|
| `algorithms/jws/chain-ec-p521-sha512` | OpenSSL verifies a P-521 certificate signature on the path; RustCrypto had no P-521 |
| `substrate/pkix/jws/name-case-differs`, `name-printable-vs-utf8`, `name-extra-whitespace`, `name-trailing-space` | OpenSSL chains names by their RFC 5280 section 7.1 canonical form (case folded, whitespace collapsed, string type ignored); the 0.7 core compared bytes |

The security-substrate bake-off recorded all five as rows where Java (the
oracle) verifies and the Rust core alone refused
([2026-09-26-security-substrate-bakeoff.md](2026-09-26-security-substrate-bakeoff.md),
"cand=java"). Each path still ends at a pinned root and every signature on
it is checked.

The 138 reason changes fall into six groups (`results/reason-changes.txt`
lists each old and new reason and message with a count and an example id):

1. **OpenSSL decodes more of each embedded certificate** (50 receipt
   rows). A mutated certificate (a name entry, an extension) that the 0.7
   reader kept as bytes makes `d2i_CMS_ContentInfo` refuse the whole
   envelope: `MALFORMED`, where 0.7 reached the chain and refused there
   (`UNTRUSTED_CHAIN`, `INVALID_CERTIFICATE`, `INVALID_CERTIFICATE_PURPOSE`).
   The reverse happens too: a certificate the 0.7 reader refused and
   OpenSSL reads fails later, on the chain.
2. **Canonical names** (50 rows): 49 mutants of the four `name-*` rows,
   where the chain no longer stops at the name and the refusal comes from
   the next check (validity, the ES256 signature, the marker OID), and one
   receipt whose signer OpenSSL finds by its canonical issuer name before
   the signature fails (`MALFORMED` "signer certificate not embedded" to
   `INVALID_SIGNATURE`).
3. **x5c entries** (22 rows): which mutated certificate is "not a valid
   certificate" follows OpenSSL's decoder and the core's readability check
   (`INVALID_CERTIFICATE`) rather than the 0.7 reader.
4. **`crls` garbage** (9 rows, `substrate/cms/crls-garbage` and its
   mutants): OpenSSL decodes the unsigned `crls` field, so garbage there is
   `MALFORMED`; 0.7 skipped the field. The earlier bake-offs recorded this
   as "library stricter, keep": Apple receipts carry no `crls`.
5. **Signer identified by subjectKeyIdentifier** (5 rows): 0.7 refused it
   as `MALFORMED`; OpenSSL's `CMS_SignerInfo_cert_cmp` matches it, and the
   row is refused later (these substrate chains carry no Apple marker).
   Java accepts it too.
6. **The 0.7 reader's own limits in unsigned values** (2 rows, mutants of
   `substrate/flood/unsigned-attribute-values-10000`): a multi-byte tag or
   a five-octet length inside an unsigned attribute value was `MALFORMED`
   in 0.7; OpenSSL keeps the value whole, the core's depth measure finds
   no SEQUENCE or SET in it, and the row is refused later.

The 2,971 message-only rows are refusals with the same reason whose detail
now comes from OpenSSL's decoder ("not a CMS ContentInfo") or from the
bound that fires first: the embedded-certificate and SignerInfo bounds now
run on a shallow decode before the full one, so a mutant with 11 or more
certificates and a broken certificate reports the bound.

**Against the references** (`results/ref-template.txt`,
`results/ref-node.txt`): 0 rows where the OpenSSL core's verdict differs
from a reference and the pre-migration core does not. Every verdict
difference from the references predates the migration and is a 0.7 change
(the marker OIDs, caller policy and device binding leaving the core, the
endpoint's 21003, the untyped JWS claims), or a call the 0.7 API takes as
a string and the runner cannot pass (`NOT_UTF8`). The five flips above
move the core onto the references' verdicts.

## Where this stops holding

- The corpora exercise the 0.7 API; the reason tokens in the reference rows
  are pre-0.7, so the references are compared on verdicts only.
- One OpenSSL (4.0.2) on x86_64 Linux. The wasm32-wasip1 build of the same
  core links, and `examples/bench` built for it verifies the genuine
  sandbox receipts under Wasmtime, but the corpora were not run on it.
- The runner reads non-UTF-8 endpoint bodies lossily, as the ABI v1 shim
  did; the receipt and JWS entry points take strings.
