# aprv-openssl

The OpenSSL adapter under `apple-purchase-receipt-verifier`: the one crate
of the library that holds `unsafe` code, and the only one that talks to
OpenSSL. It parses, builds paths and checks signatures; the core
(`../src/`) keeps Apple's policy (the pinned roots, the marker OIDs, the
chain instant, the bounds, the reasons and their order) and holds
`#![forbid(unsafe_code)]`.

It knows nothing about JSON, the C ABI or Wasm. Its surface is plain Rust
values: DER in, certificates, facts and booleans out.

| Item | What it does |
|---|---|
| `Certificate` | one X.509 certificate (`d2i_X509`, whole input): comparison, issuance (`X509_check_issued` then `X509_verify`), key usability, extensions, validity at a second, CA capability, the readability rules the 0.7 reader applied (version, octet-aligned signature, no duplicate extension, decodable basicConstraints and keyUsage) |
| `verify_path` | builds and validates a path to the caller's anchors at a given second, and reports every problem with its depth |
| `SignedData` | a CMS `SignedData`: `parse` bounds the envelope (`EnvelopeLimits`) before `d2i_CMS_ContentInfo`; then content, embedded certificates, per-`SignerInfo` signer matching, signed-attribute facts and the signature check |
| `payload::*` | the receipt payload through the templates in `payload.c`, after the header walk, within a `Budget` |
| `full_decodes_during` | how many full CMS decodes ran while a closure ran (the tests' seam for "refused before the full decode") |
| `verify_es256`, `sha256` | the JWS signature and the digest |
| `keys_used_during` | the SPKI of every key used while a closure runs (the tests' key-use seam) |

## The OpenSSL APIs, and why these

- **CMS**: `d2i_CMS_ContentInfo`, `CMS_get0_SignerInfos`,
  `CMS_SignerInfo_cert_cmp`, `CMS_SignerInfo_set1_signer_cert`,
  `CMS_SignerInfo_verify` (the signature over signed attributes) and
  `CMS_SignerInfo_verify_content` (the `messageDigest`, or the signature
  over the content), with the content digested through our own `BIO_f_md`
  chain by each `SignerInfo`'s own `digestAlgorithm`. Never `CMS_verify`:
  it builds a store, may consult default trust, and decides which signer
  counts; the core does all three itself. `CMS_SignerInfo_verify_content`
  takes the hash from `digestAlgorithm` alone. For an RSA key OpenSSL
  reads `signatureAlgorithm` only to choose PKCS#1 v1.5 or RSASSA-PSS and
  compares a hash only in the PSS parameters; for an ECDSA key it does not
  read `signatureAlgorithm` at all.
- **Paths**: `X509_verify_cert` over an `X509_STORE` holding one of the
  caller's anchors and nothing else, run once per anchor that may end the
  path, with the untrusted certificates narrowed first to those that sign
  the target or one another by signature: OpenSSL's issuer lookup takes
  the first name match, in the store and in the untrusted list, and never
  tries another, so neither the anchors' order nor a same-named
  certificate placed first decides the path. Each run sets
  `X509_V_FLAG_PARTIAL_CHAIN` (a pinned anchor is an anchor whether or not
  it is self-signed), `set_time` (the chain instant), `set_depth` (the
  path length bound) and a verify callback that records every problem and
  lets verification continue, so the core can apply 0.7's order. Anchors are trusted by fiat: their own validity,
  CA flag and path length problems are waived, as is an expiry reported at
  exactly the `notAfter` second (RFC 5280 includes it; OpenSSL checks
  whole seconds and the core adds the millisecond check). No purpose,
  policy, revocation or host check is asked for.
- **Certificates**: `X509_check_issued`, `X509_verify`, `X509_check_ca`,
  `X509_get_extension_flags` (`EXFLAG_CRITICAL`: an unhandled critical
  extension), `X509_get_ext_d2i`, `ASN1_BIT_STRING_get_length` (4.0 API:
  the signature's unused bits).
- **Templates**: `ASN1_item_d2i` with items declared in C, the way OpenSSL
  declares its own. `payload.c` is the receipt payload (a SET OF
  attributes, each a `SEQUENCE OF ANY` whose first three fields the adapter
  types; the contract accepts a fourth field). `envelope.c` is a shallow
  `ContentInfo` and `SignedData` whose members stay raw `ANY` values: it
  names the content type and gives the certificate, CRL and `SignerInfo`
  counts before `d2i_CMS_ContentInfo` builds every embedded certificate's
  public key. Both declare their items' prototypes, and `envelope.c`
  asserts the layout `src/sys.rs` mirrors (`_Static_assert` there, `const`
  assertions here).
- **The header walk** (`src/walk.rs`): `ASN1_get_object`, OpenSSL's TLV
  header decoder, over raw BER. It reads tags and lengths and decodes no
  value, allocates nothing and copies nothing. It is the only file of the
  adapter that calls `ASN1_get_object` (`src/sys.rs` declares it), and the
  core calls it nowhere: `tools/check-layering.mjs` rule 6 holds both. It
  answers what OpenSSL's decoders do not:
  - over the whole envelope, before the shallow decode's member bounds
    and the full decode: nesting of constructed values of every class
    (the core's depth bound, 32) and the number of values (its node
    budget, 100,000), so the budget also bounds the entries the shallow
    decode builds;
  - the chunks of a constructed `OCTET STRING` in the payload (an
    attribute value, the Xcode wrap) must be `OCTET STRING`s, as X.690
    section 8.7.3 says; OpenSSL joins any tag. Six constructed levels
    pass, as OpenSSL decodes six (`ASN1_MAX_STRING_NEST`). Elsewhere a
    constructed string's chunks are joined unchecked, as OpenSSL's
    `asn1_collect` joins them, and the whole string is handed to OpenSSL
    at its outermost level;
  - over the receipt payload, the same budgets plus the header forms 0.7's
    reader refused and OpenSSL reads: a tag in high-tag-number form, a
    length of more than four octets, and a constructed string value.
- **Signatures**: `EcdsaSig` and `EcKey` through rust-openssl for ES256
  (P-256 only, 64-byte `r || s`); everything else inside the CMS and path
  calls above.

Every raw call sits in a small safe function with a `// SAFETY:` comment;
the crate denies `unsafe_op_in_unsafe_fn` and Clippy's
`undocumented_unsafe_blocks`.

## Isolation

- `init()` runs once, before any other OpenSSL call from this crate:
  `OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG)` first, which runs
  OpenSSL's configuration step in its "no configuration" form, so a later
  implicit initialisation (rust-openssl's `OPENSSL_init_ssl`) cannot load
  `openssl.cnf` or `OPENSSL_CONF`. Every public entry point calls it.
- No store is built with default paths, and no lookup is added:
  `SSL_CERT_FILE`, `SSL_CERT_DIR` and OPENSSLDIR's `certs/` are never
  read. No provider or engine is loaded, and nothing opens a socket.
- `tests/isolation.rs` holds this from outside. A child process gets a
  planted `SSL_CERT_FILE` and `SSL_CERT_DIR` holding the root of the
  fixture chain, an `OPENSSL_CONF` whose default property query names a
  provider that does not exist (loaded, it breaks every signature check),
  and `OPENSSL_MODULES` and `OPENSSL_ENGINES` directories. The child must
  still anchor the chain under its real root only, and verify the receipt.
  Under `strace` (`APRV_REQUIRE_STRACE=1` makes a missing one fatal), it
  must touch no planted path and nothing under OPENSSLDIR, and open no
  socket. Two controls prove the detectors: loading the configuration
  before the adapter's first call breaks verification and shows in the
  trace, and the planted trust file and directory, loaded explicitly,
  anchor the chain.
- `../tests/trust_pinning.rs` scans this crate's source for trust-path,
  configuration, provider and socket APIs.

**Two limits of the isolation test.** On a build configured
`no-autoload-config` (the prebuilt native and wasm32-wasip1 installs of the
evidence), rust-openssl's initialisation never asks for the configuration,
so the test's "isolated" child proves the rule only on the vendored build,
which CI runs. And OpenSSL still reads its CPU-capability variables
(`OPENSSL_ia32cap`, `OPENSSL_armcap`, ...) on native builds with assembly;
a planted value can make a process crash with an illegal instruction, but
cannot change a verdict. Neither is tested.

**One limit.** OpenSSL's configuration is process-wide. A host process
that initialises OpenSSL with its configuration before this crate's first
call (another library calling `OPENSSL_init_crypto` with
`OPENSSL_INIT_LOAD_CONFIG`, or rust-openssl's own initialisation in a
build without `no-autoload-config`) has loaded it for everyone, and this
crate runs under it. `aprv.wasm` and the C ABI's own OpenSSL are alone in
their process, so this concerns a Rust program that also uses OpenSSL.

## Build inputs

The adapter needs **OpenSSL 4.0 or later**; `build.rs` refuses to build
against anything older (it calls 4.0 API and relies on 4.0's inclusive
`notAfter`).

**Vendored (the default feature).** openssl-sys 0.9.117 builds OpenSSL
from source through openssl-src, but its manifest takes only openssl-src
300.x (OpenSSL 3.x). `../vendor/openssl-sys` is the crates.io release with
that one requirement changed to 400.0.1 (OpenSSL 4.0.2);
`../vendor/refresh-openssl-sys.sh` rebuilds it from the release, checks
the release's SHA-256 and the one changed line. The library's workspace
applies it with `[patch.crates-io]`, and so do `../ffi` and `../fuzz`,
which are workspaces of their own. `../.cargo/config.toml` sets
`OPENSSL_CONFIG_DIR=/nonexistent/aprv-openssl`, which openssl-sys passes
to openssl-src as `--openssldir`, so the compiled-in OPENSSLDIR is a
directory that does not exist. Cargo reads that file only when invoked
inside `rust/`; from elsewhere, set the variable yourself.

A patch applies only inside the workspace that declares it: **a crates.io
user of the library gets openssl-src 300.x**, which `build.rs` refuses,
until openssl-sys widens its requirement. Such a user builds with
`OPENSSL_NO_VENDOR=1 OPENSSL_DIR=<OpenSSL 4 installation>`.

**Prebuilt (`OPENSSL_NO_VENDOR=1 OPENSSL_DIR=<prefix> OPENSSL_STATIC=1`).**
The evidence builds use OpenSSL 4.0.2 from
`https://github.com/openssl/openssl/releases/download/openssl-4.0.2/openssl-4.0.2.tar.gz`,
SHA-256 `736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8`,
configured with at least `no-shared no-module no-dso no-engine
no-autoload-config --openssldir=/nonexistent/aprv-openssl`
(`docs/evidence/2026-09-26-substrate-followup/scripts/build-libs.sh`).
The vendored and the prebuilt build answer all 6,179 corpus rows
identically (`docs/evidence/2026-09-29-openssl-core-parity.md`).

**wasm32-wasip1.** The same core builds against an OpenSSL 4.0.2 built
with wasi-sdk 34 (`linux-generic32 no-asm no-threads no-sock
no-ui-console` and the wasi-libc emulation macros;
`docs/evidence/2026-09-26-security-substrate-bakeoff/scripts/build-wasm-libs.sh`):

```sh
WS=<wasi-sdk 34.0>
CC_wasm32_wasip1=$WS/bin/clang \
CFLAGS_wasm32_wasip1="--target=wasm32-wasip1 --sysroot=$WS/share/wasi-sysroot" \
AR_wasm32_wasip1=$WS/bin/llvm-ar \
OPENSSL_NO_VENDOR=1 OPENSSL_DIR=<wasm OpenSSL prefix> OPENSSL_STATIC=1 \
  cargo build --target wasm32-wasip1 --lib
```

`payload.c` and `envelope.c` are compiled by `cc` with the headers of the
OpenSSL openssl-sys found, for the same target.

## Tests

`tests/isolation.rs` here; everything else runs through the core
(`cargo test --workspace` from `rust/`), including the shared vectors in
`fixtures/cases.json`.
