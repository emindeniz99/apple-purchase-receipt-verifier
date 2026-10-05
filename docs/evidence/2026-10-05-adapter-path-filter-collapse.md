# One recorded path instead of the adapter's per-anchor runs: no

**Question.** The adapter's `verify_path` re-filters, bottom-up, a set
the core has already filtered top-down: `linked_above` narrows the
untrusted certificates by name and signature, and `run` calls
`X509_verify_cert` once per anchor `X509_check_issued` pairs with the
target or one of them, keeping the first path that passes (R10 of the
2026-10-05 simplicity audit). If `authenticated_top_down` recorded the
issuer that vouched for each certificate, could the core hand OpenSSL
exactly one path and one anchor, with every verdict unchanged? The
answer decides whether that collapse (`collapse.patch`, about 100 fewer
lines) lands.

**Answer: no.** Every shared case and every corpus call keeps its answer,
byte for byte, but a genuine receipt whose unsigned bag holds an expired
certificate for its intermediate's key ahead of the renewal changes from
`ok` to `INVALID_CERTIFICATE`. The collapse is not applied; the per-anchor
runs stay.

**Versions.** OpenSSL 4.0.2 (`openssl-src` 400.0.1+4.0.2), Rust 1.98.1,
the test profile. The corpus is the archive `fixtures/corpus.json` pins
(`corpus-2026-09-29.tar.gz`, SHA-256 `89b599c5...b956d`): five pinned
call files, 6,179 calls. All runs 2026-10-05 on one Linux x86-64
container, on the branch at `docs(docs): record java's key-before-path
order for keyless targets`.

**Method.**

- The change (`collapse.patch`): `authenticated_top_down` returns each
  accepted certificate with what vouched for it, the first issuer of the
  round that reached it whose signature verified, an anchor, or nothing
  for an embedded copy of an anchor. `receipt_path` follows those links
  from the signer to an anchor and passes OpenSSL that path and a store
  of that anchor alone; `validate_pair` passes the anchor that signed the
  intermediate. The adapter's `run` becomes one `X509_verify_cert` call,
  and `linked_above`, `may_have_issued`, `links_hold` and
  `Certificate::signed_by` go.
- `cargo test --locked --workspace --all-features --no-fail-fast` in
  `rust/`, with and without the patch.
- `replay.sh` answers every corpus call with the native twin of
  `aprv.wasm` (the four calls of `aprv-surface`, answered as `aprv-wire`
  documents) at the checked-out tree; `classify.py` compares two row sets
  call by call: verdict, reason, payload, message.
- `path_cost.rs` counts the signatures the core checks itself (every key
  `keys_used_during` records, outside `X509_verify_cert`) for the shared
  receipt and the shared transaction, and times 200 verifications of
  each, three runs with and three without the patch.
- `renewed_intermediate.rs` builds the counterexample below.

The cargo-fuzz targets were not run: they need a nightly toolchain,
`cargo-fuzz` and a target directory of their own, which this run did not
have room for. The corpus's `fuzz` file (5,000 calls the fuzz campaign
derived from the shared cases) stands in for them.

## Results

| Check | Without the patch | With it |
|---|---|---|
| `conformance` (388 cases and two harness checks) | 390 passed | 390 passed |
| whole workspace | 729 passed | 729 passed, one test rewritten (below) |
| corpus rows (`results/collapse.txt`) | | 6,179 of 6,179 byte for byte the same |
| signatures the core checks itself, shared receipt (`results/path-cost.txt`) | 5 | 3 |
| signatures the core checks itself, shared transaction | 4 | 3 |
| one verification, shared receipt (3 runs) | 0.82, 0.82, 0.79 ms | 0.94, 0.93, 0.85 ms |
| one verification, shared transaction (3 runs) | 0.94, 0.85, 0.84 ms | 0.80, 0.99, 1.13 ms |
| renewed intermediate after its expired twin (`results/renewed-intermediate.txt`) | ok | `INVALID_CERTIFICATE` |

The timings are within the run-to-run noise of the test profile, where
`X509_verify_cert` dominates; the patch saves signature checks, not
measurable time.

**The counterexample.** `renewed_intermediate.rs` mints a root, two
certificates for one intermediate key (a renewal valid 2020 to 2099, and
an expired one valid 2010 to 2015, same subject), and a signer that key
signed, and judges a dateless receipt at 2025-01-01. Both intermediate
certificates are issued by the pinned root, so the top-down walk accepts
both, and both verify the signer; the walk records the first one in the
bag. With the expired one first the patched core hands OpenSSL the path
through it, and the answer is `INVALID_CERTIFICATE`. Without the patch,
`linked_above` keeps both and OpenSSL picks the issuer itself:
`get0_best_issuer_sk` takes the first candidate that is valid at the
check time and falls back to a name match only when none is
(`crypto/x509/x509_vfy.c:414-445`, the time check at 431). The receipt
verifies in either order, at 352f0d1 too. Its signature and chain are
genuine, so by R20 a change of its verdict is a bug.

A collapse that keeps this would record every issuer that vouched for
each certificate and hand OpenSSL all of them, which is the set
`linked_above` already computes; the saving would mostly move code
rather than remove it.

**The rewritten test.** With the patch, `trust_pinning.rs`
`an_intermediate_without_key_cert_sign_is_still_reported_as_not_a_ca`
fails on its message: it calls `receipt_path` directly with a leaf whose
intermediate lacks `keyCertSign`, which the top-down walk never accepts
(`X509_check_issued` judges `keyUsage`), so there is no recorded path
("chain does not reach a pinned root" instead of "an intermediate is not
a CA"; `UNTRUSTED_CHAIN` either way). The patch renames and rewrites it.
Through the public API the answer was already decided before the path.

**The same replay across the whole branch.** Against the branch's base
(352f0d1, `results/branch-before-collapse.txt` and
`results/branch-message-changes.txt`, from `message-changes.py`), the
branch's commits change no verdict in the corpus; among the shared cases,
`receipt/reject-eleven-embedded-crls` moves from `MALFORMED` to `ok`
within its `oneOf` (the ten-CRL cap went). 573 corpus rows differ: 568
change their message only, and five change their reason,
all the same input: the corpus's copy of
`receipt/reject-signer-on-an-unimplemented-curve` and four fuzz
mutations of it, generated before that fixture's intermediate carried the
WWDR marker. A vouched-for signer on an unimplemented curve under an
intermediate without the marker was `INVALID_CERTIFICATE_PURPOSE` (the
hand-written keyless path passed, then the marker failed); with Java's
order its key answers first, `INVALID_CERTIFICATE`, which is Java's
answer and the current fixture's. The shared case uses the current
fixture and keeps `INVALID_CERTIFICATE`.

**Where this stops holding.** The corpus is the 2026-09-29 archive and
the cases are those of `fixtures/cases.json` at this commit; neither
holds two certificates for one key, which is why both missed the
counterexample.
