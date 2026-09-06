# Releasing the Rust port

The `publish-crates` job (crates.io trusted publishing via
`rust-lang/crates-io-auth-action`) is implemented in `release.yml`, and the
`release-please-config.json` entry for `rust/Cargo.toml` is implemented.
Owner bootstrap steps and the release-budget note live in
[`BOOTSTRAP.md`](../BOOTSTRAP.md) under "crates.io" — that section is
current and this file no longer repeats it. Until they are done,
`publish-crates` skips itself rather than failing the tag run.

## `rust/Cargo.lock` is committed, and release-please bumps it

Cargo ignores a library's lockfile downstream, so the file constrains only
this repository. It is committed because every CI leg runs `--locked`: a
hijacked dependency release cannot reach a runner before the seven-day
dependabot cooldown has looked at it.

The lockfile records this package's own version, so a release that touched
only `Cargo.toml` would leave the lock stale and fail every `--locked` job.
release-please's toml updater cannot address a `[[package]]` entry by name,
so `.github/workflows/release-please.yml` runs `cargo update --workspace`
(and, for `rust/fuzz/Cargo.lock`, `cargo update -p
apple-purchase-receipt-verifier`) on the release branch right after the
action and pushes the result. If a release PR ever lands with a stale lock,
that step is the thing to check.

Regenerate the file the way CI needs it, resolvable on the 1.74.0 floor:

```bash
CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo +stable generate-lockfile
```

## What the published tarball contains

`exclude = ["tests/**", "fuzz/**"]` in `Cargo.toml`, so the crate ships
`src/`, `certs/`, `Cargo.toml`, `Cargo.lock`, `README.md` and `LICENSE` and
nothing else. Cargo packs the lockfile whatever the manifest says; a
consumer's build ignores it.
The tests read `../../fixtures`, which a registry consumer does not have,
and a test suite that cannot run is worse than one that is not shipped. That
means the published file set is **not** the repository file set, which is
exactly the gap the post-publish smoke test below exists to close.

## `post-publish-smoke.yml` — added

The `crates` job copies `.github/smoke/crates-smoke/` outside the checkout,
runs `cargo add "apple-purchase-receipt-verifier@=$VERSION"` against the real
registry and `cargo run`. The manifest deliberately ships with an empty
`[dependencies]` so it can never pin a stale version.

`.github/smoke/crates-smoke/src/main.rs` asserts three bundled roots, verifies
`fixtures/public-receipts/receipt-sandbox-g5.b64` and checks that a verifier
configured for another bundle id rejects it with `Reason::WrongBundleId`. The
receipt comes from the checkout, not from the crate, which is the point of the
paragraph above: `exclude` drops the fixtures, so this exercises the file set a
consumer actually receives.

The leg is gated on the `registries` input, so it skips rather than fails while
crates.io is unbootstrapped (`BOOTSTRAP.md`).
