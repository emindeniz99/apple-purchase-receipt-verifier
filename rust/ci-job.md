# CI jobs to add for the Rust port

Everything the Rust port needs from `.github/workflows/ci.yml`, ready to
paste. The orchestrator owns that file; this is the exact text, in the house
style: every action pinned to a full commit SHA with its tag in a comment,
`persist-credentials: false` on every checkout, `timeout-minutes` on every
job, and no interpolation of event fields into a `run:` block.

The SHA pin below is the one `ci.yml` already uses at the time of writing —
copy whatever that file currently pins rather than this literal if
dependabot has since bumped it.

## Why no `actions/cache` and no toolchain action

The toolchains come from the `rustup` already present on the GitHub runner,
so this port adds **no new action to pin** beyond `actions/checkout`. A
clean debug build of the library plus every test target takes about 25
seconds on 94 packages, which is cheaper than restoring a cache — and it
keeps the repository's "publish jobs never cache" rule trivially satisfiable,
because there is no cache anywhere to poison.

## Jobs

```yaml
  rust:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    strategy:
      fail-fast: false
      matrix:
        # Rust has no LTS lines. 1.74.0 is the floor the manifest claims, so
        # it is the one that needs proving; stable is what users have; beta
        # is the early warning.
        toolchain: ["1.74.0", "stable", "beta"]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - run: rustup toolchain install ${{ matrix.toolchain }} --profile minimal
      # The floor is PROVEN, not declared. MSRV-aware resolution runs on a
      # modern cargo: the env var is stable since 1.84 and, unlike
      # `resolver = "3"` in the manifest, is invisible to consumers — cargo
      # 1.82 refuses to parse a manifest that carries that key, which would
      # break every consumer below 1.85.
      - name: pin dependencies to the floor
        if: matrix.toolchain == '1.74.0'
        working-directory: rust
        run: |
          rustup toolchain install stable --profile minimal
          CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo +stable generate-lockfile
      - name: test on the floor
        if: matrix.toolchain == '1.74.0'
        working-directory: rust
        run: cargo +1.74.0 test --locked --all-features
      - name: test on ${{ matrix.toolchain }}
        if: matrix.toolchain != '1.74.0'
        working-directory: rust
        run: |
          cargo +${{ matrix.toolchain }} test --all-features
          cargo +${{ matrix.toolchain }} test --no-default-features

  rust-lint:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - run: rustup toolchain install stable --profile minimal --component rustfmt,clippy
      - run: cargo fmt --check
        working-directory: rust
      - run: cargo clippy --all-targets --all-features -- -D warnings
        working-directory: rust
      # rust/certs/ is a copy of the repository's certs/, because
      # `cargo package` cannot reach outside the package directory. A copy
      # that drifts ships stale trust anchors — the Rust twin of the
      # node-runtimes job's roots-data.ts guard.
      - run: diff -r certs rust/certs

  rust-supply-chain:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - run: rustup toolchain install stable --profile minimal
      # Advisories, license policy, and the banned-crate list that is the
      # mechanised form of "pinned anchors only, no network ever": a
      # dependency bump cannot introduce a system trust store or an HTTP
      # client, because cargo-deny refuses the crates that carry them.
      #
      # This runs on the DEFAULT resolution, never on the MSRV lockfile, so
      # a stale floor pin cannot hide an advisory.
      - run: cargo install cargo-deny --locked
      - run: cargo deny check
        working-directory: rust
```

## Nothing else changes

The Rust port needs no entry in `conformance` (it runs
`fixtures/cases.json` from its own `cargo test`, and `tools/lint-cases.mjs`
stays the one linter of that file), and no new action for `zizmor` to
inspect beyond the checkout it already knows.

## `.github/dependabot.yml`

```yaml
  # The MSRV floor is a claim this repository tests (see the rust job's
  # 1.74.0 leg), so a bump that raises it is a deliberate decision and not
  # a dependabot merge. When one of these needs a newer Rust, raise
  # rust-version in rust/Cargo.toml in the same pull request, or ignore the
  # bump with a comment saying which floor it would have forced.
  - package-ecosystem: cargo
    directory: /rust
    schedule:
      interval: weekly
```
