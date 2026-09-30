# openssl-sys and OpenSSL 4: the upstream `vendored-4` feature

Measured 2026-09-30. This note backs the crates.io hold in
docs/rust-core/DECISIONS.md R19 and the crates.io section of BOOTSTRAP.md.

## Question

Does the change that lets `openssl-sys` vendor OpenSSL 4 break anything in
rust-openssl's own CI, and do the red jobs on that pull request come from
the change? The answer decides whether the core crate can leave its
workspace patch of `openssl-sys` and publish past 0.7 once upstream
releases the feature.

## The change

Upstream pull request
<https://github.com/rust-openssl/rust-openssl/pull/2692> adds an opt-in
`vendored-4` feature to `openssl-sys`. It builds OpenSSL 4 from
`openssl-src` 400.x, which the crate takes under a renamed optional build
dependency. The `vendored` feature does not change and still resolves
`openssl-src` 300.x.

## Method

The fork `emindeniz99/rust-openssl` ran upstream's CI workflow twice:

| Branch | Tree | Run |
|---|---|---|
| `ci-baseline` | upstream master, unchanged | 36632153660 |
| `vendored-openssl-4` | the pull request's branch | 36632157425 |

## Result

Both runs fail the same seven jobs and no others. All six new `vendored-4`
legs pass, and the existing `vendored` legs still resolve `openssl-src`
300.x. The seven failures happen on unchanged master too, so the change
does not cause them.

### The six BoringSSL legs: googlesource answers HTTP 503

The workflow step "Build OpenSSL" runs `curl -L $url | tar -xzf -` with

```
https://boringssl.googlesource.com/boringssl/+archive/338f44af3c92ef665bf740a8127a2d69c872b52a.tar.gz
```

The step passes no `-f` and no `--retry`, sets no `pipefail` and checks no
checksum. When the server answers with an HTML error page, `tar` reads the
page and exits 2.

Since about 2026-09-28 googlesource's web endpoints (`+archive`,
`?format=TEXT` and `?format=JSON`) intermittently answer with Google's
generic "Error 503 (Service Unavailable)!!1" page, 1,459 bytes, with no
`Retry-After` and no rate-limit wording, on every googlesource host tried.
Probed 2026-09-30 from 23:01 to 23:09 UTC:

| Request on the pinned URL | 503 |
|---|---|
| `HEAD` | 22 of 30 |
| `GET` | 2 of 6 |
| depth-1 `git fetch` of the commit, same host | 0 of 4 (3 to 7 s each) |

The GitHub mirror `github.com/google/boringssl.git` serves the same commit
with the same tree, `b9dcac50c52aa268a414058ec6b00081decd921b`.

The `+archive` tarball is not byte-stable. The server sets file mtimes at
request time, and three `GET`s gave three sizes and three SHA-256 values
with identical extracted contents, so nobody can pin it by hash.

Other projects hit the same outage and moved to git or the mirror:
pfBlockerNG/pfBlockerNG#3351, electron/build-images#102 and
richc117/legible-cities-app#252.

Nobody has filed this upstream yet. Upstream master has had no push since
2026-09-22; its last green master run is 35719133989.

Fixes, best first:

1. `git init`, `git fetch --depth 1 https://boringssl.googlesource.com/boringssl <sha>`,
   `git checkout FETCH_HEAD`. Same origin and same commit, and the commit
   hash verifies the content.
2. `curl -fsSL --retry` to a file, then `tar`. It hides the outage and
   adds no integrity check.
3. Fix 1 with the GitHub mirror as a fallback. It adds a second origin,
   for availability only.
4. A BoringSSL release tarball pinned by SHA-256, as curl/curl does. It
   changes the tested commit, so it is the maintainers' call.

### windows-vcpkg-arm64: `STATUS_ACCESS_VIOLATION`

`cargo test -p openssl --lib` crashes with `STATUS_ACCESS_VIOLATION`, on
unchanged master too.

- Runner image `windows-11-vs2026-arm64` 20260920.164.1, MSVC
  14.51.36231, vcpkg `openssl` 3.6.4, rustc 1.98.1.
- The last log line before the crash is
  `ssl::test::add_extra_chain_cert ... ok`. The tests run in parallel, so
  the crashing test need not be the next one in the log.
- Upstream's arm64 job passed on 2026-09-24 (PR #2690, run 36061870123)
  and has failed since 2026-09-25 (PR #2691, run 36192256708). The
  `windows-11-arm` image moved to Visual Studio 2026 between 2026-09-21
  and 2026-09-30 (actions/runner-images#14602). An older report of a
  similar crash: rust-openssl/rust-openssl#2406 (May 2025).

## Commands to repeat the probe

```sh
URL=https://boringssl.googlesource.com/boringssl/+archive/338f44af3c92ef665bf740a8127a2d69c872b52a.tar.gz
for i in $(seq 30); do curl -sS -o /dev/null -w '%{http_code}\n' -I "$URL"; done | sort | uniq -c
for i in $(seq 6); do curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' "$URL"; done

git init "$SCRATCH/boringssl"
git -C "$SCRATCH/boringssl" fetch --depth 1 \
  https://boringssl.googlesource.com/boringssl 338f44af3c92ef665bf740a8127a2d69c872b52a
git -C "$SCRATCH/boringssl" rev-parse FETCH_HEAD^{tree}
```

The tree hash printed last should be
`b9dcac50c52aa268a414058ec6b00081decd921b`; fetching the same commit from
`https://github.com/google/boringssl.git` should print the same.

## Limits

- The 503 counts come from one eight-minute window from one network. They
  show the outage exists, not its rate at any other time.
- Not verified: the contents of upstream's Actions cache; which runner
  image upstream's passing 2026-09-24 arm64 job used; a Google status page
  for the outage; and one upstream arm BoringSSL leg that exited 100 (from
  `apt-get`) instead of 2.
- Merging the pull request and releasing it is upstream's decision. Until
  an `openssl-sys` release carries `vendored-4`, the core crate keeps its
  workspace patch and stays at 0.7 on crates.io.
