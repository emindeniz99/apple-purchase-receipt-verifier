# CI notes for the Go host (lane C, rust-core migration)

For the integrator. This lane does not touch `.github/`; everything the
workflows need to change for the wazero host is here. Nothing needs a
secret.

## What changed under CI

- `go/go.mod` now has one requirement, `github.com/tetratelabs/wazero
  v1.9.0`, and a `go.sum`. The directive reads `go 1.22.0`, not `go 1.22`,
  because wazero v1.9.0's own `go.mod` does; the floor is still Go 1.22.
  `GOFLAGS=-mod=readonly` in the `go` job works, since `go.sum` is committed.
- `go/internal/wasm/aprv.wasm` is git-ignored until integration: CI copies the module into place before building, since `//go:embed` needs it present. `aprv.wasm.sha256` is committed.
- `go/internal/wasm/aprv.wasm` and `aprv.wasm.sha256` are the embedded
  module. **They are the round-13 stand-in (0.6 core) until the release build
  overwrites both**; see `wasm-copies` below. One thing differs from the
  round-13 artifact: its panic-location strings held the build directory
  (11 paths, all under a scratch directory), which may not be committed, so
  that fixed-length prefix was overwritten in place with `/buildxxx...`. The
  module is otherwise byte for byte the original (`da786ac8...fb68`, 2,967,116
  bytes, unchanged length), validates with `wasm-tools`, and answers the corpus
  identically; its committed hash is `f837e7a3...7e4a`. The release build remaps
  its paths and needs no such step.
- The hand-written verifier is gone. The last commit that has it is
  `ac000fd`, the parent of the commit that removed it; use it as the oracle
  for a differential run and as the source of the port-only tests
  (Phase 7 step 1).
- 221 of the 311 cases differ with the stand-in, because its wire is the 0.6
  one (`payloadJson`, camelCase receipts, `INVALID_*_FORMAT` reasons). With
  the release build the wire is the 0.7 one this package reads, and the
  conformance job is the gate that says so. Until then `go test ./...` is red
  on `TestConformance` only.

## Jobs

| Job | Change |
|---|---|
| `go` (matrix `1.22` to `1.27`, `GOTOOLCHAIN=local`) | none to the command (`go test ./...`). Each leg downloads wazero once; give the job a module cache. Expect about 45 s per leg on 4 cores. The `1.22` leg is the floor claim: it builds wazero v1.9.0 on the oldest toolchain. |
| `go-race` | `go test -race -count=2 ./...` as today. Slow: the host tests alone take about 80 s under `-race` on 4 shared cores, the root package several times that. Raise `timeout-minutes` to 40. |
| `go-platforms` | keep macOS and Windows on Go 1.27 with `go test ./...`. Add `CGO_ENABLED=0` to both. wazero's compiler runs on both; no leg-specific code. |
| `go-cross` (new) | `CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> go build ./... && go vet ./...` for `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `linux/arm64`. All four pass on this lane (Go 1.24.7). Add `linux/386` if 32-bit is claimed: it builds too, but wazero runs it on its interpreter, and the 256 MiB memory limit is a 32-bit hazard nobody has measured. |
| `go-scratch` (new) | the `FROM scratch` check with no daemon: `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$RUNNER_TEMP/scratch/corpusrun" ./internal/corpusrun`, copy one calls file next to it, `sudo chroot "$RUNNER_TEMP/scratch" /corpusrun /calls.jsonl` with an empty environment, and compare the rows with an ordinary run. Also `ldd` must say "not a dynamic executable". Passed here: 22 rows, identical output. |
| `go-fuzz` | **delete the `internal/der` step**: `FuzzParseDER` went with the package. The `FuzzVerifyReceipt` and `FuzzVerifySignedData` step stays. Each execution costs about 5 ms (a receipt) to 15 ms (a JWS) now, so 60 s is about 10k executions; raise `-fuzztime` if that matters. |
| `go-lint` | unchanged. `govulncheck ./...` now sees wazero: the comment "the library has no dependencies, so anything it reports is a standard-library advisory" is out of date. The grep for `x509.SystemCertPool` and friends still passes. |
| `go-generate-check` | unchanged until Phase 7 deletes `go/roots/certs` and `go generate`. |
| `wasm-copies` | for Go: `cd go/internal/wasm && sha256sum -c aprv.wasm.sha256`, and the hash in that file must equal the release build's `aprv.wasm` SHA-256 (`test "$(cut -d' ' -f1 aprv.wasm.sha256)" = "$BUILD_SHA256"`). The package also checks the pair when it loads, so a copy swapped without its hash file fails every test on import. `release-please.yml` must refresh **both files together** on the release branch. |
| `one-implementation` | the grep gate must allow, in `go/`: `crypto/x509` in `config.go`, `roots.go`, `verifier.go` (the Config's trust-anchor type and `.Raw`; nothing is parsed or checked there); `crypto/sha256` and `encoding/hex` in `roots.go` and `internal/wasm/wasm.go` (pinning the roots and the module); `encoding/base64` in `verifier.go` and `receiptpayload.go` (init's roots, the wire's bytes fields). `x509.ParseCertificate` appears only in `roots.go`, which Phase 7 deletes with `go/roots/`. `apisurface_test.go` (`TestLibraryHoldsNoVerificationLogic`, `TestOnlyTheRootsAreEverParsedAsCertificates`) holds the same lines in Go and fails on a new import, so keep the two in step. |
| post-publish `smoke-go` | the smoke module resolves `go/vX.Y.Z` from the proxy on the floor toolchain with `GOTOOLCHAIN=local`. It now downloads wazero too, so it needs `go mod tidy` (or `go get`) in the scratch module and a `go.sum`, and `GOFLAGS=-mod=mod` or an explicit `go mod download`. Keep the assertion that `DefaultConfig().Roots()` returns three certificates, and add one genuine receipt verifying through the embedded module. |
| `dependabot.yml` `/go` | wazero v1.10 needs Go 1.23, v1.11 needs 1.24 and v1.12 needs 1.25. To keep the floor at 1.22, ignore wazero versions `>= 1.10.0` (the floors-are-claims rule in CLAUDE.md); raising the floor is a deliberate `feat`, not a bump. wazero v1.9.0 and v1.12.0 measured the same speed here (5.0 and 5.6 ms per receipt, within noise on a loaded machine). |

## The corpus parity gate

`go/internal/corpusrun` runs a calls file through the package's host layer
(the same pool and canonical-ABI call `Verifier` uses) and prints rows in the
Node runner's format, so round 13's classifier reads them unchanged:

```sh
cd go && CGO_ENABLED=0 go build -o "$OUT/corpusrun" ./internal/corpusrun
for c in cases hostile algorithms substrate fuzz; do
  "$OUT/corpusrun" [-module path/to/aprv.wasm] "$CALLS/$c.jsonl" > "$OUT/pkg-$c.jsonl"
done
python3 docs/evidence/2026-09-29-canonical-abi-final/py/classify.py pkg "$CALLS" "$NODEROWS" "$OUT/pkg"
```

`$CALLS` is the directory `py/calls_bytes.py` writes (one file per corpus)
and `$NODEROWS` the ABI v1 Node rows. `-module` runs a candidate build without
copying it into the package first. With the stand-in this gives 6,176
identical, 2 `clock-moves-chain` and 1 `init-refusal`, as round 13 expects;
against the release build the reference rows change with the wire and the
classifier's categories are Phase 1's to redefine. The host layer is compared
byte for byte; the typed reading in `receiptFromJSON` and `readResult` is what
the 311 cases pin.

## Suggested legs, not built here

- `GODEBUG=fips140=only go test ./...`: the old suite had a subprocess test
  that FIPS-only mode does not crash the caller. Nothing in the package uses a
  non-FIPS Go primitive now (`crypto/rand`, `crypto/sha256`), so the leg is
  cheap insurance rather than a test file.
- An isolation leg: plant a root in `SSL_CERT_FILE` and `SSL_CERT_DIR` and run
  `transaction/reject-foreign-root` through the package; the module cannot
  read a file, so the answer must not change. The old `systemtrust_test.go`
  did this in a subprocess against Go's own trust store.
- A wazero-only memory check in workerd-free environments: none needed; the
  256 MiB limit is `memoryLimitPages` in `internal/host/module.go` and
  `TestMemoryLimit` covers it.

## The floor

`go 1.22.0` in `go.mod`, wazero v1.9.0. Raising wazero raises the floor
(v1.10: 1.23, v1.11: 1.24, v1.12: 1.25), and the `go` matrix would then start
at the new floor. The Go module is published from a `go/v*` tag: never move
or delete one; a bad release is fixed forward with `retract`.
