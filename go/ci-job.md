# CI jobs for the Go port

The jobs below go into `.github/workflows/ci.yml`, plus one entry for
`.github/dependabot.yml` and one job for `.github/workflows/post-publish-smoke.yml`.
They follow the conventions already in those files: every action pinned to a
full commit SHA with the tag in a trailing comment, `persist-credentials: false`
on every checkout, `timeout-minutes` on every job, and no `permissions:` block
per job because the workflow-level `contents: read` already covers them.

## One SHA has to be resolved before this lands

`actions/setup-go` does not appear anywhere in this repository yet, so there is
no existing pin to copy and the GitHub API was not reachable from the
environment this port was written in. Resolve it in the same commit:

```bash
gh api repos/actions/setup-go/commits/v6 --jq .sha
```

and replace every `<SETUP_GO_SHA>` below with the result, keeping the
`# v6.x.y` comment naming the tag it resolved from. Dependabot's existing
`github-actions` entry keeps it current afterwards.

## `ci.yml` — the test matrix

```yaml
  go:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    strategy:
      fail-fast: false
      matrix:
        # Both supported lines plus every line down to the go.mod floor:
        # a floor nothing executes is a claim, not a fact. This is the
        # analogue of the java-runtime-8 job.
        go: ["1.22", "1.23", "1.24", "1.25", "1.26", "1.27"]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-go@<SETUP_GO_SHA> # v6.x.y
        with:
          go-version: ${{ matrix.go }}
          cache: true
      # GOTOOLCHAIN=local is the whole point of the matrix. Without it Go
      # downloads a newer toolchain whenever go.mod asks for one, and the
      # "go 1.22" floor would be compiled by 1.27 on every leg.
      - run: go version && go test ./...
        working-directory: go
        env:
          GOTOOLCHAIN: local
          GOFLAGS: -mod=readonly
```

## `ci.yml` — the other operating systems

Windows earns its place: the conformance adapter walks the filesystem to find
`fixtures/`, the `.b64` fixtures pick up CRLF on checkout, and the
whitespace-stripping base64 decode is what makes that survive. macOS earns its
place because `x509.Certificate.Verify` falls back to the OS trust evaluation
there, and this library must still never reach it. One Go version each, not a
cross product.

```yaml
  go-platforms:
    runs-on: ${{ matrix.os }}
    timeout-minutes: 20
    strategy:
      fail-fast: false
      matrix:
        os: [macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-go@<SETUP_GO_SHA> # v6.x.y
        with:
          go-version: "1.27"
          cache: true
      - run: go test ./...
        working-directory: go
        env:
          GOFLAGS: -mod=readonly
```

## `ci.yml` — race detector

`-count=2` so a second run in the same process catches state left behind by
the first, which is exactly what a cached buffer or a memoised location would
be.

```yaml
  go-race:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-go@<SETUP_GO_SHA> # v6.x.y
        with:
          go-version: "1.27"
          cache: true
      - run: go test -race -count=2 ./...
        working-directory: go
```

## `ci.yml` — fuzzing

The seed corpora already run on every `go test`; this is the exploratory pass.
A crasher it finds is written under `testdata/fuzz/` — commit that file, it
becomes a permanent regression case.

```yaml
  go-fuzz:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-go@<SETUP_GO_SHA> # v6.x.y
        with:
          go-version: "1.27"
          cache: true
      - name: fuzz the DER reader
        run: go test ./internal/der -run '^FuzzParseDER$' -fuzz '^FuzzParseDER$' -fuzztime=60s
        working-directory: go
      - name: fuzz the verifiers
        run: |
          set -euo pipefail
          for target in FuzzVerifyReceipt FuzzVerifyReceiptBase64 FuzzVerifyTransaction; do
            go test . -run "^${target}\$" -fuzz "^${target}\$" -fuzztime=60s
          done
        working-directory: go
```

## `ci.yml` — lint, vulnerabilities, and the structural gates

Two things about this job differ from the plan and were measured rather than
assumed:

1. **staticcheck cannot lint another module in place.** Running
   `go run honnef.co/go/tools/cmd/staticcheck ./../...` from `go/tools`
   fails with `pattern ./../...: directory prefix .. does not contain main
   module or its selected dependencies`. Build the binary in the tools module
   and run it from the library directory instead.
2. **staticcheck v0.8.1 requires Go 1.26 or newer** (`honnef.co/go/tools@v0.8.1
   requires go >= 1.26.0`), which is why `go/tools/go.mod` declares
   `go 1.26.0` while the library module stays at `go 1.22`. The two are
   separate modules precisely so the linter's floor never becomes the
   library's.

```yaml
  go-lint:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-go@<SETUP_GO_SHA> # v6.x.y
        with:
          go-version: "1.27"
          cache: true
      - run: test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }
        working-directory: go
      - run: go vet ./...
        working-directory: go
      # Pinned in go/tools/go.mod + go.sum, so the linter versions are
      # lockfile material dependabot can bump rather than a floating
      # @latest that changes what CI enforces without a commit.
      - name: build the pinned linters
        run: |
          set -euo pipefail
          go build -o "$RUNNER_TEMP/staticcheck" honnef.co/go/tools/cmd/staticcheck
          go build -o "$RUNNER_TEMP/govulncheck" golang.org/x/vuln/cmd/govulncheck
        working-directory: go/tools
      - run: "$RUNNER_TEMP/staticcheck ./..."
        working-directory: go
      - run: "$RUNNER_TEMP/govulncheck ./..."
        working-directory: go
```

`govulncheck` reports only reachable vulnerabilities. The library has no
dependencies, so anything it reports is a standard-library advisory and the
fix is a toolchain bump — which is worth failing the build for, because the
ones that reach this code arrive through `x509.ParseCertificate` on
attacker-supplied certificate bytes.

### The forbidden-API gates are Go tests, not a grep

The plan proposed a `grep -rn` step. That is in the workflow below as a
belt-and-braces line, but the real gates are
`TestLibraryImportsNothingForbidden` and
`TestLibraryMentionsNoForbiddenIdentifier` in `go/apisurface_test.go`: they
parse the library's own source with `go/parser`, so a comment explaining *why*
the platform verifier is never called does not trip the check that enforces
it, and a rename cannot slip past a regex. They run in every matrix leg, on
every platform, for free. The grep stays as a second, dumber opinion:

```yaml
      # Structural gates: the library must never reach the OS trust store
      # or the network. The authoritative versions of these are Go tests
      # (apisurface_test.go); this is a second, cruder opinion that fails
      # even if someone deletes them.
      - name: no system trust store, no network
        run: |
          set -euo pipefail
          if grep -rn --include='*.go' \
              -e 'x509\.SystemCertPool' -e 'x509\.NewCertPool' \
              -e 'x509\.VerifyOptions' -e '"net/http"' -e '"net"' \
              --exclude='*_test.go' --exclude-dir=tools --exclude-dir=gencerts .; then
            echo "::error::forbidden API in the published module"
            exit 1
          fi
        working-directory: go
```

## `ci.yml` — the embedded roots cannot drift

`go/roots/certs` is a copy of the repo-root `certs/`, because an embed pattern
may not reach outside its module directory (verified: `//go:embed
../certs/AppleIncRootCertificate.cer` is an `invalid pattern syntax` compile
error). This is a new repo invariant of exactly the same species as
`node/src/roots-data.ts`, and it belongs next to that bullet in `CLAUDE.md`.

```yaml
  go-generate-check:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-go@<SETUP_GO_SHA> # v6.x.y
        with:
          go-version: "1.27"
          cache: true
      - run: go generate ./... && git diff --exit-code
        working-directory: go
```

`TestEmbeddedRootsMatchTheRepositoryCerts` asserts the same thing from inside
the suite, so a contributor who never runs `go generate` still sees it locally.

## `dependabot.yml`

```yaml
  - package-ecosystem: gomod
    directory: /go
    schedule:
      interval: weekly
    cooldown:
      default-days: 7
  - package-ecosystem: gomod
    directory: /go/tools
    schedule:
      interval: weekly
    cooldown:
      default-days: 7
```

The `/go` entry has no requirements to track and only follows the toolchain
directive; `/go/tools` tracks staticcheck and govulncheck. Keeping them
separate is what stops a linter bump from touching the published module graph.

## `post-publish-smoke.yml`

The job that would catch the `go:embed` copy being missing from the module
zip — the Go analogue of the `dist/index.js`-missing-from-the-tarball incident
that motivated this workflow. It installs by module path from
`proxy.golang.org`, outside the checkout, on the **floor** Go with
`GOTOOLCHAIN=local`.

```yaml
  go:
    name: go — resolve the published module and verify a receipt
    needs: resolve
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ needs.resolve.outputs.ref }}
          persist-credentials: false
      - uses: actions/setup-go@<SETUP_GO_SHA> # v6.x.y
        with:
          go-version: "1.22"
          cache: false
      - name: install the published module into a scratch consumer
        env:
          VERSION: ${{ needs.resolve.outputs.version }}
          MODULE: github.com/${{ github.repository }}/go
        run: |
          set -euo pipefail
          mkdir -p "$RUNNER_TEMP/go-smoke"
          cp .github/smoke/go-smoke/main.go "$RUNNER_TEMP/go-smoke/"
          cp fixtures/public-receipts/receipt-sandbox-g5.b64 "$RUNNER_TEMP/go-smoke/"
          cd "$RUNNER_TEMP/go-smoke"
          go mod init smoke
          # The proxy does not publish atomically; poll for the version.
          for attempt in $(seq 1 20); do
            if go get "${MODULE}@v${VERSION}"; then break; fi
            echo "proxy has not picked up v${VERSION} yet (attempt $attempt of 20); waiting 30s"
            sleep 30
          done
          go run .
        env:
          GOTOOLCHAIN: local
```

`.github/smoke/go-smoke/main.go` verifies
`fixtures/public-receipts/receipt-sandbox-g5.b64` against `AppleReceiptRoots()`
and asserts the bundle id and the two in-app purchases — the same shape as the
npm and PyPI smoke programs. Keep it outside `go/` so it never becomes part of
the published module.

## zizmor

Nothing new is introduced: no `pull_request_target`, no interpolation of
event-controlled fields into a `run:` body (the smoke job routes them through
`env:`, as the existing jobs do), and no cache in a publish job. The
0-findings baseline holds.
