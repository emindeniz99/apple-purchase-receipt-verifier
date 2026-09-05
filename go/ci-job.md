# CI job to add for the Go port — post-publish smoke test only

Every job this file used to describe (`go`, `go-platforms`, `go-race`,
`go-fuzz`, `go-lint`, `go-generate-check`) is implemented in
`.github/workflows/ci.yml`, and the `/go` and `/go/tools` dependabot entries
are implemented in `.github/dependabot.yml`. This file survives only for the
one job that is not wired yet.

## `post-publish-smoke.yml` — not yet added

`post-publish-smoke.yml` currently covers npm, PyPI, Maven Central and
SwiftPM only (see `ROADMAP.md`). The job below is the Go leg: it would catch
the embedded `roots/certs/*.cer` copy being absent from the module zip, the
Go-shaped version of the incident that motivated that workflow. It installs
by module path from `proxy.golang.org`, outside the checkout, on the
**floor** Go with `GOTOOLCHAIN=local`.

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
      - uses: actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16 # v6.5.0
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

`.github/smoke/go-smoke/main.go` (not yet written — the other four smoke
programs live in `.github/smoke/`) needs to verify
`fixtures/public-receipts/receipt-sandbox-g5.b64` against `AppleReceiptRoots()`
and assert the bundle id and the two in-app purchases, the same shape as the
npm and PyPI smoke programs. Keep it outside `go/` so it never becomes part of
the published module.
