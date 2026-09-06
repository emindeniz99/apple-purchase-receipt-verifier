# Releasing the Go module

Bootstrap preconditions (repository must be public, resolving the module by
hand before the first tag, the pkg.go.dev badge timing) and the immutability
hazards (never delete or move a `go/v*` tag, the future `/v2` module-path
requirement) live in [`BOOTSTRAP.md`](../BOOTSTRAP.md) under "Go module
proxy" — that section is current and this file no longer repeats it. The
`tag-go-module` job it describes is implemented in `release.yml`.

## What the module zip contains

`go/` and nothing else — the module's own subtree. That is why `go/LICENSE`
exists as a copy of the repo-root MIT text, the same reason `node/LICENSE`
does, and why the fixtures stay at the repository root and never move inside
`go/`: the tests reference `../fixtures`, which a consumer does not have and
never needs, keeping the zip to a few tens of kilobytes.

`go/tools/` is a separate module, so its `go.mod` excludes that subtree from
the library module entirely; staticcheck and govulncheck can never enter a
consumer's module graph.

## Smoke test

Wired. `post-publish-smoke.yml`'s `go` job resolves
`github.com/emindeniz99/apple-purchase-receipt-verifier/go@vX.Y.Z` from
`proxy.golang.org` into a scratch module outside the checkout, on the go.mod
floor (1.22) with `GOTOOLCHAIN=local`, and runs
`.github/smoke/go-smoke/main.go` against
`fixtures/public-receipts/receipt-sandbox-g5.b64`.

The assertion that earns the job its place is `AppleReceiptRoots()` returning
three certificates. `go:embed` cannot reach outside a module, so `go/roots/certs`
is a generated copy of the repo-root `certs/`; if it ever falls out of the
module zip the library still compiles and has no trust anchors at all. That is
the Go shape of the two empty npm releases that motivated the workflow.

The smoke program lives outside `go/` so it never becomes part of the published
module.
