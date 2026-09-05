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

Not yet wired — see [`ci-job.md`](./ci-job.md) for the job spec.
