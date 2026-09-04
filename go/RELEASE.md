# Releasing the Go module

## `release-please-config.json` needs no change at all

That is the opposite of the other four ports, so it is worth stating rather
than leaving as an absence: **there is no version string anywhere in the Go
module.** No manifest, no constant, no generated file. The git tag *is* the
version, so the Go port adds no `extra-files` entry, and `CLAUDE.md`'s "one
version, five files" count is unchanged by this port.

`.release-please-manifest.json` is likewise untouched.

## `release.yml` gains one job, and it is not a publish job

Go modules are served from the git repository by `proxy.golang.org`. There is
no registry account, no token, no OIDC trusted publisher, no 2FA handshake and
no per-month release budget. Publishing is a tag plus a proxy fetch.

**The tag matters.** A module in the subdirectory `go/` is published by a tag
named `go/vX.Y.Z` — the module path's subdirectory prefix, then the semver
tag. The plain `vX.Y.Z` tag release-please already creates does *not* publish
it.

```yaml
  tag-go-module:
    name: tag the go module at this release
    runs-on: ubuntu-latest
    needs: ci-passed
    timeout-minutes: 15
    permissions:
      contents: write     # the only job in this workflow that needs it
    steps:
      # No checkout: the ref is created through the API, so no credential is
      # ever written to disk and persist-credentials never applies.
      - env:
          GH_TOKEN: ${{ github.token }}
          REF: ${{ github.ref_name }}          # vX.Y.Z
        run: |
          set -euo pipefail
          TAG="go/${REF}"
          if gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG" >/dev/null 2>&1; then
            echo "$TAG already exists — skipping (re-runs are safe)."
          else
            gh api -X POST "repos/$GITHUB_REPOSITORY/git/refs" \
              -f "ref=refs/tags/$TAG" -f "sha=$GITHUB_SHA"
            echo "created $TAG at $GITHUB_SHA"
          fi
          # "Publishing" is a proxy fetch. Warm it so pkg.go.dev indexes the
          # version and the checksum-database entry exists before consumers
          # arrive.
          MOD="github.com/$GITHUB_REPOSITORY/go"
          for attempt in $(seq 1 10); do
            if GOPROXY=https://proxy.golang.org GOFLAGS=-mod=mod \
               go list -m "$MOD@${REF}"; then exit 0; fi
            echo "proxy has not picked up ${REF} yet (attempt $attempt of 10); waiting 30s"
            sleep 30
          done
          echo "::error::$MOD@${REF} never became resolvable from proxy.golang.org"
          exit 1
```

Adjust `needs:` to whatever the workflow's existing gate job is called; the
point is that the tag is created only after CI has passed for that commit.

### Why not a second release-please package

release-please *can* produce `go/vX.Y.Z` — its config schema has
`include-component-in-tag` and `tag-separator`, so
`{"go": {"component": "go", "include-component-in-tag": true, "tag-separator":
"/"}}` would work. It would also fork the version stream: each package bumps
only from commits touching its own path, which breaks "one version for all
packages", and the `linked-versions` plugin exists to re-couple them, which is
machinery bought to undo machinery. The API-created tag keeps a single version
stream and changes no release-please configuration.

**Never rename `release.yml`.** It is already the match key for npm and PyPI
trusted publishing; adding a job to it does not change that, and the rule in
`CLAUDE.md` still applies.

## Before the first `go/v*` tag

Three preconditions, all of which hold today except the last:

1. **The repository must be public.** `proxy.golang.org` cannot fetch a
   private repo, and `GOPRIVATE`/`GONOSUMDB` are a consumer-side setting this
   project cannot impose.
2. **`go/go.mod` must already declare the final module path on the tagged
   commit.** A tag pointing at a commit whose `go.mod` says something else is
   permanently poisoned in the checksum database.
3. **Verify the module resolves once, by hand, without burning a tag.** A
   pseudo-version needs no tag at all:

   ```bash
   GOPROXY=direct go list -m \
     github.com/emindeniz99/apple-purchase-receipt-verifier/go@<commit-sha>
   ```

   That proves the module path, the subdirectory prefix and the zip contents.

## The hazard the other registries do not have

**A published Go version is immutable, and its hash is recorded in
`sum.golang.org` forever.** Deleting or re-pointing `go/v0.4.0` does not
un-publish it; it makes every consumer's build fail with a checksum mismatch
that looks exactly like a supply-chain attack. There is no `npm unpublish`
equivalent and no "drop the staging repository".

- **Never delete or move a `go/v*` tag.** Ever.
- A bad release is fixed forward: a new patch version whose `go.mod` carries
  `retract v0.4.0 // <reason>`.
- `v2.0.0` and beyond require the module path to gain a `/v2` suffix
  (`.../go/v2`) and the tags to become `go/v2.x.y`. The shared version stream
  will reach 2.0.0 for reasons that have nothing to do with this port, so this
  is scheduled work: decide it before 1.0.0 is cut, not after.

These three bullets belong in `CLAUDE.md` under "the invariants that are easy
to break", alongside the `release.yml` rename rule.

## What the module zip contains

`go/` and nothing else — the module's own subtree. That is why `go/LICENSE`
exists as a copy of the repo-root MIT text, the same reason `node/LICENSE`
does. It is also why the fixtures stay at the repository root and never move
inside `go/`: the tests reference `../fixtures`, which a consumer does not
have and never needs, and keeping them out holds the zip to a few tens of
kilobytes.

`go/tools/` is a separate module, so its `go.mod` excludes that subtree from
the library module entirely; staticcheck and govulncheck can never enter a
consumer's module graph.

## Smoke test

`post-publish-smoke.yml` gets a `go` job — see `ci-job.md`. It is the job that
would catch the embedded `roots/certs/*.cer` copy being absent from the module
zip, which is the Go-shaped version of the incident that motivated that
workflow.

## Badge

There is no registry badge for Go. The convention is
`https://pkg.go.dev/badge/github.com/emindeniz99/apple-purchase-receipt-verifier/go.svg`,
which renders only after the first proxy fetch — so add it after the first
`go/v*` tag, not before.
