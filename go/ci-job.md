# CI jobs for the Go port — all implemented

Every job this file used to describe (`go`, `go-platforms`, `go-race`,
`go-fuzz`, `go-lint`, `go-generate-check`) is implemented in
`.github/workflows/ci.yml`, and the `/go` and `/go/tools` dependabot entries
are implemented in `.github/dependabot.yml`. The last one outstanding, the
post-publish smoke leg, is now the `go` job in
`.github/workflows/post-publish-smoke.yml` with its program at
`.github/smoke/go-smoke/main.go`; [`RELEASE.md`](./RELEASE.md) says what it
asserts and why.

Nothing here is outstanding, so this file can be deleted whenever someone is
touching the Go port's docs anyway.
