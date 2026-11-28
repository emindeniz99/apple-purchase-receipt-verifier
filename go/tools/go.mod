// Test-only tooling, in its own module so nothing here ever enters the
// published module graph. `go build ./...` on the library never sees it,
// and `go list -m all` for a consumer never mentions it.
module github.com/emindeniz99/apple-purchase-receipt-verifier/go/tools

go 1.26.0

require (
	golang.org/x/vuln v1.10.0
	honnef.co/go/tools v0.8.2
)

require (
	github.com/BurntSushi/toml v1.6.0 // indirect
	golang.org/x/exp/typeparams v0.0.0-20260908205506-85c1c2202aba // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/telemetry v0.0.0-20261116191925-e77a43154acb // indirect
	golang.org/x/tools v0.53.0 // indirect
)
