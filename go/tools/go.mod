// Test-only tooling, in its own module so nothing here ever enters the
// published module graph. `go build ./...` on the library never sees it,
// and `go list -m all` for a consumer never mentions it.
module github.com/emindeniz99/apple-purchase-receipt-verifier/go/tools

go 1.26.0

require (
	golang.org/x/vuln v1.8.0
	honnef.co/go/tools v0.8.1
)

require (
	github.com/BurntSushi/toml v1.6.0 // indirect
	golang.org/x/exp/typeparams v0.0.0-20260908205506-85c1c2202aba // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/telemetry v0.0.0-20260921160320-bdcd072333a6 // indirect
	golang.org/x/tools v0.50.0 // indirect
)
