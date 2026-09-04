//go:build tools

// Package tools pins the linters CI runs, so their versions are lockfile
// material dependabot can bump rather than a floating @latest that can
// change what CI enforces without a commit.
package tools

import (
	_ "golang.org/x/vuln/cmd/govulncheck"
	_ "honnef.co/go/tools/cmd/staticcheck"
)
