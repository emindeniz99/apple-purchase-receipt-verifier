// Package wasm carries aprv.wasm, the one verification module, and refuses
// to load when its bytes are not the ones aprv.wasm.sha256 names.
//
// The module is a build artifact of the release job, committed here
// because the Go module is published from a git tag and go:embed cannot
// reach outside the module directory. CI rebuilds it and fails when the
// committed copy's SHA-256 differs from the release build's, and the
// check in this package's init means a copy swapped without its hash file
// fails on import instead of running.
package wasm

import (
	"crypto/sha256"
	_ "embed" // for the two go:embed directives below
	"encoding/hex"
	"fmt"
	"strings"
)

// Module is aprv.wasm, the core module of the canonical ABI.
//
//go:embed aprv.wasm
var Module []byte

// sumFile is aprv.wasm.sha256 in sha256sum's format, so
// `sha256sum -c aprv.wasm.sha256` checks the same claim from a shell.
//
//go:embed aprv.wasm.sha256
var sumFile string

func init() {
	if err := Check(Module, sumFile); err != nil {
		panic("applereceipt: " + err.Error())
	}
}

// SHA256 is the module's expected SHA-256, lowercase hex, as
// aprv.wasm.sha256 records it.
func SHA256() string {
	sum, _ := expected(sumFile)
	return sum
}

// Check reports whether module hashes to the SHA-256 that sumFile, a
// `sha256sum` line, records for aprv.wasm.
func Check(module []byte, sumFile string) error {
	want, err := expected(sumFile)
	if err != nil {
		return err
	}
	got := sha256.Sum256(module)
	if hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("the embedded aprv.wasm hashes to %x, aprv.wasm.sha256 records %s",
			got, want)
	}
	return nil
}

// expected reads the one `<64 hex digits>  aprv.wasm` line.
func expected(sumFile string) (string, error) {
	fields := strings.Fields(sumFile)
	if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != "aprv.wasm" {
		return "", fmt.Errorf("aprv.wasm.sha256 is not one `<sha256>  aprv.wasm` line")
	}
	sum := fields[0]
	if _, err := hex.DecodeString(sum); err != nil || len(sum) != 64 || sum != strings.ToLower(sum) {
		return "", fmt.Errorf("aprv.wasm.sha256 does not hold a lowercase SHA-256")
	}
	return sum, nil
}
