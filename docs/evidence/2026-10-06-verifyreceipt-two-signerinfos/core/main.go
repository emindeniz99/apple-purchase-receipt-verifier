// Prints the Rust core's answer (through the Go package and its pinned
// aprv.wasm) for every .b64 file in a directory. Usage: go run . <dir>
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

func main() {
	v, err := applereceipt.NewVerifier(applereceipt.NewConfig(applereceipt.ConfigOptions{}))
	if err != nil {
		panic(err)
	}
	files, _ := filepath.Glob(filepath.Join(os.Args[1], "*.b64"))
	sort.Strings(files)
	for _, f := range files {
		b, _ := os.ReadFile(f)
		answer := "ok"
		if _, err := v.VerifyReceipt(strings.TrimSpace(string(b))); err != nil {
			reason, _ := applereceipt.ReasonOf(err)
			answer = string(reason)
		}
		fmt.Printf("%s\t%s\n", strings.TrimSuffix(filepath.Base(f), ".b64"), answer)
	}
}
