// Smoke-tests the module as published to proxy.golang.org, imported by module
// path from a directory that is not the repository. Run it after a `go get` of
// the published version:
//
//	mkdir "$(mktemp -d)" && cd "$_" && go mod init smoke
//	go get github.com/emindeniz99/apple-purchase-receipt-verifier/go@v0.7.0
//	cp <repo>/.github/smoke/go-smoke/main.go <repo>/fixtures/public-receipts/receipt-sandbox-g5.b64 .
//	go run .
//
// Apple's three roots are compiled into aprv.wasm, which go:embed carries in
// the module zip, so the defaults name no roots of their own (nil means the
// module's). A module zip that lost aprv.wasm or its hash fails below, on the
// genuine receipt.
//
// This file is deliberately outside go/ so it never becomes part of the
// published module.
package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

func main() {
	raw, err := os.ReadFile("receipt-sandbox-g5.b64")
	if err != nil {
		fail("cannot read the fixture: %v", err)
	}
	receiptB64 := strings.TrimSpace(string(raw))

	config := applereceipt.DefaultConfig()
	if roots := config.Roots(); roots != nil {
		fail("expected the module's built-in roots (nil), got %d configured", len(roots))
	}
	verifier, err := applereceipt.NewVerifier(config)
	if err != nil {
		fail("cannot build the verifier: %v", err)
	}

	// A real Apple-signed receipt against the real pinned root: exercises the
	// embedded module, the chain build and the signature check inside it.
	receipt, err := verifier.VerifyReceipt(receiptB64)
	if err != nil {
		fail("verification failed: %v", err)
	}
	if receipt.ReceiptType == nil || *receipt.ReceiptType != "ProductionSandbox" {
		fail("receiptType was %v, expected ProductionSandbox", deref(receipt.ReceiptType))
	}
	if receipt.BundleID == nil || *receipt.BundleID != "dev.bonzer.weeka.app" {
		fail("bundleId was %v", deref(receipt.BundleID))
	}

	// And the negative direction, so a verifier that accepted everything would
	// fail here too: the same receipt with one bit flipped in its signature,
	// the byte 128 from the end of the DER (BENCHMARKS.md).
	der, err := base64.StdEncoding.DecodeString(receiptB64)
	if err != nil {
		fail("cannot decode the fixture: %v", err)
	}
	der[len(der)-128] ^= 0x01
	if _, err := verifier.VerifyReceipt(base64.StdEncoding.EncodeToString(der)); err == nil {
		fail("a tampered signature was not rejected")
	} else if reason, ok := applereceipt.ReasonOf(err); !ok || reason != applereceipt.ReasonInvalidSignature {
		fail("rejected for %v, expected INVALID_SIGNATURE", err)
	}

	fmt.Printf("go: published module verified a genuine Apple receipt (%s, %d purchases)"+
		" and rejected a tampered signature\n", *receipt.BundleID, len(receipt.InApp))
}

func deref(s *string) any {
	if s == nil {
		return nil
	}
	return fmt.Sprintf("%q", *s)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
