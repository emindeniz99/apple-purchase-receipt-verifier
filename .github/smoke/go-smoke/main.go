// Smoke-tests the module as published to proxy.golang.org, imported by module
// path from a directory that is not the repository. Run it after a `go get` of
// the published version:
//
//	mkdir "$(mktemp -d)" && cd "$_" && go mod init smoke
//	go get github.com/emindeniz99/apple-purchase-receipt-verifier/go@v0.4.0
//	cp <repo>/.github/smoke/go-smoke/main.go <repo>/fixtures/public-receipts/receipt-sandbox-g5.b64 .
//	go run .
//
// go:embed cannot reach outside a module, so go/roots/certs is a generated copy
// of the repo-root certs/. If that copy ever falls out of the module zip the
// library compiles and then has no trust anchors at all — the Go-shaped version
// of the two empty npm releases. AppleReceiptRoots() below is what catches it.
//
// This file is deliberately outside go/ so it never becomes part of the
// published module.
package main

import (
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

	roots := applereceipt.AppleReceiptRoots()
	if len(roots) != 3 {
		fail("expected three embedded Apple roots, got %d", len(roots))
	}

	// A real Apple-signed receipt against the real pinned root: exercises the
	// embedded certs, the DER reader, the chain build and the signature check.
	verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
		TrustedRoots: roots,
		BundleID:     "dev.bonzer.weeka.app",
	})
	if err != nil {
		fail("cannot build the verifier: %v", err)
	}
	receipt, err := verifier.VerifyBase64(receiptB64)
	if err != nil {
		fail("verification failed: %v", err)
	}
	if receipt.ReceiptType != "ProductionSandbox" {
		fail("receiptType was %q, expected ProductionSandbox", receipt.ReceiptType)
	}
	if receipt.BundleID != "dev.bonzer.weeka.app" {
		fail("bundleId was %q", receipt.BundleID)
	}

	// And the negative direction, so a verifier that accepted everything would
	// fail here too.
	other, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
		TrustedRoots: roots,
		BundleID:     "com.other.app",
	})
	if err != nil {
		fail("cannot build the second verifier: %v", err)
	}
	if _, err := other.VerifyBase64(receiptB64); err == nil {
		fail("a receipt for another bundle id was not rejected")
	} else if reason, ok := applereceipt.ReasonOf(err); !ok || reason != applereceipt.ReasonWrongBundleID {
		fail("rejected for %v, expected WRONG_BUNDLE_ID", reason)
	}

	fmt.Printf("go: published module verified a genuine Apple receipt (%s, %d purchases)"+
		" and rejected a foreign bundle id\n", receipt.BundleID, len(receipt.InAppPurchases))
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
