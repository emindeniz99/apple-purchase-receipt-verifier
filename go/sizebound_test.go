package applereceipt_test

import (
	"runtime"
	"strings"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// The base64 entry points are the untrusted-network surface: the
// endpoint emulates Apple's verifyReceipt host, and VerifyReceipt takes
// the string a client sends. MaxReceiptBytes is documented as rejecting
// larger inputs BEFORE decoding and BEFORE parsing: it caps the base64
// string's length as well as the DER, so it bounds the decode too, not
// just the parse that follows it. Decoding first and measuring afterwards
// means the ceiling never limits the work the attacker buys.
//
// The bound asserted is on allocation relative to the fixed ceiling, not
// to the input, because the whole point is that the input length must
// stop mattering. The exact boundary of each form is pinned in
// inputcaps_test.go.

const oversizedBase64Chars = 64 << 20 // 64 MiB of base64 => ~48 MiB decoded

func oversizedBase64() string { return strings.Repeat("QUFB", oversizedBase64Chars/4) }

func allocatedBy(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestEndpointDoesNotDecodeBeyondItsCeiling(t *testing.T) {
	const ceiling = applereceipt.MaxReceiptBytes
	verifier := verifierFor(t, applereceipt.AppleRoots())
	body := oversizedBase64()
	request := `{"receipt-data":"` + body + `"}`
	var response string
	allocated := allocatedBy(func() {
		response = verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentProduction, request)
	})
	if !strings.HasPrefix(response, `{"status":21002`) {
		t.Fatalf("response = %.80s, want a 21002 status", response)
	}
	t.Logf("%d base64 chars, ceiling %d: allocated %d bytes", len(body), ceiling, allocated)
	// The answer needs at most the ceiling plus a byte to know the input
	// is over it. Anything near the 48 MiB the body decodes to means the
	// decode ran to completion before the ceiling was consulted, or the
	// request-body cap ran before the receipt-data cap could.
	if allocated > 4*ceiling {
		t.Errorf("a %d-char body allocated %d bytes against a %d byte ceiling; "+
			"MaxReceiptBytes must bound the decode, not only the parse",
			len(body), allocated, ceiling)
	}
}

func TestVerifyReceiptDoesNotDecodeBeyondItsCeiling(t *testing.T) {
	const ceiling = applereceipt.MaxReceiptBytes
	pki := newReceiptPKI(t)
	verifier := verifierFor(t, pki.anchors())
	body := oversizedBase64()
	var got error
	allocated := allocatedBy(func() { _, got = verifier.VerifyReceipt(body) })
	requireReason(t, got, applereceipt.ReasonTooLarge)
	t.Logf("allocated %d bytes against a %d byte ceiling", allocated, ceiling)
	if allocated > 4*ceiling {
		t.Errorf("a %d-char body allocated %d bytes against a %d byte ceiling",
			len(body), allocated, ceiling)
	}
}
