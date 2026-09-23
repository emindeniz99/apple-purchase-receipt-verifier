package applereceipt_test

import (
	"runtime"
	"strings"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// The base64 entry points are the untrusted-network surface: the
// endpoint emulates Apple's verifyReceipt host, and VerifyBase64 takes
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
	endpoint, err := applereceipt.NewVerifyReceiptEndpoint(applereceipt.VerifyReceiptEndpointOptions{
		TrustedRoots: applereceipt.AppleReceiptRoots(),
		Environment:  applereceipt.EnvironmentProduction,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := oversizedBase64()
	var response applereceipt.VerifyReceiptResponse
	allocated := allocatedBy(func() {
		response = endpoint.VerifyReceipt(applereceipt.VerifyReceiptRequest{ReceiptData: body}).Response()
	})
	if response.Status != applereceipt.StatusMalformed {
		t.Fatalf("status = %d, want %d", response.Status, applereceipt.StatusMalformed)
	}
	t.Logf("%d base64 chars, ceiling %d: allocated %d bytes", len(body), ceiling, allocated)
	// The answer needs at most the ceiling plus a byte to know the input
	// is over it. Anything near the 48 MiB the body decodes to means the
	// decode ran to completion before the ceiling was consulted.
	if allocated > 4*ceiling {
		t.Errorf("a %d-char body allocated %d bytes against a %d byte ceiling; "+
			"MaxReceiptBytes must bound the decode, not only the parse",
			len(body), allocated, ceiling)
	}
}

func TestVerifyBase64DoesNotDecodeBeyondItsCeiling(t *testing.T) {
	const ceiling = applereceipt.MaxReceiptBytes
	pki := newReceiptPKI(t)
	verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
		TrustedRoots: pki.anchors(),
		BundleID:     "com.example.app",
	})
	if err != nil {
		t.Fatal(err)
	}
	body := oversizedBase64()
	for _, entry := range []struct {
		name string
		call func() error
	}{
		{"VerifyBase64", func() error { _, err := verifier.VerifyBase64(body); return err }},
		{"VerifyBase64WithDeviceGUID", func() error {
			_, err := verifier.VerifyBase64WithDeviceGUID(body, []byte("guid"))
			return err
		}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			var got error
			allocated := allocatedBy(func() { got = entry.call() })
			requireReason(t, got, applereceipt.ReasonInvalidReceiptFormat)
			t.Logf("allocated %d bytes against a %d byte ceiling", allocated, ceiling)
			if allocated > 4*ceiling {
				t.Errorf("a %d-char body allocated %d bytes against a %d byte ceiling",
					len(body), allocated, ceiling)
			}
		})
	}
}
