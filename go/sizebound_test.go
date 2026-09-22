package applereceipt_test

import (
	"encoding/base64"
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
// The bound asserted is on allocation relative to the configured
// ceiling, not to the input, because the whole point is that the input
// length must stop mattering.

const oversizedBase64Chars = 64 << 20 // 64 MiB of base64 => ~48 MiB decoded

func oversizedBase64() string { return strings.Repeat("QUFB", oversizedBase64Chars/4) }

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func allocatedBy(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestEndpointDoesNotDecodeBeyondItsCeiling(t *testing.T) {
	const ceiling = 1 << 20
	endpoint, err := applereceipt.NewVerifyReceiptEndpoint(applereceipt.VerifyReceiptEndpointOptions{
		TrustedRoots:    applereceipt.AppleReceiptRoots(),
		Environment:     applereceipt.EnvironmentProduction,
		MaxReceiptBytes: ceiling,
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
	const ceiling = 1 << 20
	pki := newReceiptPKI(t)
	verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
		TrustedRoots:    pki.anchors(),
		BundleID:        "com.example.app",
		MaxReceiptBytes: ceiling,
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

// The ceiling is exact on both forms: on the DER it counts bytes, on the
// base64 string it counts the string as sent. Both forms must give the
// same reason at the boundary.
func TestCeilingIsExactAtTheBoundary(t *testing.T) {
	pki := newReceiptPKI(t)
	receipt := pki.receipt(t)
	encoded := base64Std(receipt)
	verifierWith := func(t *testing.T, ceiling int) *applereceipt.ReceiptVerifier {
		verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
			TrustedRoots:    pki.anchors(),
			BundleID:        "com.example.app",
			MaxReceiptBytes: ceiling,
		})
		if err != nil {
			t.Fatal(err)
		}
		return verifier
	}
	for _, entry := range []struct {
		name   string
		offset int
		accept bool
	}{
		{"exactly at the ceiling", 0, true},
		{"one byte of room to spare", 1, true},
		{"one byte short", -1, false},
	} {
		t.Run(entry.name, func(t *testing.T) {
			_, derErr := verifierWith(t, len(receipt)+entry.offset).Verify(receipt)
			_, b64Err := verifierWith(t, len(encoded)+entry.offset).VerifyBase64(encoded)
			if entry.accept {
				if derErr != nil || b64Err != nil {
					t.Fatalf("offset %d rejected the receipt: der=%v base64=%v", entry.offset, derErr, b64Err)
				}
				return
			}
			requireReason(t, derErr, applereceipt.ReasonInvalidReceiptFormat)
			requireReason(t, b64Err, applereceipt.ReasonInvalidReceiptFormat)
			if !strings.Contains(derErr.Error(), "exceeds") || !strings.Contains(b64Err.Error(), "exceeds") {
				t.Errorf("the ceiling, not a parse failure, must refuse:\n der = %v\n b64 = %v", derErr, b64Err)
			}
		})
	}
}

// The string cap counts the string as sent, whitespace included, as the
// Java, PHP and Python ports do: the decoder walks every character it
// skips, so whitespace is work too, and a cap that ignored it would let a
// string of spaces of any length through to the decoder.
func TestStringCeilingCountsWhitespace(t *testing.T) {
	pki := newReceiptPKI(t)
	receipt := pki.receipt(t)
	var wrapped strings.Builder
	encoded := base64Std(receipt)
	for i := 0; i < len(encoded); i += 64 {
		end := i + 64
		if end > len(encoded) {
			end = len(encoded)
		}
		wrapped.WriteString(encoded[i:end])
		wrapped.WriteString("\n")
	}
	for _, entry := range []struct {
		ceiling int
		accept  bool
	}{
		{wrapped.Len(), true},
		{wrapped.Len() - 1, false},
	} {
		verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
			TrustedRoots:    pki.anchors(),
			BundleID:        "com.example.app",
			MaxReceiptBytes: entry.ceiling,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = verifier.VerifyBase64(wrapped.String())
		if entry.accept {
			if err != nil {
				t.Fatalf("a line-wrapped receipt at exactly the ceiling was rejected: %v", err)
			}
			continue
		}
		requireReason(t, err, applereceipt.ReasonInvalidReceiptFormat)
	}
}
