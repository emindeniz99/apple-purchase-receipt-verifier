package applereceipt_test

import (
	"runtime"
	"strings"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// indefiniteOctetString wraps payload in `levels` indefinite-length
// constructed OCTET STRING headers. Each level costs four bytes of input
// and is legal BER, which is why genuine Apple receipts use the form at
// all.
func indefiniteOctetString(payload []byte, levels int) []byte {
	out := payload
	for i := 0; i < levels; i++ {
		wrapped := make([]byte, 0, len(out)+4)
		wrapped = append(wrapped, 0x24, 0x80)
		wrapped = append(wrapped, out...)
		wrapped = append(wrapped, 0x00, 0x00)
		out = wrapped
	}
	return out
}

// hostileNestedReceipt is the shape a DoS-amplification attack takes: a
// structurally valid CMS whose payload is legal but nested as deeply as
// the reader allows, at four bytes per level. Everything about it is
// unauthenticated — no signature, no chain — and every byte of the parse
// happens before the certificate count, the chain walk and the signature
// check, because the creation date has to come out of the payload first.
func hostileNestedReceipt(t *testing.T, pki receiptPKI, attributes, attributeBytes, outerLevels, innerLevels int) []byte {
	t.Helper()
	body := strings.Repeat("A", attributeBytes)
	parts := make([][]byte, 0, attributes)
	for i := 0; i < attributes; i++ {
		value := indefiniteOctetString(derOctetString([]byte(body)), innerLevels)
		parts = append(parts, derSequence(derInt(9000+int64(i%50)), derInt(1), value))
	}
	payload := derSet(concat(parts...))

	encap := derSequence(derOID(oidPKCS7Data), derContext0(indefiniteOctetString(derOctetString(payload), outerLevels)))
	signerInfo := derSequence(
		derInt(1),
		derSequence(pki.leaf.cert.RawIssuer, derInteger(pki.leaf.cert.SerialNumber)),
		algorithmIdentifier(oidSHA256),
		algorithmIdentifier(oidRSA),
		derOctetString([]byte{1, 2, 3, 4}),
	)
	signedData := derSequence(
		derInt(1),
		derSet(algorithmIdentifier(oidSHA256)),
		encap,
		derContext0(concat(pki.embedded()...)),
		derSet(signerInfo),
	)
	return derSequence(derOID(oidPKCS7Sign), derContext0(signedData))
}

// TestNestedReceiptDoesNotAmplify pins the claim the package makes about
// its own cost: rejecting a hostile receipt must not cost dramatically
// more than accepting a genuine one. Nesting is the lever — it is free
// for the attacker (four bytes a level) and, with a per-level copy in the
// reader, multiplies the defender's work by the depth.
//
// Measured as a ratio to the input, so the assertion does not depend on
// the machine.
func TestNestedReceiptDoesNotAmplify(t *testing.T) {
	pki := newReceiptPKI(t)
	roots := pki.anchors()

	// The eContent nesting and the per-attribute nesting are separate
	// budgets: each is re-parsed from depth zero, and together they must
	// stay under the reader's MaxDepth of 32 or the blob is rejected on
	// depth alone and never reaches the amplifying path at all.
	for _, levels := range [][2]int{{1, 1}, {6, 12}, {12, 24}} {
		outer, inner := levels[0], levels[1]
		blob := hostileNestedReceipt(t, pki, 1200, 700, outer, inner)
		if len(blob) > applereceipt.DefaultMaxReceiptBytes {
			t.Fatalf("levels=%v: fixture is %d bytes, above the library's own ceiling", levels, len(blob))
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		started := time.Now()
		_, err := applereceipt.VerifyReceiptCore(blob, roots)
		elapsed := time.Since(started)
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Fatalf("levels=%v: an unsigned blob was accepted", levels)
		}
		if reasonString(err) != string(applereceipt.ReasonInvalidSignature) {
			t.Fatalf("levels=%v: blob was rejected as %s (%v) before the payload was walked; "+
				"the test is not measuring the path it claims to", levels, reasonString(err), err)
		}
		allocated := after.TotalAlloc - before.TotalAlloc
		ratio := float64(allocated) / float64(len(blob))
		t.Logf("outer=%2d inner=%2d input=%d allocated=%d ratio=%.1fx elapsed=%v reason=%v",
			outer, inner, len(blob), allocated, ratio, elapsed, reasonString(err))
		if ratio > 12 {
			t.Errorf("levels=%v: rejecting a %d byte receipt allocated %d bytes (%.1fx); "+
				"nesting depth must not multiply the cost of a rejection",
				levels, len(blob), allocated, ratio)
		}
	}
}

func reasonString(err error) string {
	if reason, ok := applereceipt.ReasonOf(err); ok {
		return string(reason)
	}
	return "not-a-VerificationError"
}
