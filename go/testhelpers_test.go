package applereceipt_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// applereceiptBase64 is standard padded base64, the form every receipt
// string entry point takes.
func applereceiptBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Shared conveniences for every _test.go file in this package: a single
// fixture's bytes by id, read from the same fixtures/cases-0.7.json the
// conformance suite runs, and the two assertions almost every hand-written
// test makes: the Reason a call failed with, and a substring of its
// message.

var (
	sharedCasesOnce sync.Once
	sharedCasesDir  string
	sharedCasesFile casesDocument
)

func sharedCases(t testing.TB) (string, casesDocument) {
	t.Helper()
	sharedCasesOnce.Do(func() {
		sharedCasesDir, sharedCasesFile = loadCases(t)
	})
	return sharedCasesDir, sharedCasesFile
}

// fixtureBytes is the decoded logical bytes of one registered fixture,
// checked against its recorded digest.
func fixtureBytes(t testing.TB, id string) []byte {
	t.Helper()
	dir, file := sharedCases(t)
	return fixtureBytesIn(t, dir, file.Fixtures, id)
}

// fixtureString is the string a fixture hands to VerifyReceipt: a text
// fixture verbatim, or DER encoded as canonical base64.
func fixtureString(t testing.TB, id string) string {
	t.Helper()
	dir, file := sharedCases(t)
	return receiptString(t, dir, file.Fixtures, id)
}

// signRawJWS signs already-encoded header and payload bytes with leaf's
// key, so a test can put bytes on the wire that signJWS's
// json.Marshal(map[string]any) could never produce (a non-object payload,
// an extra header member, a byte-exact size) while still producing a
// signature verifyES256 genuinely accepts.
func signRawJWS(t testing.TB, leaf *testCert, header, payload []byte) string {
	t.Helper()
	headerB64 := base64.RawURLEncoding.EncodeToString(header)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	key, ok := leaf.key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("signRawJWS needs an ECDSA leaf key")
	}
	digest := sha256.Sum256([]byte(headerB64 + "." + payloadB64))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return headerB64 + "." + payloadB64 + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// transactionClaims is a well-formed synthesized JWS payload, the default
// input every JWS test builds on unless it needs to vary a specific claim.
func transactionClaims() map[string]any {
	return map[string]any{
		"bundleId":      "com.example.app",
		"environment":   "Sandbox",
		"productId":     "com.example.app.pro",
		"transactionId": "2000000000000001",
		"quantity":      1,
		"signedDate":    time.Now().UnixMilli(),
	}
}

// requireReason asserts that err is a *applereceipt.Failure with Reason
// want.
func requireReason(t testing.TB, err error, want applereceipt.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected reason %s, got a nil error", want)
	}
	var failure *applereceipt.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("expected reason %s, got a non-Failure error %T: %v", want, err, err)
	}
	if failure.Reason != want {
		t.Fatalf("expected reason %s, got %s: %v", want, failure.Reason, err)
	}
}

// parseFixtureCertificate reads a raw-DER trust-anchor fixture as a
// certificate.
func parseFixtureCertificate(t testing.TB, id string) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(fixtureBytes(t, id))
	if err != nil {
		t.Fatalf("fixture %q does not parse as a certificate: %v", id, err)
	}
	return cert
}

// verifierFor is a Verifier trusting only roots, no other config.
func verifierFor(t testing.TB, roots []*x509.Certificate) *applereceipt.Verifier {
	t.Helper()
	verifier, err := applereceipt.NewVerifier(applereceipt.NewConfig(applereceipt.ConfigOptions{Roots: roots}))
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

// nestedSequences is depth ASN.1 SEQUENCEs wrapped around one INTEGER, a
// nesting bomb for the depth-bounded reader.
func nestedSequences(depth int) []byte {
	out := derInt(1)
	for i := 0; i < depth; i++ {
		out = derSequence(out)
	}
	return out
}

// requireMessage asserts that err is a *applereceipt.Failure whose
// message contains want.
func requireMessage(t testing.TB, err error, want string) {
	t.Helper()
	var failure *applereceipt.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("not a *Failure: %v", err)
	}
	if !strings.Contains(failure.Message, want) {
		t.Fatalf("message %q does not contain %q", failure.Message, want)
	}
}
