package applereceipt_test

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

func jwsVerifierFor(t *testing.T, roots []*x509.Certificate, mutate func(*applereceipt.JWSVerifierOptions)) *applereceipt.JWSVerifier {
	t.Helper()
	options := applereceipt.JWSVerifierOptions{
		TrustedRoots: roots,
		BundleID:     "com.example.app",
		AcceptedEnvironments: []applereceipt.Environment{
			applereceipt.EnvironmentSandbox, applereceipt.EnvironmentProduction,
		},
	}
	if mutate != nil {
		mutate(&options)
	}
	verifier, err := applereceipt.NewJWSVerifier(options)
	if err != nil {
		t.Fatalf("NewJWSVerifier: %v", err)
	}
	return verifier
}

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

func TestSynthesizedTransactionVerifies(t *testing.T) {
	pki := newJWSPKI(t)
	payload, err := jwsVerifierFor(t, []*x509.Certificate{pki.root.cert}, nil).
		VerifyTransaction(pki.sign(t, transactionClaims()))
	if err != nil {
		t.Fatalf("a well-formed synthesized transaction must verify: %v", err)
	}
	if payload.BundleID != "com.example.app" || payload.ProductID != "com.example.app.pro" {
		t.Fatalf("decoded claims are wrong: %+v", payload)
	}
	if payload.Quantity == nil || *payload.Quantity != 1 {
		t.Fatalf("quantity: %v", payload.Quantity)
	}
	// The escape hatch must carry every claim, modelled or not.
	if payload.Claims["productId"] != "com.example.app.pro" {
		t.Fatalf("Claims must carry the raw payload: %v", payload.Claims)
	}
}

func TestJWSShapeRejections(t *testing.T) {
	pki := newJWSPKI(t)
	verifier := jwsVerifierFor(t, []*x509.Certificate{pki.root.cert}, nil)
	good := pki.sign(t, transactionClaims())
	parts := strings.Split(good, ".")

	longSegment := strings.Repeat("A", 2<<20)

	tests := []struct {
		name  string
		input string
		want  applereceipt.Reason
	}{
		{"empty string", "", applereceipt.ReasonInvalidJWSFormat},
		{"one segment", parts[0], applereceipt.ReasonInvalidJWSFormat},
		{"two segments", parts[0] + "." + parts[1], applereceipt.ReasonInvalidJWSFormat},
		{"four segments", good + ".extra", applereceipt.ReasonInvalidJWSFormat},
		{"header is not JSON", "bm90anNvbg." + parts[1] + "." + parts[2], applereceipt.ReasonInvalidJWSFormat},
		{
			"header is a JSON array",
			base64.RawURLEncoding.EncodeToString([]byte(`[1,2]`)) + "." + parts[1] + "." + parts[2],
			applereceipt.ReasonInvalidJWSFormat,
		},
		{
			"payload is a JSON array",
			parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`["a"]`)) + "." + parts[2],
			applereceipt.ReasonInvalidJWSFormat,
		},
		{
			"payload is not JSON",
			parts[0] + ".bm90anNvbg." + parts[2],
			applereceipt.ReasonInvalidJWSFormat,
		},
		{
			"a segment far above the input bound",
			longSegment + "." + longSegment + "." + longSegment,
			applereceipt.ReasonInvalidJWSFormat,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			_, err := verifier.VerifyTransaction(test.input)
			requireReason(t, err, test.want)
		})
	}
}

func TestJWSHeaderRejections(t *testing.T) {
	pki := newJWSPKI(t)
	verifier := jwsVerifierFor(t, []*x509.Certificate{pki.root.cert}, nil)
	good := pki.sign(t, transactionClaims())
	parts := strings.Split(good, ".")
	chain := []string{
		base64.StdEncoding.EncodeToString(pki.leaf.der),
		base64.StdEncoding.EncodeToString(pki.intermediate.der),
		base64.StdEncoding.EncodeToString(pki.root.der),
	}

	headers := []struct {
		name   string
		header map[string]any
		want   applereceipt.Reason
	}{
		{"alg none", map[string]any{"alg": "none", "x5c": chain}, applereceipt.ReasonInvalidJWSFormat},
		{"alg RS256", map[string]any{"alg": "RS256", "x5c": chain}, applereceipt.ReasonInvalidJWSFormat},
		{"alg ES384", map[string]any{"alg": "ES384", "x5c": chain}, applereceipt.ReasonInvalidJWSFormat},
		{"alg missing", map[string]any{"x5c": chain}, applereceipt.ReasonInvalidJWSFormat},
		{"alg is not a string", map[string]any{"alg": 256, "x5c": chain}, applereceipt.ReasonInvalidJWSFormat},
		{"x5c missing", map[string]any{"alg": "ES256"}, applereceipt.ReasonInvalidJWSFormat},
		{"x5c is not an array", map[string]any{"alg": "ES256", "x5c": chain[0]}, applereceipt.ReasonInvalidJWSFormat},
		{"x5c of length 2", map[string]any{"alg": "ES256", "x5c": chain[:2]}, applereceipt.ReasonInvalidJWSFormat},
		{
			"x5c of length 4",
			map[string]any{"alg": "ES256", "x5c": append(append([]string{}, chain...), chain[0])},
			applereceipt.ReasonInvalidJWSFormat,
		},
		{
			"x5c entry is not a string",
			map[string]any{"alg": "ES256", "x5c": []any{1, 2, 3}},
			applereceipt.ReasonInvalidJWSFormat,
		},
		{
			"x5c entry is base64 of garbage",
			map[string]any{"alg": "ES256", "x5c": []string{
				base64.StdEncoding.EncodeToString([]byte("not a certificate")), chain[1], chain[2],
			}},
			applereceipt.ReasonInvalidCertificate,
		},
		{
			"x5c entry is not base64 at all",
			map[string]any{"alg": "ES256", "x5c": []string{"!!!!", chain[1], chain[2]}},
			applereceipt.ReasonInvalidCertificate,
		},
		{
			// A two-hundred-entry x5c is rejected on the length check,
			// before a single certificate is decoded.
			"x5c of length 200",
			map[string]any{"alg": "ES256", "x5c": repeatStrings(chain[0], 200)},
			applereceipt.ReasonInvalidJWSFormat,
		},
	}
	for _, test := range headers {
		test := test
		t.Run(test.name, func(t *testing.T) {
			header := jsonSegment(t, test.header)
			_, err := verifier.VerifyTransaction(header + "." + parts[1] + "." + parts[2])
			requireReason(t, err, test.want)
		})
	}
}

func repeatStrings(value string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = value
	}
	return out
}

func TestJWSSignatureRejections(t *testing.T) {
	pki := newJWSPKI(t)
	verifier := jwsVerifierFor(t, []*x509.Certificate{pki.root.cert}, nil)
	good := pki.sign(t, transactionClaims())
	parts := strings.Split(good, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}

	t.Run("tampered payload", func(t *testing.T) {
		tampered := jsonSegment(t, map[string]any{
			"bundleId": "com.example.app", "environment": "Sandbox", "productId": "evil",
		})
		_, err := verifier.VerifyTransaction(parts[0] + "." + tampered + "." + parts[2])
		requireReason(t, err, applereceipt.ReasonInvalidSignature)
	})
	t.Run("tampered signature", func(t *testing.T) {
		flipped := append([]byte(nil), signature...)
		flipped[0] ^= 0xff
		_, err := verifier.VerifyTransaction(
			parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(flipped))
		requireReason(t, err, applereceipt.ReasonInvalidSignature)
	})
	t.Run("63-byte signature", func(t *testing.T) {
		_, err := verifier.VerifyTransaction(
			parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature[:63]))
		requireReason(t, err, applereceipt.ReasonInvalidSignature)
	})
	t.Run("65-byte signature", func(t *testing.T) {
		_, err := verifier.VerifyTransaction(
			parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(append(signature, 0)))
		requireReason(t, err, applereceipt.ReasonInvalidSignature)
	})
	t.Run("all-zero signature (r = s = 0)", func(t *testing.T) {
		_, err := verifier.VerifyTransaction(
			parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)))
		requireReason(t, err, applereceipt.ReasonInvalidSignature)
	})
	t.Run("empty signature segment", func(t *testing.T) {
		_, err := verifier.VerifyTransaction(parts[0] + "." + parts[1] + ".")
		requireReason(t, err, applereceipt.ReasonInvalidSignature)
	})
}

func TestJWSMarkerOIDsAreCheckedBeforeTheChain(t *testing.T) {
	// A leaf with no marker OID must report INVALID_CERTIFICATE_PURPOSE
	// even when the chain is otherwise perfect — and, more importantly,
	// even when the chain is NOT (the roots here anchor nothing), because
	// on the JWS path the OID check runs first.
	root := issueCert(t, certSpec{commonName: "Root", isCA: true}, nil)
	intermediate := issueCert(t, certSpec{
		commonName: "WWDR", isCA: true, markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR},
	}, root)
	unmarkedLeaf := issueCert(t, certSpec{commonName: "Unmarked leaf"}, intermediate)
	other := newJWSPKI(t)

	jws := signJWS(t, unmarkedLeaf,
		[][]byte{unmarkedLeaf.der, intermediate.der, root.der}, transactionClaims())
	_, err := jwsVerifierFor(t, []*x509.Certificate{other.root.cert}, nil).VerifyTransaction(jws)
	requireReason(t, err, applereceipt.ReasonInvalidCertificatePurpose)
}

func TestJWSIntermediateNeedsTheWWDRMarker(t *testing.T) {
	root := issueCert(t, certSpec{commonName: "Root", isCA: true}, nil)
	intermediate := issueCert(t, certSpec{commonName: "Unmarked WWDR", isCA: true}, root)
	leaf := issueCert(t, certSpec{
		commonName: "Leaf", markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
	}, intermediate)
	jws := signJWS(t, leaf, [][]byte{leaf.der, intermediate.der, root.der}, transactionClaims())
	_, err := jwsVerifierFor(t, []*x509.Certificate{root.cert}, nil).VerifyTransaction(jws)
	requireReason(t, err, applereceipt.ReasonInvalidCertificatePurpose)
}

// x5c[2] is never trusted and never compared: swapping it must change
// nothing at all.
func TestThirdX5CEntryIsIgnored(t *testing.T) {
	pki := newJWSPKI(t)
	attacker := newJWSPKI(t)
	verifier := jwsVerifierFor(t, []*x509.Certificate{pki.root.cert}, nil)

	swapped := signJWS(t, pki.leaf,
		[][]byte{pki.leaf.der, pki.intermediate.der, attacker.root.der}, transactionClaims())
	if _, err := verifier.VerifyTransaction(swapped); err != nil {
		t.Fatalf("x5c[2] is not a trust anchor; swapping it must change nothing: %v", err)
	}
	garbage := signJWS(t, pki.leaf,
		[][]byte{pki.leaf.der, pki.intermediate.der, []byte("not a certificate")}, transactionClaims())
	if _, err := verifier.VerifyTransaction(garbage); err != nil {
		t.Fatalf("x5c[2] is never parsed; garbage there must change nothing: %v", err)
	}
}

func TestClaimChecksRunInTheDocumentedOrder(t *testing.T) {
	pki := newJWSPKI(t)
	roots := []*x509.Certificate{pki.root.cert}

	t.Run("bundle id is checked before environment", func(t *testing.T) {
		// Both claims are wrong; the bundle id must be the one reported.
		claims := transactionClaims()
		claims["bundleId"] = "com.other.app"
		claims["environment"] = "Xcode"
		verifier := jwsVerifierFor(t, roots, func(o *applereceipt.JWSVerifierOptions) {
			o.AcceptedEnvironments = []applereceipt.Environment{applereceipt.EnvironmentSandbox}
		})
		_, err := verifier.VerifyTransaction(pki.sign(t, claims))
		requireReason(t, err, applereceipt.ReasonWrongBundleID)
	})
	t.Run("staleness is checked before the bundle id", func(t *testing.T) {
		claims := transactionClaims()
		claims["bundleId"] = "com.other.app"
		claims["signedDate"] = time.Now().Add(-time.Hour).UnixMilli()
		verifier := jwsVerifierFor(t, roots, func(o *applereceipt.JWSVerifierOptions) {
			o.MaxSignedAge = time.Minute
		})
		_, err := verifier.VerifyTransaction(pki.sign(t, claims))
		requireReason(t, err, applereceipt.ReasonStalePayload)
	})
	t.Run("an unknown environment is rejected", func(t *testing.T) {
		claims := transactionClaims()
		claims["environment"] = "Martian"
		_, err := jwsVerifierFor(t, roots, nil).VerifyTransaction(pki.sign(t, claims))
		requireReason(t, err, applereceipt.ReasonWrongEnvironment)
	})
	t.Run("a missing environment claim is rejected", func(t *testing.T) {
		claims := transactionClaims()
		delete(claims, "environment")
		_, err := jwsVerifierFor(t, roots, nil).VerifyTransaction(pki.sign(t, claims))
		requireReason(t, err, applereceipt.ReasonWrongEnvironment)
	})
}

func TestAppTransactionAppleIDBinding(t *testing.T) {
	pki := newJWSPKI(t)
	roots := []*x509.Certificate{pki.root.cert}
	appAppleID := int64(123456789)

	production := map[string]any{
		"bundleId": "com.example.app", "receiptType": "Production",
		"appAppleId": appAppleID, "applicationVersion": "1.2.3",
	}

	t.Run("production without a configured app Apple id", func(t *testing.T) {
		verifier := jwsVerifierFor(t, roots, func(o *applereceipt.JWSVerifierOptions) {
			o.AcceptedEnvironments = []applereceipt.Environment{applereceipt.EnvironmentProduction}
		})
		_, err := verifier.VerifyAppTransaction(pki.sign(t, production))
		requireReason(t, err, applereceipt.ReasonWrongAppAppleID)
	})
	t.Run("production with a mismatched app Apple id", func(t *testing.T) {
		other := int64(999)
		verifier := jwsVerifierFor(t, roots, func(o *applereceipt.JWSVerifierOptions) {
			o.AcceptedEnvironments = []applereceipt.Environment{applereceipt.EnvironmentProduction}
			o.AppAppleID = &other
		})
		_, err := verifier.VerifyAppTransaction(pki.sign(t, production))
		requireReason(t, err, applereceipt.ReasonWrongAppAppleID)
	})
	t.Run("production whose payload omits the claim", func(t *testing.T) {
		claims := map[string]any{
			"bundleId": "com.example.app", "receiptType": "Production",
		}
		verifier := jwsVerifierFor(t, roots, func(o *applereceipt.JWSVerifierOptions) {
			o.AcceptedEnvironments = []applereceipt.Environment{applereceipt.EnvironmentProduction}
			o.AppAppleID = &appAppleID
		})
		_, err := verifier.VerifyAppTransaction(pki.sign(t, claims))
		requireReason(t, err, applereceipt.ReasonWrongAppAppleID)
	})
	t.Run("sandbox needs no app Apple id", func(t *testing.T) {
		claims := map[string]any{"bundleId": "com.example.app", "receiptType": "Sandbox"}
		verifier := jwsVerifierFor(t, roots, func(o *applereceipt.JWSVerifierOptions) {
			o.AcceptedEnvironments = []applereceipt.Environment{applereceipt.EnvironmentSandbox}
		})
		if _, err := verifier.VerifyAppTransaction(pki.sign(t, claims)); err != nil {
			t.Fatalf("the app Apple id binding is a Production rule only: %v", err)
		}
	})
}

func TestVerifyRawEnforcesNoClaims(t *testing.T) {
	pki := newJWSPKI(t)
	verifier := jwsVerifierFor(t, []*x509.Certificate{pki.root.cert}, func(o *applereceipt.JWSVerifierOptions) {
		o.BundleID = "com.nothing.matches.this"
		o.AcceptedEnvironments = []applereceipt.Environment{applereceipt.EnvironmentLocalTesting}
	})
	claims, err := verifier.VerifyRaw(pki.sign(t, map[string]any{
		"notificationType": "TEST", "bundleId": "com.example.app", "environment": "Sandbox",
	}))
	if err != nil {
		t.Fatalf("VerifyRaw enforces no claim: %v", err)
	}
	if claims["notificationType"] != "TEST" {
		t.Fatalf("every claim must come back: %v", claims)
	}
}

// VerifyRaw skips the claim checks but never the signature.
func TestVerifyRawStillChecksTheSignature(t *testing.T) {
	pki := newJWSPKI(t)
	other := newJWSPKI(t)
	verifier := jwsVerifierFor(t, []*x509.Certificate{other.root.cert}, nil)
	_, err := verifier.VerifyRaw(pki.sign(t, transactionClaims()))
	requireReason(t, err, applereceipt.ReasonInvalidChain)
}

// A JSON number is a value, not a spelling. json.Number.Int64 parses the
// literal, so `1722945600000.0` and `1.7229456e12` were refused while the
// bare integer was accepted -- and refusing them was not a rejection but a
// silence: signedDate read as absent moved certificate validity onto the
// current-time fallback, and expiresDate read as absent left a lapsed
// subscription entitled forever. php/tests/JsonNumberClaimTest.php pins the
// same three spellings; node, java, python and swift all read the value.
func TestEverySpellingOfADateClaimIsRead(t *testing.T) {
	pki := newJWSPKI(t)
	const signedAt int64 = 1722945600000 // 2024-08-06T12:00:00Z
	for _, spelling := range []string{"1722945600000", "1722945600000.0", "1.7229456e12"} {
		claims := transactionClaims()
		claims["signedDate"] = json.Number(spelling)
		claims["expiresDate"] = json.Number(spelling)
		verifier := jwsVerifierFor(t, []*x509.Certificate{pki.root.cert}, nil)
		payload, err := verifier.VerifyTransaction(pki.sign(t, claims))
		if err != nil {
			t.Fatalf("signedDate spelled %s: %v", spelling, err)
		}
		if payload.SignedDate == nil || *payload.SignedDate != signedAt {
			t.Fatalf("signedDate spelled %s read as %v", spelling, payload.SignedDate)
		}
		if payload.ExpiresDate == nil || *payload.ExpiresDate != signedAt {
			t.Fatalf("expiresDate spelled %s read as %v", spelling, payload.ExpiresDate)
		}
		if payload.IsActiveAt(time.UnixMilli(signedAt + 1)) {
			t.Fatalf("expiresDate spelled %s left the subscription entitled", spelling)
		}
	}
}

// The other half: a number that names no instant an int64 can hold is not a
// date whatever its spelling, and it is a chain failure rather than a silence
// -- reporting it absent would let an attacker choose the instant the
// certificate windows are judged at.
func TestADateClaimOutsideTheInt64RangeIsAChainFailure(t *testing.T) {
	pki := newJWSPKI(t)
	for _, spelling := range []string{"1e300", "-1e300", "123456789012345678901234567890"} {
		claims := transactionClaims()
		claims["signedDate"] = json.Number(spelling)
		verifier := jwsVerifierFor(t, []*x509.Certificate{pki.root.cert}, nil)
		_, err := verifier.VerifyTransaction(pki.sign(t, claims))
		requireReason(t, err, applereceipt.ReasonInvalidChain)
	}
}

func TestStalenessBoundaries(t *testing.T) {
	pki := newJWSPKI(t)
	// Inside the synthesized chain's validity window, so the only thing
	// moving in this test is the staleness rule.
	signedAt := time.Now().UTC().Truncate(time.Second)
	claims := transactionClaims()
	claims["signedDate"] = signedAt.UnixMilli()
	jws := pki.sign(t, claims)

	at := func(offset time.Duration) *applereceipt.JWSVerifier {
		return jwsVerifierFor(t, []*x509.Certificate{pki.root.cert}, func(o *applereceipt.JWSVerifierOptions) {
			o.MaxSignedAge = time.Minute
			o.Now = func() time.Time { return signedAt.Add(offset) }
		})
	}
	if _, err := at(time.Minute).VerifyTransaction(jws); err != nil {
		t.Fatalf("exactly at the maximum age must be accepted: %v", err)
	}
	_, err := at(time.Minute + time.Second).VerifyTransaction(jws)
	requireReason(t, err, applereceipt.ReasonStalePayload)
	if _, err := at(-time.Hour).VerifyTransaction(jws); err != nil {
		t.Fatalf("a payload signed after the clock is not stale: %v", err)
	}
	// MaxSignedAge unset disables the rule entirely.
	never := jwsVerifierFor(t, []*x509.Certificate{pki.root.cert}, func(o *applereceipt.JWSVerifierOptions) {
		o.Now = func() time.Time { return signedAt.Add(100 * 365 * 24 * time.Hour) }
	})
	if _, err := never.VerifyTransaction(jws); err != nil {
		t.Fatalf("MaxSignedAge zero disables the staleness rule: %v", err)
	}
}

// The injected clock must not be able to move a certificate-validity
// verdict, in either direction. This is the security property behind
// "ReceiptVerifier takes no clock" and behind the JWS fallback reading
// the system clock.
func TestInjectedClockCannotMoveCertificateValidity(t *testing.T) {
	past := time.Now().Add(-10 * 365 * 24 * time.Hour)
	root := issueCert(t, certSpec{
		commonName: "Expired Root", isCA: true,
		notBefore: past, notAfter: past.Add(24 * time.Hour),
	}, nil)
	intermediate := issueCert(t, certSpec{
		commonName: "Expired WWDR", isCA: true, markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR},
		notBefore: past, notAfter: past.Add(24 * time.Hour),
	}, root)
	leaf := issueCert(t, certSpec{
		commonName: "Expired Leaf", markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
		notBefore: past, notAfter: past.Add(24 * time.Hour),
	}, intermediate)

	// No signedDate, so the validity instant falls back — and the
	// fallback must be the system clock, not this deliberately helpful
	// injected one.
	claims := map[string]any{"bundleId": "com.example.app", "environment": "Sandbox"}
	jws := signJWS(t, leaf, [][]byte{leaf.der, intermediate.der, root.der}, claims)

	verifier := jwsVerifierFor(t, []*x509.Certificate{root.cert}, func(o *applereceipt.JWSVerifierOptions) {
		o.Now = func() time.Time { return past.Add(time.Hour) }
	})
	_, err := verifier.VerifyTransaction(jws)
	requireReason(t, err, applereceipt.ReasonInvalidChain)
}

func TestHistoricalPayloadUnderAnExpiredChainStillVerifies(t *testing.T) {
	past := time.Now().Add(-10 * 365 * 24 * time.Hour)
	root := issueCert(t, certSpec{
		commonName: "Old Root", isCA: true, notBefore: past, notAfter: past.Add(48 * time.Hour),
	}, nil)
	intermediate := issueCert(t, certSpec{
		commonName: "Old WWDR", isCA: true, markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR},
		notBefore: past, notAfter: past.Add(48 * time.Hour),
	}, root)
	leaf := issueCert(t, certSpec{
		commonName: "Old Leaf", markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
		notBefore: past, notAfter: past.Add(48 * time.Hour),
	}, intermediate)

	claims := transactionClaims()
	claims["signedDate"] = past.Add(time.Hour).UnixMilli()
	jws := signJWS(t, leaf, [][]byte{leaf.der, intermediate.der, root.der}, claims)

	if _, err := jwsVerifierFor(t, []*x509.Certificate{root.cert}, nil).VerifyTransaction(jws); err != nil {
		t.Fatalf("a payload signed while the chain was valid must still verify: %v", err)
	}
}

func TestIsActiveAt(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ms := func(at time.Time) *int64 { v := at.UnixMilli(); return &v }

	tests := []struct {
		name    string
		payload applereceipt.TransactionPayload
		want    bool
	}{
		{"no dates at all", applereceipt.TransactionPayload{}, true},
		{"not yet expired", applereceipt.TransactionPayload{ExpiresDate: ms(now.Add(time.Hour))}, true},
		{"expired", applereceipt.TransactionPayload{ExpiresDate: ms(now.Add(-time.Hour))}, false},
		{"expiring exactly now", applereceipt.TransactionPayload{ExpiresDate: ms(now)}, false},
		{"revoked", applereceipt.TransactionPayload{RevocationDate: ms(now.Add(-time.Hour))}, false},
		{"revoked exactly now", applereceipt.TransactionPayload{RevocationDate: ms(now)}, false},
		{"revocation in the future", applereceipt.TransactionPayload{RevocationDate: ms(now.Add(time.Hour))}, true},
		{
			"revoked beats an unexpired subscription",
			applereceipt.TransactionPayload{
				RevocationDate: ms(now.Add(-time.Hour)), ExpiresDate: ms(now.Add(time.Hour)),
			},
			false,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if got := test.payload.IsActiveAt(now); got != test.want {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
	var nilPayload *applereceipt.TransactionPayload
	if nilPayload.IsActiveAt(now) {
		t.Fatal("a nil payload is not active")
	}
}

// Apple ships date claims as epoch milliseconds and this port keeps them
// that way, contractually: a native date type would lose the raw claim.
func TestJWSDateClaimsStayEpochMilliseconds(t *testing.T) {
	pki := newJWSPKI(t)
	claims := transactionClaims()
	claims["expiresDate"] = int64(1893456000000)
	claims["revocationDate"] = int64(1893456000001)
	payload, err := jwsVerifierFor(t, []*x509.Certificate{pki.root.cert}, nil).
		VerifyTransaction(pki.sign(t, claims))
	if err != nil {
		t.Fatal(err)
	}
	if payload.ExpiresDate == nil || *payload.ExpiresDate != 1893456000000 {
		t.Fatalf("expiresDate: %v", payload.ExpiresDate)
	}
	if payload.RevocationDate == nil || *payload.RevocationDate != 1893456000001 {
		t.Fatalf("revocationDate: %v", payload.RevocationDate)
	}
	// A JSON round-trip keeps them integers too.
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"expiresDate":1893456000000`) {
		t.Fatalf("marshalled payload: %s", encoded)
	}
}

func TestConstructorRejectsMisconfiguration(t *testing.T) {
	pki := newJWSPKI(t)
	roots := []*x509.Certificate{pki.root.cert}

	tests := []struct {
		name    string
		options applereceipt.JWSVerifierOptions
	}{
		{"no trust anchors", applereceipt.JWSVerifierOptions{
			BundleID: "x", AcceptedEnvironments: []applereceipt.Environment{applereceipt.EnvironmentSandbox},
		}},
		{"a nil certificate among the anchors", applereceipt.JWSVerifierOptions{
			TrustedRoots: []*x509.Certificate{nil}, BundleID: "x",
			AcceptedEnvironments: []applereceipt.Environment{applereceipt.EnvironmentSandbox},
		}},
		{"empty bundle id", applereceipt.JWSVerifierOptions{
			TrustedRoots:         roots,
			AcceptedEnvironments: []applereceipt.Environment{applereceipt.EnvironmentSandbox},
		}},
		{"empty accept set", applereceipt.JWSVerifierOptions{
			TrustedRoots: roots, BundleID: "x",
		}},
		{"unknown environment in the accept set", applereceipt.JWSVerifierOptions{
			TrustedRoots: roots, BundleID: "x",
			AcceptedEnvironments: []applereceipt.Environment{"Martian"},
		}},
		{"negative max signed age", applereceipt.JWSVerifierOptions{
			TrustedRoots: roots, BundleID: "x",
			AcceptedEnvironments: []applereceipt.Environment{applereceipt.EnvironmentSandbox},
			MaxSignedAge:         -time.Second,
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			verifier, err := applereceipt.NewJWSVerifier(test.options)
			if err == nil {
				t.Fatal("expected a configuration error")
			}
			if verifier != nil {
				t.Fatal("a failed constructor must not return a verifier")
			}
			// Misconfiguration is a programming bug, not a verdict about
			// a receipt: a caller switching on Reason must never see it.
			if _, ok := applereceipt.ReasonOf(err); ok {
				t.Fatalf("misconfiguration must not carry a Reason: %v", err)
			}
		})
	}
}

// The anchors are copied at construction: mutating the caller's slice
// afterwards must not repoint the verifier's trust.
func TestTrustAnchorsAreCopiedAtConstruction(t *testing.T) {
	pki := newJWSPKI(t)
	attacker := newJWSPKI(t)
	roots := []*x509.Certificate{pki.root.cert}
	verifier := jwsVerifierFor(t, roots, nil)
	roots[0] = attacker.root.cert
	if _, err := verifier.VerifyTransaction(pki.sign(t, transactionClaims())); err != nil {
		t.Fatalf("the verifier must hold its own copy of the anchors: %v", err)
	}
}
