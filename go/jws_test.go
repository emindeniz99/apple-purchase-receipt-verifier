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

func jwsHeaderFor(t *testing.T, pki jwsPKI) []byte {
	t.Helper()
	chain := []string{
		base64.StdEncoding.EncodeToString(pki.leaf.der),
		base64.StdEncoding.EncodeToString(pki.intermediate.der),
		base64.StdEncoding.EncodeToString(pki.root.der),
	}
	header, err := json.Marshal(map[string]any{"alg": "ES256", "x5c": chain})
	if err != nil {
		t.Fatal(err)
	}
	return header
}

func TestSynthesizedJWSVerifies(t *testing.T) {
	pki := newJWSPKI(t)
	payload, err := verifierFor(t, pki.anchorSlice()).VerifySignedData(pki.sign(t, transactionClaims()))
	if err != nil {
		t.Fatalf("a well-formed synthesized JWS must verify: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(payload.JSON()), &decoded); err != nil {
		t.Fatalf("payload.JSON() must be the exact signed JSON: %v", err)
	}
	if decoded["bundleId"] != "com.example.app" || decoded["productId"] != "com.example.app.pro" {
		t.Fatalf("decoded claims are wrong: %+v", decoded)
	}
	if payload.String() != payload.JSON() {
		t.Fatal("String() must be JSON()")
	}
}

func TestJWSShapeRejections(t *testing.T) {
	pki := newJWSPKI(t)
	verifier := verifierFor(t, pki.anchorSlice())
	good := pki.sign(t, transactionClaims())
	parts := strings.Split(good, ".")

	longSegment := strings.Repeat("A", 2<<20)

	tests := []struct {
		name  string
		input string
		want  applereceipt.Reason
	}{
		{"empty string", "", applereceipt.ReasonMalformed},
		{"one segment", parts[0], applereceipt.ReasonMalformed},
		{"two segments", parts[0] + "." + parts[1], applereceipt.ReasonMalformed},
		{"four segments", good + ".extra", applereceipt.ReasonMalformed},
		{"header is not canonical base64url", "!!!." + parts[1] + "." + parts[2], applereceipt.ReasonMalformed},
		{"header is not JSON", "bm90anNvbg." + parts[1] + "." + parts[2], applereceipt.ReasonMalformed},
		{
			"header is a JSON array",
			base64.RawURLEncoding.EncodeToString([]byte(`[1,2]`)) + "." + parts[1] + "." + parts[2],
			applereceipt.ReasonMalformed,
		},
		{
			"a segment far above the input bound",
			longSegment + "." + longSegment + "." + longSegment,
			applereceipt.ReasonTooLarge,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			_, err := verifier.VerifySignedData(test.input)
			requireReason(t, err, test.want)
		})
	}
}

func TestJWSHeaderRejections(t *testing.T) {
	pki := newJWSPKI(t)
	verifier := verifierFor(t, pki.anchorSlice())
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
		{"alg none", map[string]any{"alg": "none", "x5c": chain}, applereceipt.ReasonMalformed},
		{"alg RS256", map[string]any{"alg": "RS256", "x5c": chain}, applereceipt.ReasonMalformed},
		{"alg ES384", map[string]any{"alg": "ES384", "x5c": chain}, applereceipt.ReasonMalformed},
		{"alg missing", map[string]any{"x5c": chain}, applereceipt.ReasonMalformed},
		{"alg is not a string", map[string]any{"alg": 256, "x5c": chain}, applereceipt.ReasonMalformed},
		{"x5c missing", map[string]any{"alg": "ES256"}, applereceipt.ReasonMalformed},
		{"x5c is not an array", map[string]any{"alg": "ES256", "x5c": chain[0]}, applereceipt.ReasonMalformed},
		{"x5c of length 2", map[string]any{"alg": "ES256", "x5c": chain[:2]}, applereceipt.ReasonMalformed},
		{
			"x5c of length 4",
			map[string]any{"alg": "ES256", "x5c": append(append([]string{}, chain...), chain[0])},
			applereceipt.ReasonMalformed,
		},
		{
			"x5c entry is not a string",
			map[string]any{"alg": "ES256", "x5c": []any{1, 2, 3}},
			applereceipt.ReasonMalformed,
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
			applereceipt.ReasonMalformed,
		},
	}
	for _, test := range headers {
		test := test
		t.Run(test.name, func(t *testing.T) {
			header := jsonSegment(t, test.header)
			_, err := verifier.VerifySignedData(header + "." + parts[1] + "." + parts[2])
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
	verifier := verifierFor(t, pki.anchorSlice())
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
		_, err := verifier.VerifySignedData(parts[0] + "." + tampered + "." + parts[2])
		requireReason(t, err, applereceipt.ReasonInvalidSignature)
	})
	t.Run("tampered signature", func(t *testing.T) {
		flipped := append([]byte(nil), signature...)
		flipped[0] ^= 0xff
		_, err := verifier.VerifySignedData(
			parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(flipped))
		requireReason(t, err, applereceipt.ReasonInvalidSignature)
	})
	t.Run("63-byte signature", func(t *testing.T) {
		_, err := verifier.VerifySignedData(
			parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature[:63]))
		requireReason(t, err, applereceipt.ReasonInvalidSignature)
	})
	t.Run("65-byte signature", func(t *testing.T) {
		_, err := verifier.VerifySignedData(
			parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(append(signature, 0)))
		requireReason(t, err, applereceipt.ReasonInvalidSignature)
	})
	t.Run("all-zero signature (r = s = 0)", func(t *testing.T) {
		_, err := verifier.VerifySignedData(
			parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)))
		requireReason(t, err, applereceipt.ReasonInvalidSignature)
	})
	t.Run("empty signature segment", func(t *testing.T) {
		_, err := verifier.VerifySignedData(parts[0] + "." + parts[1] + ".")
		requireReason(t, err, applereceipt.ReasonInvalidSignature)
	})
}

// Once the signature is genuinely valid and the chain genuinely reaches a
// pinned root, an unparseable or non-object payload is UNREADABLE_PAYLOAD,
// not a shape rejection: Apple's signature already vouches for the bytes.
func TestPayloadNotAnObjectIsUnreadableOnceSignatureVerifies(t *testing.T) {
	pki := newJWSPKI(t)
	verifier := verifierFor(t, pki.anchorSlice())
	header := jwsHeaderFor(t, pki)

	tests := []struct {
		name    string
		payload string
	}{
		{"a JSON array", `[1,2,3]`},
		{"not JSON at all", `not json`},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			jws := signRawJWS(t, pki.leaf, header, []byte(test.payload))
			_, err := verifier.VerifySignedData(jws)
			requireReason(t, err, applereceipt.ReasonUnreadablePayload)
		})
	}
}

// The chain is checked before the marker OIDs on both paths (owner,
// 2026-09-27): a chain that does not reach a pinned root is
// UNTRUSTED_CHAIN even when the leaf is also unmarked, and only once the
// chain is trusted does an unmarked leaf report
// INVALID_CERTIFICATE_PURPOSE.
func TestJWSMarkerOIDsAreCheckedAfterTheChain(t *testing.T) {
	t.Run("untrusted chain reports UNTRUSTED_CHAIN, not the marker", func(t *testing.T) {
		root := issueCert(t, certSpec{commonName: "Root", isCA: true}, nil)
		intermediate := issueCert(t, certSpec{
			commonName: "WWDR", isCA: true, markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR},
		}, root)
		unmarkedLeaf := issueCert(t, certSpec{commonName: "Unmarked leaf"}, intermediate)
		other := newJWSPKI(t)

		jws := signJWS(t, unmarkedLeaf,
			[][]byte{unmarkedLeaf.der, intermediate.der, root.der}, transactionClaims())
		_, err := verifierFor(t, other.anchorSlice()).VerifySignedData(jws)
		requireReason(t, err, applereceipt.ReasonUntrustedChain)
	})
	t.Run("trusted chain with an unmarked leaf reports the marker", func(t *testing.T) {
		root := issueCert(t, certSpec{commonName: "Root", isCA: true}, nil)
		intermediate := issueCert(t, certSpec{
			commonName: "WWDR", isCA: true, markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR},
		}, root)
		unmarkedLeaf := issueCert(t, certSpec{commonName: "Unmarked leaf"}, intermediate)

		jws := signJWS(t, unmarkedLeaf,
			[][]byte{unmarkedLeaf.der, intermediate.der, root.der}, transactionClaims())
		_, err := verifierFor(t, []*x509.Certificate{root.cert}).VerifySignedData(jws)
		requireReason(t, err, applereceipt.ReasonInvalidCertificatePurpose)
	})
}

func TestJWSIntermediateNeedsTheWWDRMarker(t *testing.T) {
	root := issueCert(t, certSpec{commonName: "Root", isCA: true}, nil)
	intermediate := issueCert(t, certSpec{commonName: "Unmarked WWDR", isCA: true}, root)
	leaf := issueCert(t, certSpec{
		commonName: "Leaf", markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
	}, intermediate)
	jws := signJWS(t, leaf, [][]byte{leaf.der, intermediate.der, root.der}, transactionClaims())
	_, err := verifierFor(t, []*x509.Certificate{root.cert}).VerifySignedData(jws)
	requireReason(t, err, applereceipt.ReasonInvalidCertificatePurpose)
}

// x5c[2] is never trusted and never compared, so swapping in a stranger's
// root must change nothing — but it must still BE a certificate. The two
// halves are the whole of what the third entry means: identity irrelevant,
// readability required.
func TestThirdX5CEntryIsUntrustedButMustParse(t *testing.T) {
	pki := newJWSPKI(t)
	attacker := newJWSPKI(t)
	verifier := verifierFor(t, pki.anchorSlice())

	swapped := signJWS(t, pki.leaf,
		[][]byte{pki.leaf.der, pki.intermediate.der, attacker.root.der}, transactionClaims())
	if _, err := verifier.VerifySignedData(swapped); err != nil {
		t.Fatalf("x5c[2] is not a trust anchor; swapping it must change nothing: %v", err)
	}
	garbage := signJWS(t, pki.leaf,
		[][]byte{pki.leaf.der, pki.intermediate.der, []byte("not a certificate")}, transactionClaims())
	_, err := verifier.VerifySignedData(garbage)
	requireReason(t, err, applereceipt.ReasonInvalidCertificate)
}

// A JSON number is a value, not a spelling: signedDate steers which
// instant the chain is judged valid at, so all three spellings must be
// read the same way. php/tests/JsonNumberClaimTest.php pins the same
// three spellings; every port reads the value.
func TestEverySpellingOfASignedDateIsRead(t *testing.T) {
	const signedAt int64 = 1722945600000 // 2024-08-06T12:00:00Z
	past := time.UnixMilli(signedAt).Add(-time.Hour)
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
	verifier := verifierFor(t, []*x509.Certificate{root.cert})

	for _, spelling := range []string{"1722945600000", "1722945600000.0", "1.7229456e12"} {
		payload := []byte(`{"bundleId":"com.example.app","signedDate":` + spelling + `}`)
		header, err := json.Marshal(map[string]any{
			"alg": "ES256",
			"x5c": []string{
				base64.StdEncoding.EncodeToString(leaf.der),
				base64.StdEncoding.EncodeToString(intermediate.der),
				base64.StdEncoding.EncodeToString(root.der),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		jws := signRawJWS(t, leaf, header, payload)
		if _, err := verifier.VerifySignedData(jws); err != nil {
			t.Fatalf("signedDate spelled %s: the chain is only valid at that instant: %v", spelling, err)
		}
	}
}

// A signedDate no int64 can hold (1e300) counts as not stated, the same
// treatment absence gets: the clock stands in for it (owner, 2026-09-27),
// rather than failing the chain outright. The chain here is valid now and
// would still be, whatever a representable signedDate said; the point is
// only that an unrepresentable one does not itself cause a failure.
func TestUnrepresentableSignedDateFallsBackToTheClock(t *testing.T) {
	pki := newJWSPKI(t)
	verifier := verifierFor(t, pki.anchorSlice())
	for _, spelling := range []string{"1e300", "-1e300", "123456789012345678901234567890"} {
		claims := transactionClaims()
		claims["signedDate"] = json.Number(spelling)
		if _, err := verifier.VerifySignedData(pki.sign(t, claims)); err != nil {
			t.Fatalf("signedDate spelled %s must fall back to the clock, not fail: %v", spelling, err)
		}
	}
}

// The contrasting case: a signedDate that IS representable is used
// literally, even when it names an instant outside the chain's validity
// window and the clock ("now") would have let the chain through.
func TestSignedDateOutsideTheChainWindowIsAChainFailure(t *testing.T) {
	now := time.Now()
	root := issueCert(t, certSpec{
		commonName: "Root", isCA: true, notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	}, nil)
	intermediate := issueCert(t, certSpec{
		commonName: "WWDR", isCA: true, markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR},
		notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	}, root)
	leaf := issueCert(t, certSpec{
		commonName: "Leaf", markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
		notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	}, intermediate)

	claims := map[string]any{
		"bundleId": "com.example.app", "environment": "Sandbox",
		"signedDate": now.Add(-100 * 365 * 24 * time.Hour).UnixMilli(),
	}
	jws := signJWS(t, leaf, [][]byte{leaf.der, intermediate.der, root.der}, claims)
	_, err := verifierFor(t, []*x509.Certificate{root.cert}).VerifySignedData(jws)
	requireReason(t, err, applereceipt.ReasonInvalidCertificate)
}

// A payload stating no date of its own is judged at the system clock, so
// a chain that has since expired is INVALID_CERTIFICATE.
func TestDatelessPayloadIsJudgedAtTheSystemClock(t *testing.T) {
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

	// No signedDate, so the validity instant falls back to the system
	// clock, where this chain has expired.
	claims := map[string]any{"bundleId": "com.example.app", "environment": "Sandbox"}
	jws := signJWS(t, leaf, [][]byte{leaf.der, intermediate.der, root.der}, claims)

	_, err := verifierFor(t, []*x509.Certificate{root.cert}).VerifySignedData(jws)
	requireReason(t, err, applereceipt.ReasonInvalidCertificate)
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

	if _, err := verifierFor(t, []*x509.Certificate{root.cert}).VerifySignedData(jws); err != nil {
		t.Fatalf("a payload signed while the chain was valid must still verify: %v", err)
	}
}

// The payload is returned exactly as signed: large integers and their
// exact digits survive, because there is no typed model reading them
// through a float on the way out.
func TestPayloadJSONIsPassedThroughVerbatim(t *testing.T) {
	pki := newJWSPKI(t)
	claims := transactionClaims()
	claims["transactionId"] = "2000000000000001"
	claims["webOrderLineItemId"] = json.Number("9223372036854775807")
	payload, err := verifierFor(t, pki.anchorSlice()).VerifySignedData(pki.sign(t, claims))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.JSON(), `"webOrderLineItemId":9223372036854775807`) {
		t.Fatalf("exact digits were not preserved: %s", payload.JSON())
	}
}

// The anchors are copied at construction: mutating the caller's slice
// afterwards must not repoint the verifier's trust.
func TestTrustAnchorsAreCopiedAtConstruction(t *testing.T) {
	pki := newJWSPKI(t)
	attacker := newJWSPKI(t)
	roots := []*x509.Certificate{pki.root.cert}
	verifier := verifierFor(t, roots)
	roots[0] = attacker.root.cert
	if _, err := verifier.VerifySignedData(pki.sign(t, transactionClaims())); err != nil {
		t.Fatalf("the verifier must hold its own copy of the anchors: %v", err)
	}
}
