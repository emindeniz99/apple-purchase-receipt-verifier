package applereceipt_test

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// endpointVerifierFor is a Verifier trusting only roots, with a fixed
// clock when now is non-nil (the system clock otherwise).
func endpointVerifierFor(t *testing.T, roots []*x509.Certificate, now func() int64) *applereceipt.Verifier {
	t.Helper()
	options := applereceipt.ConfigOptions{Roots: roots}
	if now != nil {
		options.Clock = now
	}
	verifier, err := applereceipt.NewVerifier(applereceipt.NewConfig(options))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return verifier
}

func decodeEndpointResponse(t *testing.T, response string) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(response), &decoded); err != nil {
		t.Fatalf("the endpoint must always answer JSON, got %q: %v", response, err)
	}
	return decoded
}

func endpointStatus(t *testing.T, response string) int {
	t.Helper()
	decoded := decodeEndpointResponse(t, response)
	status, ok := decoded["status"].(float64)
	if !ok {
		t.Fatalf("no numeric status in %s", response)
	}
	return int(status)
}

func TestEndpointMalformedBodies(t *testing.T) {
	pki := newReceiptPKI(t)
	endpoint := endpointVerifierFor(t, pki.anchors(), nil)

	t.Run("empty receipt-data", func(t *testing.T) {
		if got := endpointStatus(t, endpoint.VerifyReceiptEndpoint(
			applereceipt.EnvironmentSandbox, `{"receipt-data":""}`)); got != applereceipt.StatusMalformedReceiptData {
			t.Fatalf("status: got %d", got)
		}
	})
	t.Run("receipt-data that is not a receipt", func(t *testing.T) {
		request := `{"receipt-data":"` + base64.StdEncoding.EncodeToString([]byte("nope")) + `"}`
		if got := endpointStatus(t, endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request)); got != applereceipt.StatusMalformedReceiptData {
			t.Fatalf("status: got %d", got)
		}
	})

	jsonBodies := []struct {
		name string
		body string
		want int
	}{
		{"not JSON at all", "}{", applereceipt.StatusMalformedReceiptData},
		{"a JSON array", `[1,2,3]`, applereceipt.StatusMalformedReceiptData},
		{"JSON null", `null`, applereceipt.StatusMalformedReceiptData},
		{"a JSON string", `"receipt"`, applereceipt.StatusMalformedReceiptData},
		{"a JSON number", `42`, applereceipt.StatusMalformedReceiptData},
		{"an object with no receipt-data", `{}`, applereceipt.StatusMalformedReceiptData},
		{"receipt-data is null", `{"receipt-data":null}`, applereceipt.StatusMalformedReceiptData},
		{"receipt-data is a number", `{"receipt-data":123}`, applereceipt.StatusMalformedReceiptData},
		{"receipt-data is an object", `{"receipt-data":{"a":1}}`, applereceipt.StatusMalformedReceiptData},
		{"receipt-data is empty", `{"receipt-data":""}`, applereceipt.StatusMalformedReceiptData},
		{"empty body", ``, applereceipt.StatusMalformedReceiptData},
	}
	for _, test := range jsonBodies {
		test := test
		t.Run(test.name, func(t *testing.T) {
			out := endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, test.body)
			if got := endpointStatus(t, out); got != test.want {
				t.Fatalf("status: got %d, want %d (%s)", got, test.want, out)
			}
		})
	}
}

func TestEndpointAcceptsAndIgnoresTheCompatibilityFields(t *testing.T) {
	pki := newReceiptPKI(t)
	endpoint := endpointVerifierFor(t, pki.anchors(), nil)
	body, err := json.Marshal(map[string]any{
		"receipt-data":             applereceiptBase64(pki.receipt(t)),
		"password":                 "a shared secret that cannot be checked locally",
		"exclude-old-transactions": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := endpointStatus(t, endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, string(body))); got != applereceipt.StatusOK {
		t.Fatalf("password and exclude-old-transactions are accepted and ignored, got %d", got)
	}
}

// status 0 must be present in the wire body: an omitted field would
// produce a body no verifyReceipt client can read.
func TestSuccessBodyCarriesAnExplicitZeroStatus(t *testing.T) {
	pki := newReceiptPKI(t)
	endpoint := endpointVerifierFor(t, pki.anchors(), nil)
	request := `{"receipt-data":"` + applereceiptBase64(pki.receipt(t)) + `"}`
	out := endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request)
	if !strings.Contains(out, `"status":0`) {
		t.Fatalf(`the success body must carry "status":0, got %s`, out)
	}
}

func TestEndpointJSONIsDeterministic(t *testing.T) {
	pki := newReceiptPKI(t)
	at := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	endpoint := endpointVerifierFor(t, pki.anchors(), func() int64 { return at })
	request := `{"receipt-data":"` + applereceiptBase64(pki.receipt(t)) + `"}`
	first := endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request)
	for i := 0; i < 20; i++ {
		if got := endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request); got != first {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, got)
		}
	}
}

func TestRequestDateComesFromTheInjectedClock(t *testing.T) {
	pki := newReceiptPKI(t)
	at := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	endpoint := endpointVerifierFor(t, pki.anchors(), func() int64 { return at })
	request := `{"receipt-data":"` + applereceiptBase64(pki.receipt(t)) + `"}`
	response := endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request)
	decoded := decodeEndpointResponse(t, response)
	if decoded["status"] != float64(applereceipt.StatusOK) {
		t.Fatalf("status: %v", decoded["status"])
	}
	receipt, ok := decoded["receipt"].(map[string]any)
	if !ok {
		t.Fatalf("no receipt object in %s", response)
	}
	want := map[string]string{
		"request_date":     "2025-01-01 00:00:00 Etc/GMT",
		"request_date_ms":  "1735689600000",
		"request_date_pst": "2024-12-31 16:00:00 America/Los_Angeles",
	}
	for key, value := range want {
		if got := receipt[key]; got != value {
			t.Errorf("%s: got %v, want %q", key, got, value)
		}
	}
}

// A receipt with no creation date falls back to the configured clock for
// its validity instant (the same clock request_date is rendered from,
// since the 0.7 API has a single Config.Clock rather than a separate
// per-request "now"): a clock outside the chain's validity window must
// not authenticate it.
func TestEndpointClockCannotAuthenticateAnExpiredChain(t *testing.T) {
	past := time.Now().Add(-10 * 365 * 24 * time.Hour)
	root := issueCert(t, certSpec{
		commonName: "Expired Receipt Root", isCA: true, rsa: true,
		notBefore: past, notAfter: past.Add(48 * time.Hour),
	}, nil)
	intermediate := issueCert(t, certSpec{
		commonName: "Expired Receipt WWDR", isCA: true, rsa: true,
		markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR},
		notBefore:  past, notAfter: past.Add(48 * time.Hour),
	}, root)
	leaf := issueCert(t, certSpec{
		commonName: "Expired Receipt Signer", rsa: true,
		markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
		notBefore:  past, notAfter: past.Add(48 * time.Hour),
	}, intermediate)
	// A receipt with no creation date, so the validity instant falls back
	// to the configured clock.
	der := buildCMS(t, cmsSpec{
		content:         receiptPayload(attr(2, derUTF8String("com.example.app"))),
		signer:          leaf,
		certificates:    [][]byte{leaf.der, intermediate.der},
		withSignedAttrs: true,
	})
	// A clock long after the chain's validity window closed.
	endpoint := endpointVerifierFor(t, []*x509.Certificate{root.cert}, func() int64 { return past.Add(100 * time.Hour).UnixMilli() })
	request := `{"receipt-data":"` + applereceiptBase64(der) + `"}`
	if got := endpointStatus(t, endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request)); got != applereceipt.StatusNotAuthenticated {
		t.Fatalf("a clock outside the chain's validity window must not authenticate it, got %d", got)
	}
}

func TestEndpointEnvironmentRouting(t *testing.T) {
	pki := newReceiptPKI(t)
	// Every receipt_type the routing rule has an opinion about, plus the
	// missing-attribute case, in both environments. The rule fails
	// closed: only "Production" and "ProductionVPP" are production.
	tests := []struct {
		receiptType  string
		onProduction int
		onSandbox    int
	}{
		{"Production", applereceipt.StatusOK, applereceipt.StatusProductionReceiptOnSandbox},
		{"ProductionVPP", applereceipt.StatusOK, applereceipt.StatusProductionReceiptOnSandbox},
		{"ProductionSandbox", applereceipt.StatusSandboxReceiptOnProduction, applereceipt.StatusOK},
		{"ProductionVPPSandbox", applereceipt.StatusSandboxReceiptOnProduction, applereceipt.StatusOK},
		{"Xcode", applereceipt.StatusSandboxReceiptOnProduction, applereceipt.StatusOK},
		{"", applereceipt.StatusSandboxReceiptOnProduction, applereceipt.StatusOK},
	}
	for _, test := range tests {
		test := test
		name := test.receiptType
		if name == "" {
			name = "no receipt_type attribute"
		}
		t.Run(name, func(t *testing.T) {
			attributes := []([]byte){attr(2, derUTF8String("com.example.app"))}
			if test.receiptType != "" {
				attributes = append(attributes, attr(0, derUTF8String(test.receiptType)))
			}
			attributes = append(attributes,
				attr(12, derIA5String(time.Now().UTC().Format(time.RFC3339))))
			der := pki.receipt(t, attributes...)
			request := `{"receipt-data":"` + applereceiptBase64(der) + `"}`

			production := endpointVerifierFor(t, pki.anchors(), nil).
				VerifyReceiptEndpoint(applereceipt.EnvironmentProduction, request)
			if got := endpointStatus(t, production); got != test.onProduction {
				t.Errorf("on Production: got %d, want %d", got, test.onProduction)
			}
			sandbox := endpointVerifierFor(t, pki.anchors(), nil).
				VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request)
			if got := endpointStatus(t, sandbox); got != test.onSandbox {
				t.Errorf("on Sandbox: got %d, want %d", got, test.onSandbox)
			}
			// A routed answer carries no receipt and no environment: it is
			// a redirect, not a verdict about the contents.
			if decoded := decodeEndpointResponse(t, production); decoded["status"] != float64(applereceipt.StatusOK) {
				if _, has := decoded["receipt"]; has {
					t.Error("a 21007/21008 answer must carry no receipt")
				}
				if _, has := decoded["environment"]; has {
					t.Error("a 21007/21008 answer must carry no environment")
				}
			}
		})
	}
}

func TestEndpointStatusesForFailedVerification(t *testing.T) {
	pki := newReceiptPKI(t)
	other := newReceiptPKI(t)
	endpoint := endpointVerifierFor(t, other.anchors(), nil)

	t.Run("a foreign chain is 21003", func(t *testing.T) {
		request := `{"receipt-data":"` + applereceiptBase64(pki.receipt(t)) + `"}`
		if got := endpointStatus(t, endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request)); got != applereceipt.StatusNotAuthenticated {
			t.Fatalf("got %d", got)
		}
	})
	t.Run("a malformed receipt is 21002", func(t *testing.T) {
		request := `{"receipt-data":"` + applereceiptBase64(derSequence(derInt(1))) + `"}`
		if got := endpointStatus(t, endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request)); got != applereceipt.StatusMalformedReceiptData {
			t.Fatalf("got %d", got)
		}
	})
}

// The endpoint does not check the bundle id, exactly like Apple's: the
// caller compares receipt.bundle_id itself.
func TestEndpointDoesNotCheckTheBundleID(t *testing.T) {
	pki := newReceiptPKI(t)
	request := `{"receipt-data":"` + applereceiptBase64(pki.receipt(t)) + `"}`
	response := endpointVerifierFor(t, pki.anchors(), nil).
		VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request)
	decoded := decodeEndpointResponse(t, response)
	if decoded["status"] != float64(applereceipt.StatusOK) {
		t.Fatalf("status: %v", decoded["status"])
	}
	receipt := decoded["receipt"].(map[string]any)
	if receipt["bundle_id"] != "com.example.app" {
		t.Fatalf("bundle_id: %v", receipt["bundle_id"])
	}
}

func TestEndpointNeverPanicsOverTheHostileCorpus(t *testing.T) {
	pki := newReceiptPKI(t)
	// A frozen clock, so the only thing that can make two bodies differ is
	// the receipt they describe.
	at := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	endpoint := endpointVerifierFor(t, pki.anchors(), func() int64 { return at })
	good := pki.receipt(t)
	genuineRequest := `{"receipt-data":"` + applereceiptBase64(good) + `"}`
	genuine := endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, genuineRequest)
	if got := endpointStatus(t, genuine); got != applereceipt.StatusOK {
		t.Fatalf("the unmutated receipt must verify: %d", got)
	}

	corpus := [][]byte{
		nil, {}, []byte("not a receipt"), derSequence(derInt(1)),
		good[:len(good)/2], append(append([]byte{}, good...), 0xff),
		nestedSequences(200),
	}
	for i := range good {
		mutated := append([]byte{}, good...)
		mutated[i] ^= 0xff
		corpus = append(corpus, mutated)
	}
	for i, input := range corpus {
		request := `{"receipt-data":"` + applereceiptBase64(input) + `"}`
		response := endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request)
		status := endpointStatus(t, response)
		// 21009 means something escaped that was not a *Failure.
		if status == applereceipt.StatusInternalDataAccessError {
			t.Fatalf("corpus entry %d produced 21009: something unexpected escaped", i)
		}
		if status != applereceipt.StatusOK {
			continue
		}
		// A mutation is allowed to leave the answer unchanged — the CMS
		// signatureAlgorithm identifier, for instance, is deliberately
		// never consulted (see TestSignatureAlgorithmIdentifierIsNotConsulted).
		// What it may never do is change what the receipt says.
		if response != genuine {
			t.Fatalf("corpus entry %d verified with a DIFFERENT body:\n%s\n%s", i, genuine, response)
		}
	}
}

// A recorded, deliberate property, shared with the Node port: the
// SignerInfo's signatureAlgorithm OID, when it names no specific combined
// scheme this package recognises (Change 3, receiptalgorithm.go's "bare
// key-type OID" fallback), does not itself decide the verdict. The hash
// comes from digestAlgorithm and the scheme from the certificate's own key
// type, both enforced; the identifier is a claim about the signature that
// the signature does not cover, so believing it beyond "is this a
// syntactically valid OID" would be worse than ignoring it. Renaming it to
// a different, unrecognised-but-well-formed OID of the same encoded
// length therefore changes no verdict, which is exactly why the mutation
// suites assert "the answer never changes" rather than "every mutation is
// rejected".
func TestSignatureAlgorithmIdentifierIsNotConsulted(t *testing.T) {
	pki := newReceiptPKI(t)
	good := pki.receipt(t)
	// The rsaEncryption OID inside the SignerInfo, i.e. the last
	// occurrence of its encoding in the blob.
	needle := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}
	at := lastIndex(good, needle)
	if at < 0 {
		t.Fatal("could not locate the SignerInfo signatureAlgorithm OID")
	}
	mutated := append([]byte(nil), good...)
	// Flip a low bit of the OID's last byte, not the high (continuation)
	// bit: 1.2.840.113549.1.1.1 (rsaEncryption) becomes
	// 1.2.840.113549.1.1.3 (md4WithRSAEncryption), a different,
	// well-formed, still-unrecognised-as-a-named-scheme OID. Flipping the
	// high bit instead would corrupt the OID's own BER encoding (it turns
	// a terminal arc byte into a continuation byte with nothing to
	// continue), which is a MALFORMED SignerInfo, a different property
	// than the one this test pins.
	mutated[at+len(needle)-1] ^= 0x02
	if _, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(mutated)); err != nil {
		t.Fatalf("the signatureAlgorithm identifier is not consulted, so this must still verify: %v", err)
	}
}

func lastIndex(haystack, needle []byte) int {
	for i := len(haystack) - len(needle); i >= 0; i-- {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func TestAppleDateTripleShape(t *testing.T) {
	pki := newReceiptPKI(t)
	creation := time.Date(2024, 8, 6, 12, 0, 0, 0, time.UTC)
	der := pki.receipt(t,
		attr(0, derUTF8String("ProductionSandbox")),
		attr(2, derUTF8String("com.example.app")),
		attr(12, derIA5String(creation.Format(time.RFC3339))),
		attr(17, receiptPayload(
			attr(1702, derUTF8String("com.example.app.vip")),
			attr(1701, derInt(2)),
			attr(1711, derInt(42)),
			attr(1719, derInt(1)),
			attr(1708, derIA5String("2030-02-01T09:30:00Z")),
		)),
	)
	request := `{"receipt-data":"` + applereceiptBase64(der) + `"}`
	response := endpointVerifierFor(t, pki.anchors(), nil).
		VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request)
	decoded := decodeEndpointResponse(t, response)
	if decoded["status"] != float64(applereceipt.StatusOK) {
		t.Fatalf("status: %v", decoded["status"])
	}
	receipt := decoded["receipt"].(map[string]any)
	want := map[string]any{
		"receipt_creation_date":     "2024-08-06 12:00:00 Etc/GMT",
		"receipt_creation_date_ms":  "1722945600000",
		"receipt_creation_date_pst": "2024-08-06 05:00:00 America/Los_Angeles",
	}
	for key, value := range want {
		if got := receipt[key]; got != value {
			t.Errorf("%s: got %v, want %v", key, got, value)
		}
	}
	inApp, ok := receipt["in_app"].([]any)
	if !ok || len(inApp) != 1 {
		t.Fatalf("in_app: %v", receipt["in_app"])
	}
	entry := inApp[0].(map[string]any)
	// Apple renders every one of these as a string on the wire, however
	// they are typed in the receipt.
	for key, value := range map[string]any{
		"quantity":                 "2",
		"web_order_line_item_id":   "42",
		"is_in_intro_offer_period": "true",
		"expires_date":             "2030-02-01 09:30:00 Etc/GMT",
		"expires_date_ms":          "1896168600000",
	} {
		if got := entry[key]; got != value {
			t.Errorf("in_app[0].%s: got %v, want %v", key, got, value)
		}
	}
	// A date the receipt does not carry is absent, not empty or zero.
	if _, present := entry["cancellation_date"]; present {
		t.Error("a date the receipt does not carry must be absent from the body")
	}
}

// The wire body must contain the download id's exact digits. Serialising
// it through a float64 anywhere in the pipeline would answer
// 9223372036854775808 (2^63) instead of 9223372036854775807 (2^63-1) here.
func TestEndpointIdsExactDigits(t *testing.T) {
	pki := newReceiptPKI(t)
	der := pki.receipt(t,
		attr(0, derUTF8String("Production")),
		attr(2, derUTF8String("com.example.app")),
		attr(1, derInt(1234567890)),
		attr(15, derInt(9223372036854775807)),
		attr(16, derInt(456789012)),
		attr(17, receiptPayload(
			attr(1702, derUTF8String("com.example.app.coins100")),
			attr(1713, derInt(0)),
		)),
	)
	endpoint := endpointVerifierFor(t, pki.anchors(), nil)
	request := `{"receipt-data":"` + applereceiptBase64(der) + `"}`
	out := endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentProduction, request)
	for _, literal := range []string{
		`"adam_id":1234567890`,
		`"app_item_id":1234567890`,
		`"download_id":9223372036854775807`,
		`"version_external_identifier":456789012`,
		`"is_trial_period":"false"`,
	} {
		if !strings.Contains(out, literal) {
			t.Errorf("body must contain the literal %s, got %s", literal, out)
		}
	}
	if strings.Contains(out, "9223372036854775808") {
		t.Fatalf("download_id was rounded to 2^63 somewhere in the pipeline: %s", out)
	}
}

// An attribute the receipt does not carry leaves its key OUT of the body
// entirely, never JSON null.
func TestEndpointIdsAbsentAreOmitted(t *testing.T) {
	pki := newReceiptPKI(t)
	der := pki.receipt(t,
		attr(0, derUTF8String("ProductionSandbox")),
		attr(2, derUTF8String("com.example.app")),
		attr(17, receiptPayload(
			attr(1702, derUTF8String("com.example.app.coins100")),
		)),
	)
	endpoint := endpointVerifierFor(t, pki.anchors(), nil)
	request := `{"receipt-data":"` + applereceiptBase64(der) + `"}`
	out := endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request)
	for _, key := range []string{
		"adam_id", "app_item_id", "download_id", "version_external_identifier", "is_trial_period",
	} {
		if strings.Contains(out, `"`+key+`"`) {
			t.Errorf("absent attribute must omit its key %q entirely, got %s", key, out)
		}
	}
}

// The clock is read at most once per call (config.go). A dateless receipt
// needs "now" twice, for the chain instant and for request_date; both must
// be the same reading, so the response can never show a request_date the
// chain was not judged at.
func TestEndpointReadsTheClockOncePerCall(t *testing.T) {
	pki := newReceiptPKI(t)
	dateless := pki.receipt(t,
		attr(0, derUTF8String("ProductionSandbox")),
		attr(2, derUTF8String("com.example.app")))
	start := time.Now().UnixMilli()
	reads := 0
	clock := func() int64 {
		reads++
		return start + int64(reads)*3_600_000
	}
	endpoint := endpointVerifierFor(t, pki.anchors(), clock)
	request := `{"receipt-data":"` + applereceiptBase64(dateless) + `"}`

	response := decodeEndpointResponse(t, endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request))
	if response["status"] != float64(applereceipt.StatusOK) {
		t.Fatalf("status: %v", response["status"])
	}
	if reads != 1 {
		t.Fatalf("one endpoint call read the clock %d times, want 1", reads)
	}
	receipt, _ := response["receipt"].(map[string]any)
	if got, want := receipt["request_date_ms"], strconv.FormatInt(start+3_600_000, 10); got != want {
		t.Fatalf("request_date_ms %v is not the clock's one reading %s", got, want)
	}

	if _, err := endpoint.VerifyReceipt(applereceiptBase64(dateless)); err != nil {
		t.Fatal(err)
	}
	if reads != 2 {
		t.Fatalf("VerifyReceipt of a dateless receipt must read the clock exactly once, total reads %d", reads)
	}
}

// A caller's clock that panics is the caller's failure, not the input's:
// INTERNAL_ERROR from the verify methods and 21009 from the endpoint,
// never a panic that takes the caller's request down.
func TestPanickingClockBecomesAnInternalError(t *testing.T) {
	pki := newReceiptPKI(t)
	dateless := pki.receipt(t,
		attr(0, derUTF8String("ProductionSandbox")),
		attr(2, derUTF8String("com.example.app")))
	for name, value := range map[string]any{
		"an error": errors.New("clock backend unavailable"),
		"a string": "clock failure",
	} {
		value := value
		t.Run(name, func(t *testing.T) {
			verifier := endpointVerifierFor(t, pki.anchors(), func() int64 { panic(value) })
			_, err := verifier.VerifyReceipt(applereceiptBase64(dateless))
			requireReason(t, err, applereceipt.ReasonInternalError)

			request := `{"receipt-data":"` + applereceiptBase64(dateless) + `"}`
			if got := verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, request); got != `{"status":21009}` {
				t.Fatalf("endpoint answered %s, want {\"status\":21009}", got)
			}
			// A dated receipt still needs the clock for request_date.
			dated := `{"receipt-data":"` + applereceiptBase64(pki.receipt(t)) + `"}`
			if got := verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, dated); got != `{"status":21009}` {
				t.Fatalf("endpoint answered %s for a dated receipt, want {\"status\":21009}", got)
			}
		})
	}
}
