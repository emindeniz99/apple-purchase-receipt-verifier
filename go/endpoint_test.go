package applereceipt_test

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

func endpointFor(t *testing.T, roots []*x509.Certificate, environment applereceipt.Environment,
	now func() time.Time) *applereceipt.VerifyReceiptEndpoint {
	t.Helper()
	endpoint, err := applereceipt.NewVerifyReceiptEndpoint(applereceipt.VerifyReceiptEndpointOptions{
		TrustedRoots: roots, Environment: environment, Now: now,
	})
	if err != nil {
		t.Fatalf("NewVerifyReceiptEndpoint: %v", err)
	}
	return endpoint
}

func TestEndpointMalformedBodies(t *testing.T) {
	pki := newReceiptPKI(t)
	endpoint := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, nil)

	t.Run("empty receipt-data", func(t *testing.T) {
		if got := endpoint.VerifyReceipt(applereceipt.VerifyReceiptRequest{}).Status; got != applereceipt.StatusMalformed {
			t.Fatalf("status: got %d", got)
		}
	})
	t.Run("receipt-data that is not a receipt", func(t *testing.T) {
		response := endpoint.VerifyReceipt(applereceipt.VerifyReceiptRequest{
			ReceiptData: base64.StdEncoding.EncodeToString([]byte("nope")),
		})
		if response.Status != applereceipt.StatusMalformed {
			t.Fatalf("status: got %d", response.Status)
		}
	})

	jsonBodies := []struct {
		name string
		body string
		want int
	}{
		{"not JSON at all", "}{", applereceipt.StatusMalformed},
		{"a JSON array", `[1,2,3]`, applereceipt.StatusMalformed},
		{"JSON null", `null`, applereceipt.StatusMalformed},
		{"a JSON string", `"receipt"`, applereceipt.StatusMalformed},
		{"a JSON number", `42`, applereceipt.StatusMalformed},
		{"an object with no receipt-data", `{}`, applereceipt.StatusMalformed},
		{"receipt-data is null", `{"receipt-data":null}`, applereceipt.StatusMalformed},
		{"receipt-data is a number", `{"receipt-data":123}`, applereceipt.StatusMalformed},
		{"receipt-data is an object", `{"receipt-data":{"a":1}}`, applereceipt.StatusMalformed},
		{"receipt-data is empty", `{"receipt-data":""}`, applereceipt.StatusMalformed},
		{"empty body", ``, applereceipt.StatusMalformed},
	}
	for _, test := range jsonBodies {
		test := test
		t.Run(test.name, func(t *testing.T) {
			var response applereceipt.VerifyReceiptResponse
			out := endpoint.VerifyReceiptJSON([]byte(test.body))
			if err := json.Unmarshal(out, &response); err != nil {
				t.Fatalf("the endpoint must always answer JSON, got %q: %v", out, err)
			}
			if response.Status != test.want {
				t.Fatalf("status: got %d, want %d (%s)", response.Status, test.want, out)
			}
		})
	}
}

func TestEndpointAcceptsAndIgnoresTheCompatibilityFields(t *testing.T) {
	pki := newReceiptPKI(t)
	endpoint := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, nil)
	body, err := json.Marshal(map[string]any{
		"receipt-data":             base64.StdEncoding.EncodeToString(pki.receipt(t)),
		"password":                 "a shared secret that cannot be checked locally",
		"exclude-old-transactions": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var response applereceipt.VerifyReceiptResponse
	if err := json.Unmarshal(endpoint.VerifyReceiptJSON(body), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != applereceipt.StatusOK {
		t.Fatalf("password and exclude-old-transactions are accepted and ignored, got %d", response.Status)
	}
}

// status 0 must be present in the wire body. Go's omitempty on an int
// field would silently drop it and produce a body no verifyReceipt client
// can read.
func TestSuccessBodyCarriesAnExplicitZeroStatus(t *testing.T) {
	pki := newReceiptPKI(t)
	endpoint := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, nil)
	body, err := json.Marshal(map[string]any{
		"receipt-data": base64.StdEncoding.EncodeToString(pki.receipt(t)),
	})
	if err != nil {
		t.Fatal(err)
	}
	out := string(endpoint.VerifyReceiptJSON(body))
	if !strings.Contains(out, `"status":0`) {
		t.Fatalf(`the success body must carry "status":0, got %s`, out)
	}
}

func TestEndpointJSONIsDeterministic(t *testing.T) {
	pki := newReceiptPKI(t)
	at := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	endpoint := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox,
		func() time.Time { return at })
	body, err := json.Marshal(map[string]any{
		"receipt-data": base64.StdEncoding.EncodeToString(pki.receipt(t)),
	})
	if err != nil {
		t.Fatal(err)
	}
	first := string(endpoint.VerifyReceiptJSON(body))
	for i := 0; i < 20; i++ {
		if got := string(endpoint.VerifyReceiptJSON(body)); got != first {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, got)
		}
	}
}

func TestRequestDateComesFromTheInjectedClock(t *testing.T) {
	pki := newReceiptPKI(t)
	at := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	endpoint := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox,
		func() time.Time { return at })
	response := endpoint.VerifyReceipt(applereceipt.VerifyReceiptRequest{
		ReceiptData: base64.StdEncoding.EncodeToString(pki.receipt(t)),
	})
	if response.Status != applereceipt.StatusOK {
		t.Fatalf("status: %d", response.Status)
	}
	want := map[string]string{
		"request_date":     "2025-01-01 00:00:00 Etc/GMT",
		"request_date_ms":  "1735689600000",
		"request_date_pst": "2024-12-31 16:00:00 America/Los_Angeles",
	}
	for key, value := range want {
		if got := response.Receipt[key]; got != value {
			t.Errorf("%s: got %v, want %q", key, got, value)
		}
	}
}

// The endpoint's clock reaches request_date and nothing else. A clock
// planted inside an expired chain's window must not authenticate it.
func TestEndpointClockCannotAuthenticateAnExpiredChain(t *testing.T) {
	past := time.Now().Add(-10 * 365 * 24 * time.Hour)
	root := issueCert(t, certSpec{
		commonName: "Expired Receipt Root", isCA: true, rsa: true,
		notBefore: past, notAfter: past.Add(48 * time.Hour),
	}, nil)
	leaf := issueCert(t, certSpec{
		commonName: "Expired Receipt Signer", rsa: true,
		markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
		notBefore:  past, notAfter: past.Add(48 * time.Hour),
	}, root)
	// A receipt with no creation date, so the validity instant falls back
	// — to the system clock, never to the injected one.
	der := buildCMS(t, cmsSpec{
		content:      receiptPayload(attr(2, derUTF8String("com.example.app"))),
		signer:       leaf,
		certificates: [][]byte{leaf.der},
	})
	endpoint := endpointFor(t, []*x509.Certificate{root.cert}, applereceipt.EnvironmentSandbox,
		func() time.Time { return past.Add(time.Hour) })
	response := endpoint.VerifyReceipt(applereceipt.VerifyReceiptRequest{
		ReceiptData: base64.StdEncoding.EncodeToString(der),
	})
	if response.Status != applereceipt.StatusNotAuthenticated {
		t.Fatalf("an injected clock must not authenticate an expired chain, got %d", response.Status)
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
			data := base64.StdEncoding.EncodeToString(der)

			production := endpointFor(t, pki.anchors(), applereceipt.EnvironmentProduction, nil).
				VerifyReceipt(applereceipt.VerifyReceiptRequest{ReceiptData: data})
			if production.Status != test.onProduction {
				t.Errorf("on Production: got %d, want %d", production.Status, test.onProduction)
			}
			sandbox := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, nil).
				VerifyReceipt(applereceipt.VerifyReceiptRequest{ReceiptData: data})
			if sandbox.Status != test.onSandbox {
				t.Errorf("on Sandbox: got %d, want %d", sandbox.Status, test.onSandbox)
			}
			// A routed answer carries no receipt and no environment: it
			// is a redirect, not a verdict about the contents.
			if production.Status != applereceipt.StatusOK &&
				(production.Receipt != nil || production.Environment != "") {
				t.Error("a 21007/21008 answer must carry neither receipt nor environment")
			}
		})
	}
}

func TestEndpointStatusesForFailedVerification(t *testing.T) {
	pki := newReceiptPKI(t)
	other := newReceiptPKI(t)
	endpoint := endpointFor(t, other.anchors(), applereceipt.EnvironmentSandbox, nil)

	t.Run("a foreign chain is 21003", func(t *testing.T) {
		response := endpoint.VerifyReceipt(applereceipt.VerifyReceiptRequest{
			ReceiptData: base64.StdEncoding.EncodeToString(pki.receipt(t)),
		})
		if response.Status != applereceipt.StatusNotAuthenticated {
			t.Fatalf("got %d", response.Status)
		}
	})
	t.Run("a malformed receipt is 21002", func(t *testing.T) {
		response := endpoint.VerifyReceipt(applereceipt.VerifyReceiptRequest{
			ReceiptData: base64.StdEncoding.EncodeToString(derSequence(derInt(1))),
		})
		if response.Status != applereceipt.StatusMalformed {
			t.Fatalf("got %d", response.Status)
		}
	})
}

// The endpoint does not check the bundle id, exactly like Apple's: the
// caller compares receipt.bundle_id itself.
func TestEndpointDoesNotCheckTheBundleID(t *testing.T) {
	pki := newReceiptPKI(t)
	response := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, nil).
		VerifyReceipt(applereceipt.VerifyReceiptRequest{
			ReceiptData: base64.StdEncoding.EncodeToString(pki.receipt(t)),
		})
	if response.Status != applereceipt.StatusOK {
		t.Fatalf("status: %d", response.Status)
	}
	if response.Receipt["bundle_id"] != "com.example.app" {
		t.Fatalf("bundle_id: %v", response.Receipt["bundle_id"])
	}
}

func TestEndpointNeverPanicsOverTheHostileCorpus(t *testing.T) {
	pki := newReceiptPKI(t)
	// A frozen clock, so the only thing that can make two bodies differ
	// is the receipt they describe.
	at := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	endpoint := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox,
		func() time.Time { return at })
	good := pki.receipt(t)
	genuine := endpoint.VerifyReceipt(applereceipt.VerifyReceiptRequest{
		ReceiptData: base64.StdEncoding.EncodeToString(good),
	})
	if genuine.Status != applereceipt.StatusOK {
		t.Fatalf("the unmutated receipt must verify: %d", genuine.Status)
	}
	genuineBody, err := json.Marshal(genuine)
	if err != nil {
		t.Fatal(err)
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
		response := endpoint.VerifyReceipt(applereceipt.VerifyReceiptRequest{
			ReceiptData: base64.StdEncoding.EncodeToString(input),
		})
		// 21009 means something escaped that was not a VerificationError.
		if response.Status == applereceipt.StatusInternal {
			t.Fatalf("corpus entry %d produced 21009: something unexpected escaped", i)
		}
		if response.Status != applereceipt.StatusOK {
			continue
		}
		// A mutation is allowed to leave the answer unchanged — the CMS
		// signatureAlgorithm identifier, for instance, is deliberately
		// never consulted (see TestSignatureAlgorithmIdentifierIsNotConsulted).
		// What it may never do is change what the receipt says.
		body, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != string(genuineBody) {
			t.Fatalf("corpus entry %d verified with a DIFFERENT body:\n%s\n%s", i, genuineBody, body)
		}
	}
}

// A recorded, deliberate property, shared with the Node port: the
// SignerInfo's signatureAlgorithm AlgorithmIdentifier is not consulted.
// The hash comes from digestAlgorithm and the scheme is RSA PKCS#1 v1.5,
// both enforced; the identifier is a claim about the signature that the
// signature does not cover, so believing it would be worse than ignoring
// it. Changing it therefore changes no verdict, which is exactly why the
// mutation suites assert "the answer never changes" rather than "every
// mutation is rejected".
func TestSignatureAlgorithmIdentifierIsNotConsulted(t *testing.T) {
	pki := newReceiptPKI(t)
	good := pki.receipt(t)
	// The rsaEncryption OID inside the SignerInfo, i.e. the last
	// occurrence of its encoding in the blob.
	needle := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}
	at := bytes.LastIndex(good, needle)
	if at < 0 {
		t.Fatal("could not locate the SignerInfo signatureAlgorithm OID")
	}
	mutated := bytes.Clone(good)
	mutated[at+len(needle)-1] ^= 0xff
	if _, err := applereceipt.VerifyReceiptCore(mutated, pki.anchors()); err != nil {
		t.Fatalf("the signatureAlgorithm identifier is not consulted, so this must still verify: %v", err)
	}
}

func TestEndpointConstructorRejectsMisconfiguration(t *testing.T) {
	pki := newReceiptPKI(t)
	tests := []struct {
		name    string
		options applereceipt.VerifyReceiptEndpointOptions
	}{
		{"no anchors", applereceipt.VerifyReceiptEndpointOptions{
			Environment: applereceipt.EnvironmentSandbox,
		}},
		{"no environment", applereceipt.VerifyReceiptEndpointOptions{
			TrustedRoots: pki.anchors(),
		}},
		// Environment is the four-valued Apple type, but Apple has no
		// verifyReceipt host for Xcode or LocalTesting, so the endpoint
		// narrows it at construction rather than at request time.
		{"Xcode is not an endpoint environment", applereceipt.VerifyReceiptEndpointOptions{
			TrustedRoots: pki.anchors(), Environment: applereceipt.EnvironmentXcode,
		}},
		{"LocalTesting is not an endpoint environment", applereceipt.VerifyReceiptEndpointOptions{
			TrustedRoots: pki.anchors(), Environment: applereceipt.EnvironmentLocalTesting,
		}},
		{"an unknown environment", applereceipt.VerifyReceiptEndpointOptions{
			TrustedRoots: pki.anchors(), Environment: "Martian",
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			endpoint, err := applereceipt.NewVerifyReceiptEndpoint(test.options)
			if err == nil {
				t.Fatal("expected a configuration error")
			}
			if endpoint != nil {
				t.Fatal("a failed constructor must not return an endpoint")
			}
			if _, ok := applereceipt.ReasonOf(err); ok {
				t.Fatalf("misconfiguration must not carry a Reason: %v", err)
			}
		})
	}
}

// The IANA database is a deployment artifact, so the location is
// injectable and the failure to find one is a construction error naming
// the remedy rather than a wrong instant at request time.
func TestPacificLocationIsInjectable(t *testing.T) {
	pki := newReceiptPKI(t)
	fixed := time.FixedZone("America/Los_Angeles", -5*3600)
	endpoint, err := applereceipt.NewVerifyReceiptEndpoint(applereceipt.VerifyReceiptEndpointOptions{
		TrustedRoots:    pki.anchors(),
		Environment:     applereceipt.EnvironmentSandbox,
		PacificLocation: fixed,
		Now:             func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	response := endpoint.VerifyReceipt(applereceipt.VerifyReceiptRequest{
		ReceiptData: base64.StdEncoding.EncodeToString(pki.receipt(t)),
	})
	if got := response.Receipt["request_date_pst"]; got != "2024-12-31 19:00:00 America/Los_Angeles" {
		t.Fatalf("the injected location must drive the _pst rendering, got %v", got)
	}
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
	response := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, nil).
		VerifyReceipt(applereceipt.VerifyReceiptRequest{
			ReceiptData: base64.StdEncoding.EncodeToString(der),
		})
	if response.Status != applereceipt.StatusOK {
		t.Fatalf("status: %d", response.Status)
	}
	want := map[string]any{
		"receipt_creation_date":     "2024-08-06 12:00:00 Etc/GMT",
		"receipt_creation_date_ms":  "1722945600000",
		"receipt_creation_date_pst": "2024-08-06 05:00:00 America/Los_Angeles",
	}
	for key, value := range want {
		if got := response.Receipt[key]; got != value {
			t.Errorf("%s: got %v, want %v", key, got, value)
		}
	}
	inApp, ok := response.Receipt["in_app"].([]any)
	if !ok || len(inApp) != 1 {
		t.Fatalf("in_app: %v", response.Receipt["in_app"])
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
