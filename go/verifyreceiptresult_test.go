package applereceipt_test

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

var resultDate = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return resultDate }

// receiptOfType builds a receipt the test PKI signs, with the given
// receipt_type ("" leaves the attribute out).
func receiptOfType(t *testing.T, pki receiptPKI, receiptType string) string {
	t.Helper()
	attributes := [][]byte{attr(2, derUTF8String("com.example.app"))}
	if receiptType != "" {
		attributes = append(attributes, attr(0, derUTF8String(receiptType)))
	}
	return base64.StdEncoding.EncodeToString(pki.receipt(t, attributes...))
}

// The result's core promise: a caller reads Verified (or Receipt) before
// trusting any field, and Reason/Err whenever that is false. That only
// works if exactly one side is set for every status the endpoint can
// answer, and if 21007/21008 count as verified: those receipts are
// genuine, only their environment differs.
func TestResultCarriesExactlyOneOfReceiptAndReason(t *testing.T) {
	pki := newReceiptPKI(t)
	other := newReceiptPKI(t)
	production := endpointFor(t, pki.anchors(), applereceipt.EnvironmentProduction, fixedClock)
	sandbox := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, fixedClock)
	foreign := endpointFor(t, other.anchors(), applereceipt.EnvironmentSandbox, fixedClock)
	panicking := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox,
		func() time.Time { panic("clock failure") })

	sandboxReceipt := receiptOfType(t, pki, "ProductionSandbox")
	productionReceipt := receiptOfType(t, pki, "Production")

	tests := []struct {
		name     string
		result   *applereceipt.VerifyReceiptResult
		status   int
		verified bool
		reason   applereceipt.Reason
	}{
		{"0", sandbox.VerifyReceiptData(sandboxReceipt), 0, true, ""},
		{"21007", production.VerifyReceiptData(sandboxReceipt), 21007, true, ""},
		{"21008", sandbox.VerifyReceiptData(productionReceipt), 21008, true, ""},
		{"21002 empty receipt-data", sandbox.VerifyReceiptData(""), 21002, false,
			applereceipt.ReasonMalformedRequest},
		{"21002 body is not JSON", sandbox.VerifyReceiptBody([]byte("}{")), 21002, false,
			applereceipt.ReasonMalformedRequest},
		{"21002 not base64", sandbox.VerifyReceiptData("!!!!"), 21002, false,
			applereceipt.ReasonInvalidReceiptFormat},
		{"21003", foreign.VerifyReceiptData(sandboxReceipt), 21003, false, applereceipt.ReasonInvalidChain},
		{"21009", panicking.VerifyReceiptData(sandboxReceipt), 21009, false, applereceipt.ReasonInternalError},
		{"21009 zero value", &applereceipt.VerifyReceiptResult{}, 21009, false, applereceipt.ReasonInternalError},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			result := test.result
			if got := result.Status(); got != test.status {
				t.Fatalf("status %d, want %d", got, test.status)
			}
			if result.Verified() != test.verified {
				t.Fatalf("Verified() = %v, want %v", result.Verified(), test.verified)
			}
			if (result.Receipt() != nil) != test.verified {
				t.Fatal("Receipt must be set exactly when Verified is true")
			}
			if (result.Reason() == "") != test.verified {
				t.Fatal("Reason must be set exactly when Verified is false")
			}
			if (result.Err() == nil) != test.verified {
				t.Fatal("Err must be nil exactly when Verified is true")
			}
			if result.Reason() != test.reason {
				t.Fatalf("reason %q, want %q", result.Reason(), test.reason)
			}
			if !test.verified {
				if reason, ok := applereceipt.ReasonOf(result.Err()); !ok || reason != test.reason {
					t.Fatalf("Err must be a *VerificationError with the same reason, got %v", result.Err())
				}
			}
		})
	}
}

// Retrying in the other environment must cost no second verification,
// and must never let a sandbox receipt answer a production 0.
func TestResultReRendersForEitherEnvironment(t *testing.T) {
	pki := newReceiptPKI(t)
	for _, test := range []struct {
		receiptType string
		production  bool
	}{
		{"Production", true},
		{"ProductionVPP", true},
		{"ProductionSandbox", false},
		{"ProductionVPPSandbox", false},
		{"Xcode", false},
		{"", false},
	} {
		data := receiptOfType(t, pki, test.receiptType)
		for _, home := range []applereceipt.Environment{applereceipt.EnvironmentProduction, applereceipt.EnvironmentSandbox} {
			result := endpointFor(t, pki.anchors(), home, fixedClock).VerifyReceiptData(data)
			for _, target := range []applereceipt.Environment{applereceipt.EnvironmentProduction, applereceipt.EnvironmentSandbox} {
				response, err := result.ResponseFor(target)
				if err != nil {
					t.Fatal(err)
				}
				want := applereceipt.StatusOK
				switch {
				case target == applereceipt.EnvironmentProduction && !test.production:
					want = applereceipt.StatusSandboxReceiptOnProduction
				case target == applereceipt.EnvironmentSandbox && test.production:
					want = applereceipt.StatusProductionReceiptOnSandbox
				}
				if response.Status != want {
					t.Errorf("%q verified on %s, rendered for %s: status %d, want %d",
						test.receiptType, home, target, response.Status, want)
				}
				if response.Status == applereceipt.StatusOK {
					if response.Environment != target || response.Receipt == nil {
						t.Errorf("a 0 answer names the rendered environment and carries the receipt")
					}
				} else if response.Environment != "" || response.Receipt != nil {
					t.Errorf("a 21007/21008 answer carries neither receipt nor environment")
				}
				// The JSON form is the same render, serialized.
				body, err := result.JSONFor(target)
				if err != nil {
					t.Fatal(err)
				}
				marshalled, _ := json.Marshal(response)
				if !bytes.Equal(body, marshalled) {
					t.Errorf("JSONFor and ResponseFor disagree:\n%s\n%s", body, marshalled)
				}
			}
			// The home render is ResponseFor(home).
			home, _ := result.JSONFor(home)
			if !bytes.Equal(result.JSON(), home) {
				t.Errorf("JSON() must equal JSONFor(the endpoint's environment)")
			}
		}
	}
}

// The status routing is fixed when the receipt verifies. Receipt() hands
// out a shared pointer, and editing its receipt_type must not turn a
// sandbox receipt into a production 0.
func TestEditingTheReceiptCannotChangeTheStatus(t *testing.T) {
	pki := newReceiptPKI(t)
	result := endpointFor(t, pki.anchors(), applereceipt.EnvironmentProduction, fixedClock).
		VerifyReceiptData(receiptOfType(t, pki, "ProductionSandbox"))
	result.Receipt().ReceiptType = "Production"
	if result.Status() != applereceipt.StatusSandboxReceiptOnProduction {
		t.Fatalf("status %d after editing the receipt, want 21007", result.Status())
	}
}

func TestFailedResultKeepsItsStatusInEveryEnvironment(t *testing.T) {
	pki := newReceiptPKI(t)
	endpoint := endpointFor(t, pki.anchors(), applereceipt.EnvironmentProduction, fixedClock)
	for _, result := range []*applereceipt.VerifyReceiptResult{
		endpoint.VerifyReceiptData(""),
		endpoint.VerifyReceiptData("QQ=="),
		endpointFor(t, newReceiptPKI(t).anchors(), applereceipt.EnvironmentProduction, fixedClock).
			VerifyReceiptData(receiptOfType(t, pki, "Production")),
	} {
		for _, target := range []applereceipt.Environment{applereceipt.EnvironmentProduction, applereceipt.EnvironmentSandbox} {
			response, err := result.ResponseFor(target)
			if err != nil {
				t.Fatal(err)
			}
			if response.Status != result.Status() || response.Receipt != nil {
				t.Errorf("%s: a failed result rendered for %s answered %+v", result.Reason(), target, response)
			}
		}
	}
}

// Apple has no verifyReceipt host for Xcode or LocalTesting, so a render
// for one is refused the way the constructor refuses it: a plain error,
// never a *VerificationError and never a body.
func TestRenderRefusesEnvironmentsWithNoVerifyReceiptHost(t *testing.T) {
	pki := newReceiptPKI(t)
	result := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, fixedClock).
		VerifyReceiptData(receiptOfType(t, pki, "ProductionSandbox"))
	for _, environment := range []applereceipt.Environment{
		applereceipt.EnvironmentXcode, applereceipt.EnvironmentLocalTesting, "", "Martian",
	} {
		if _, err := result.ResponseFor(environment); err == nil {
			t.Errorf("ResponseFor(%q) must fail", environment)
		} else if _, ok := applereceipt.ReasonOf(err); ok {
			t.Errorf("ResponseFor(%q): a configuration error must not carry a Reason", environment)
		}
		if body, err := result.JSONFor(environment); err == nil || body != nil {
			t.Errorf("JSONFor(%q) must fail with no body", environment)
		}
	}
}

// An explicit request time is the answer to "what did we tell the client
// and when": it must become request_date without the clock being read.
// Without one, the clock is read once per call, so a result rendered
// twice (or for the other environment) never shows two dates.
func TestRequestDate(t *testing.T) {
	pki := newReceiptPKI(t)
	data := receiptOfType(t, pki, "ProductionSandbox")
	body, _ := json.Marshal(map[string]string{"receipt-data": data})
	reads := 0
	clock := func() time.Time {
		reads++
		return resultDate.Add(time.Duration(reads) * time.Hour)
	}
	endpoint := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, clock)
	explicit := time.Date(2030, 6, 1, 12, 0, 0, 0, time.UTC)

	for name, result := range map[string]*applereceipt.VerifyReceiptResult{
		"VerifyReceiptAt":     endpoint.VerifyReceiptAt(applereceipt.VerifyReceiptRequest{ReceiptData: data}, explicit),
		"VerifyReceiptDataAt": endpoint.VerifyReceiptDataAt(data, explicit),
		"VerifyReceiptBodyAt": endpoint.VerifyReceiptBodyAt(body, explicit),
	} {
		if !result.RequestDate().Equal(explicit) {
			t.Errorf("%s: RequestDate %v, want %v", name, result.RequestDate(), explicit)
		}
		if got := result.Response().Receipt["request_date_ms"]; got != strconv.FormatInt(explicit.UnixMilli(), 10) {
			t.Errorf("%s: request_date_ms %v", name, got)
		}
	}
	if reads != 0 {
		t.Fatalf("an explicit request time must not read the clock; it was read %d times", reads)
	}

	result := endpoint.VerifyReceiptData(data)
	if reads != 1 {
		t.Fatalf("the clock must be read once per call, got %d", reads)
	}
	first := result.JSON()
	_, _ = result.JSONFor(applereceipt.EnvironmentProduction)
	if again := result.JSON(); !bytes.Equal(first, again) || reads != 1 {
		t.Fatalf("rendering must not read the clock again (reads %d)", reads)
	}
	if !result.RequestDate().Equal(resultDate.Add(time.Hour)) {
		t.Fatalf("RequestDate %v is not the clock's one reading", result.RequestDate())
	}
}

// The explicit time is request_date and nothing more: a time planted
// inside an expired chain's window must not authenticate it.
func TestExplicitRequestTimeCannotAuthenticateAnExpiredChain(t *testing.T) {
	expired := expiredChainReceipt(t)
	result := endpointFor(t, expired.roots, applereceipt.EnvironmentSandbox, nil).
		VerifyReceiptDataAt(expired.data, expired.inWindow)
	if result.Status() != applereceipt.StatusNotAuthenticated || result.Verified() {
		t.Fatalf("an explicit request time must not authenticate an expired chain, got %d", result.Status())
	}
}

// An unexpected failure inside the endpoint is a 21009 result, never a
// panic that takes the caller's request down, and the cause survives for
// logging through errors.Unwrap.
func TestInternalErrorBecomesAResult(t *testing.T) {
	pki := newReceiptPKI(t)
	data := receiptOfType(t, pki, "ProductionSandbox")
	cause := errors.New("clock backend unavailable")
	for name, value := range map[string]any{"an error": cause, "a string": "clock failure"} {
		value := value
		endpoint := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox,
			func() time.Time { panic(value) })
		result := endpoint.VerifyReceiptData(data)
		if result.Reason() != applereceipt.ReasonInternalError || string(result.JSON()) != `{"status":21009}` {
			t.Fatalf("%s: got %s, %s", name, result.Reason(), result.JSON())
		}
		unwrapped := errors.Unwrap(result.Err())
		if unwrapped == nil {
			t.Fatalf("%s: errors.Unwrap must give the cause", name)
		}
		if value == cause && unwrapped != cause {
			t.Fatalf("%s: errors.Unwrap gave %v, want the panic's own error", name, unwrapped)
		}
		if got := string(endpoint.VerifyReceiptJSON([]byte(`{"receipt-data":"` + data + `"}`))); got != `{"status":21009}` {
			t.Fatalf("%s: VerifyReceiptJSON answered %s", name, got)
		}
	}
}

// The other road to INTERNAL_ERROR: a trusted signer signed content the
// library cannot read. Same status, not the client's fault, and
// errors.Unwrap gives the parser's own error.
func TestUnreadableSignedContentIsAnInternalError(t *testing.T) {
	pki := newReceiptPKI(t)
	der := buildCMS(t, cmsSpec{
		content: receiptPayload(append(
			standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now()),
			attr(17, []byte{0x04, 0x02, 0x13, 0x37}))...),
		signer:          pki.leaf,
		certificates:    pki.embedded(),
		withSignedAttrs: true,
	})
	endpoint := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, time.Now)
	result := endpoint.VerifyReceiptData(base64.StdEncoding.EncodeToString(der))
	if result.Reason() != applereceipt.ReasonInternalError || string(result.JSON()) != `{"status":21009}` {
		t.Fatalf("got %s, %s", result.Reason(), result.JSON())
	}
	reason, ok := applereceipt.ReasonOf(errors.Unwrap(result.Err()))
	if !ok || reason != applereceipt.ReasonInvalidReceiptFormat {
		t.Fatalf("errors.Unwrap must give the parser's error, got %v", errors.Unwrap(result.Err()))
	}
}

// Handing a result to encoding/json must produce Apple's body. Without
// MarshalJSON it would be "{}", silently, for any caller that used to
// encode the old VerifyReceiptResponse return value directly.
func TestResultMarshalsAsTheResponseBody(t *testing.T) {
	pki := newReceiptPKI(t)
	result := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, fixedClock).
		VerifyReceiptData(receiptOfType(t, pki, "ProductionSandbox"))
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, result.JSON()) {
		t.Fatalf("json.Marshal(result) = %s, want %s", encoded, result.JSON())
	}
}

// The bare-base64 entry point and the JSON-body entry point must be the
// same endpoint: over every receipt the conformance vectors use, in both
// environments, the answers must match byte for byte. The one exception is
// a body over MaxRequestBytes (the receipt-cap vectors' 3 MiB strings plus
// their envelope), which the body path refuses as REQUEST_TOO_LARGE before
// parsing while the bare path, which has no envelope to cap, answers on the
// receipt-data alone.
func TestReceiptDataMatchesTheBodyPathOverEveryReceiptFixture(t *testing.T) {
	compared := 0
	for _, kase := range mustCases(t).Cases {
		switch kase.Operation {
		case "verifyReceipt", "verifyReceiptBase64", "verifyReceiptEndpoint":
		default:
			continue
		}
		if kase.Input.RequestBody != "" {
			continue // already a whole body, not a receipt
		}
		input := fixtureBytes(t, kase.Input.Fixture)
		receiptData := base64.StdEncoding.EncodeToString(input)
		if fixtureCodec(t, kase.Input.Fixture) == "text" {
			receiptData = string(input)
		}
		body, err := json.Marshal(map[string]string{"receipt-data": receiptData})
		if err != nil {
			t.Fatal(err)
		}
		roots := trustedRootsFor(t, kase.Config.TrustedRoots)
		for _, environment := range []applereceipt.Environment{applereceipt.EnvironmentProduction, applereceipt.EnvironmentSandbox} {
			endpoint := endpointFor(t, roots, environment, fixedClock)
			fromData := endpoint.VerifyReceiptData(receiptData).JSON()
			fromBody := endpoint.VerifyReceiptJSON(body)
			if len(body) > applereceipt.MaxRequestBytes {
				bodyResult := endpoint.VerifyReceiptBody(body)
				if string(fromBody) != `{"status":21002}` || bodyResult.Reason() != applereceipt.ReasonRequestTooLarge {
					t.Errorf("%s on %s: a %d byte body must be 21002 REQUEST_TOO_LARGE on the body path, got %s %s",
						kase.ID, environment, len(body), fromBody, bodyResult.Reason())
				}
			} else if !bytes.Equal(fromData, fromBody) {
				t.Errorf("%s on %s: VerifyReceiptData and VerifyReceiptJSON differ:\n%s\n%s",
					kase.ID, environment, fromData, fromBody)
			}
			compared++
		}
	}
	if compared < 100 {
		t.Fatalf("only %d comparisons; the fixture set was not reached", compared)
	}
}

// The two endpoint-only reasons are real tokens other ports report, and
// they stay out of AllReasons, which is the shared schema's vocabulary
// of verifier reasons. INTERNAL_ERROR is a verifier reason too (signed
// content that cannot be read), so it is in it.
func TestEndpointOnlyReasons(t *testing.T) {
	if applereceipt.ReasonMalformedRequest != "MALFORMED_REQUEST" ||
		applereceipt.ReasonRequestTooLarge != "REQUEST_TOO_LARGE" ||
		applereceipt.ReasonInternalError != "INTERNAL_ERROR" {
		t.Fatal("the endpoint-only reason tokens are misspelled")
	}
	internal := false
	for _, reason := range applereceipt.AllReasons() {
		if reason == applereceipt.ReasonMalformedRequest || reason == applereceipt.ReasonRequestTooLarge {
			t.Fatalf("%s is endpoint-only and must not be in AllReasons", reason)
		}
		internal = internal || reason == applereceipt.ReasonInternalError
	}
	if !internal {
		t.Fatal("INTERNAL_ERROR is a verifier reason and must be in AllReasons")
	}
}

type expiredChain struct {
	roots    []*x509.Certificate
	data     string
	inWindow time.Time
}

// expiredChainReceipt is a receipt whose chain was valid for two days ten
// years ago, with no creation date, so the validity instant falls back to
// the system clock. inWindow is a time inside that old window.
func expiredChainReceipt(t *testing.T) expiredChain {
	t.Helper()
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
	der := buildCMS(t, cmsSpec{
		content:      receiptPayload(attr(2, derUTF8String("com.example.app"))),
		signer:       leaf,
		certificates: [][]byte{leaf.der},
	})
	return expiredChain{
		roots:    []*x509.Certificate{root.cert},
		data:     base64.StdEncoding.EncodeToString(der),
		inWindow: past.Add(time.Hour),
	}
}
