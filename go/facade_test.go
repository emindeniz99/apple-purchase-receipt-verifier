package applereceipt_test

// The facade's own behaviour: reading the module's answers, the six
// outcomes of docs/rust-core/ARCHITECTURE.md section 4, the clock and the
// environment. These tests run over testdata/mirror/mirror.wasm, a test
// double of the ABI that answers each verify call with the input it was
// given, so a test chooses the module's answer exactly and none of them
// depends on what the real core says. The real module is exercised by the
// conformance runner and the concurrency test.

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/host"
)

func mirrorModule(t testing.TB) []byte {
	t.Helper()
	module, err := os.ReadFile("testdata/mirror/mirror.wasm")
	if err != nil {
		t.Fatal(err)
	}
	return module
}

// mirrorVerifier is a Verifier over the test double with config, or the
// defaults.
func mirrorVerifier(t testing.TB, config *applereceipt.Config) *applereceipt.Verifier {
	t.Helper()
	if config == nil {
		config = applereceipt.DefaultConfig()
	}
	verifier, err := applereceipt.NewVerifierOverModule(config, mirrorModule(t))
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func ptr[T any](v T) *T { return &v }

const fullReceiptPayload = `{
 "receipt_type":"ProductionSandbox","app_item_id":"1234567890123456789",
 "bundle_id":"com.example.app","bundle_id_bytes":"Y29tLmV4YW1wbGUuYXBw",
 "application_version":"7","opaque_value":"AQID","sha1_hash":"BAUG",
 "receipt_creation_date_ms":1722945600000,"download_id":"-5",
 "version_external_identifier":null,
 "in_app":[{"quantity":1,"product_id":"pro","transaction_id":"1000000000000001",
   "purchase_date_ms":1,"original_transaction_id":"1000000000000000",
   "original_purchase_date_ms":2,"expires_date_ms":null,
   "web_order_line_item_id":"9223372036854775807","cancellation_date_ms":null,
   "is_trial_period":true,"is_in_intro_offer_period":false,
   "unknown_attributes":{"9999":["AQ=="]}}],
 "original_purchase_date_ms":3,"original_application_version":"1.0",
 "expiration_date_ms":null,
 "unknown_attributes":{"13":["AQI=","Aw=="],"2147483647":[]}}`

const fullReceiptAnswer = `{"verified":true,"payload":` + fullReceiptPayload + `,"environment":"Sandbox"}`

func TestAVerifiedReceiptIsReadIntoTheGoTypes(t *testing.T) {
	verifier := mirrorVerifier(t, nil)
	got, err := verifier.VerifyReceipt(fullReceiptAnswer)
	if err != nil {
		t.Fatal(err)
	}
	want := &applereceipt.ReceiptPayload{
		ReceiptType:           ptr("ProductionSandbox"),
		AppItemID:             ptr(int64(1234567890123456789)),
		BundleID:              ptr("com.example.app"),
		BundleIDBytes:         []byte("com.example.app"),
		ApplicationVersion:    ptr("7"),
		OpaqueValue:           []byte{1, 2, 3},
		SHA1Hash:              []byte{4, 5, 6},
		ReceiptCreationDateMs: ptr(int64(1722945600000)),
		DownloadID:            ptr(int64(-5)),
		InApp: []applereceipt.InAppPurchase{{
			Quantity:               ptr(int64(1)),
			ProductID:              ptr("pro"),
			TransactionID:          ptr("1000000000000001"),
			PurchaseDateMs:         ptr(int64(1)),
			OriginalTransactionID:  ptr("1000000000000000"),
			OriginalPurchaseDateMs: ptr(int64(2)),
			WebOrderLineItemID:     ptr(int64(9223372036854775807)),
			IsTrialPeriod:          ptr(true),
			IsInIntroOfferPeriod:   ptr(false),
			UnknownAttributes:      applereceipt.UnknownAttributes{9999: {{1}}},
		}},
		OriginalPurchaseDateMs:     ptr(int64(3)),
		OriginalApplicationVersion: ptr("1.0"),
		UnknownAttributes:          applereceipt.UnknownAttributes{13: {{1, 2}, {3}}, 2147483647: {}},
		Environment:                ptr(applereceipt.EnvironmentSandbox),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("payload\n got  %+v\n want %+v", got, want)
	}
	// ToJSON writes the same value the module did (0.7: same value, not
	// same bytes), so what a caller logs is what the core said; the
	// environment beside the payload is not part of it.
	original := strings.Join(strings.Fields(fullReceiptPayload), "")
	if !jsonEqual(parseJSONAny(t, "answer", original), parseJSONAny(t, "answer", got.ToJSON())) {
		t.Errorf("ToJSON is not the module's payload:\n got  %s\n want %s", got.ToJSON(), original)
	}
}

func TestAVerifiedReceiptWithNothingCarriedHasEmptyMapsNotNil(t *testing.T) {
	got, err := mirrorVerifier(t, nil).VerifyReceipt(`{"verified":true,"payload":{},"environment":null}`)
	if err != nil {
		t.Fatal(err)
	}
	if got.UnknownAttributes == nil || len(got.InApp) != 0 || got.BundleID != nil || got.Environment != nil {
		t.Fatalf("an empty payload: %+v", got)
	}
}

func TestSignedDataIsReturnedExactlyAsTheModuleWroteIt(t *testing.T) {
	verifier := mirrorVerifier(t, nil)
	// The payload is a JSON string holding the signed bytes: whitespace,
	// key order, 1.0 against 1 and escapes all survive.
	signed := "{ \"b\":1.0,\n \"a\": \"\\u00e9\\ud83d\\ude00\" ,\"id\":12345678901234567890}"
	answer := `{"verified":true,"payload":` + quote(signed) + `,"environment":"Production"}`
	got, err := verifier.VerifySignedData(answer)
	if err != nil {
		t.Fatal(err)
	}
	if got.JSON() != signed {
		t.Fatalf("payload %q, want %q", got.JSON(), signed)
	}
	if environment := got.Environment(); environment == nil || *environment != applereceipt.EnvironmentProduction {
		t.Fatalf("environment %v, want Production", environment)
	}
}

func TestTheEnvironmentIsTheModulesMemberBesideThePayload(t *testing.T) {
	verifier := mirrorVerifier(t, nil)
	for member, want := range map[string]*applereceipt.Environment{
		`"Production"`: ptr(applereceipt.EnvironmentProduction),
		`"Sandbox"`:    ptr(applereceipt.EnvironmentSandbox),
		`null`:         nil,
	} {
		// The payloads name another environment: only the member counts.
		receipt, err := verifier.VerifyReceipt(`{"verified":true,"payload":{"receipt_type":"Xcode"},"environment":` + member + `}`)
		if err != nil || !reflect.DeepEqual(receipt.Environment, want) {
			t.Errorf("receipt, %s: %v, %v", member, receipt, err)
		}
		signed, err := verifier.VerifySignedData(`{"verified":true,"payload":"{\"environment\":\"Xcode\"}","environment":` + member + `}`)
		if err != nil || !reflect.DeepEqual(signed.Environment(), want) {
			t.Errorf("JWS, %s: %v, %v", member, signed, err)
		}
	}
}

func quote(s string) string {
	// json.Marshal would rewrite the escapes; the module's output is
	// arbitrary text, so quote by hand.
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func TestAVerificationFailureKeepsTheModulesReasonAndMessage(t *testing.T) {
	verifier := mirrorVerifier(t, nil)
	for _, reason := range applereceipt.AllReasons() {
		answer := `{"verified":false,"reason":"` + string(reason) + `","message":"why: ` + string(reason) + `"}`
		_, err := verifier.VerifyReceipt(answer)
		requireReason(t, err, reason)
		requireMessage(t, err, "why: "+string(reason))
		var failure *applereceipt.Failure
		if !errors.As(err, &failure) || failure.Cause != nil {
			t.Errorf("%s: a verdict of the module has a cause: %+v", reason, failure)
		}
		_, err = verifier.VerifySignedData(answer)
		requireReason(t, err, reason)
	}
}

func TestAnAnswerThatIsNotTheWireIsInternalErrorNeverAGuess(t *testing.T) {
	verifier := mirrorVerifier(t, nil)
	answers := map[string]string{
		"not JSON":                        `verified`,
		"empty":                           ``,
		"an empty object":                 `{}`,
		"an array":                        `[]`,
		"a scalar":                        `true`,
		"content after the result":        `{"verified":false,"reason":"MALFORMED","message":""} {}`,
		"verified without a payload":      `{"verified":true,"environment":null}`,
		"verified with a reason":          `{"verified":true,"payload":{},"environment":null,"reason":"MALFORMED"}`,
		"verified without an environment": `{"verified":true,"payload":{}}`,
		"an environment outside the two":  `{"verified":true,"payload":{},"environment":"Xcode"}`,
		"a lowercase environment":         `{"verified":true,"payload":{},"environment":"sandbox"}`,
		"an environment that is a number": `{"verified":true,"payload":{},"environment":1}`,
		"failed without a reason":         `{"verified":false,"message":"x"}`,
		"failed with a payload":           `{"verified":false,"reason":"MALFORMED","payload":{}}`,
		"failed with an environment":      `{"verified":false,"reason":"MALFORMED","message":"x","environment":null}`,
		"a reason outside the eight":      `{"verified":false,"reason":"INVALID_RECEIPT_FORMAT","message":"x"}`,
		"a lowercase reason":              `{"verified":false,"reason":"malformed","message":"x"}`,
		"an unknown member":               `{"verified":true,"payload":{},"environment":null,"payloadJson":"{}"}`,
		"a payload with an unknown key":   `{"verified":true,"payload":{"appItemId":0},"environment":null}`,
		"an id that is not decimal":       `{"verified":true,"payload":{"app_item_id":"0x10"},"environment":null}`,
		"an id that overflows int64":      `{"verified":true,"payload":{"download_id":"9223372036854775808"},"environment":null}`,
		"an id as a number":               `{"verified":true,"payload":{"app_item_id":5},"environment":null}`,
		"an in-app id that is not text":   `{"verified":true,"payload":{"in_app":[{"web_order_line_item_id":"x"}]},"environment":null}`,
		"unknown attributes, bad key":     `{"verified":true,"payload":{"unknown_attributes":{"a":[]}},"environment":null}`,
		"unknown attributes, bad value":   `{"verified":true,"payload":{"unknown_attributes":{"1":["***"]}},"environment":null}`,
		"bytes that are not base64":       `{"verified":true,"payload":{"opaque_value":"***"},"environment":null}`,
		"a date as a string":              `{"verified":true,"payload":{"receipt_creation_date_ms":"1"},"environment":null}`,
		"a payload that is not an object": `{"verified":true,"payload":[],"environment":null}`,
		"an answer that is not UTF-8":     "{\"verified\":false,\"reason\":\"MALFORMED\",\"message\":\"\xff\"}",
	}
	for name, answer := range answers {
		payload, err := verifier.VerifyReceipt(answer)
		if payload != nil || err == nil {
			t.Errorf("%s: verified", name)
			continue
		}
		requireReason(t, err, applereceipt.ReasonInternalError)
		var failure *applereceipt.Failure
		var trap *host.TrapError
		if !errors.As(err, &failure) || failure.Cause == nil || errors.As(failure.Cause, &trap) {
			t.Errorf("%s: the cause should describe the unusable answer, not a trap: %+v", name, failure)
		}
		if strings.Contains(err.Error(), "appItemId") || strings.Contains(err.Error(), "\xff") {
			t.Errorf("%s: the failure message quotes the answer: %v", name, err)
		}
	}
	// The signed-data payload must be a JSON string.
	for name, answer := range map[string]string{
		"an object payload":       `{"verified":true,"payload":{},"environment":null}`,
		"a null payload":          `{"verified":true,"payload":null,"environment":null}`,
		"a number payload":        `{"verified":true,"payload":1,"environment":null}`,
		"no environment":          `{"verified":true,"payload":"{}"}`,
		"an environment of Xcode": `{"verified":true,"payload":"{}","environment":"Xcode"}`,
	} {
		payload, err := verifier.VerifySignedData(answer)
		if payload != nil {
			t.Errorf("%s: verified", name)
		}
		requireReason(t, err, applereceipt.ReasonInternalError)
	}
	// And the endpoint's answer must be JSON text.
	for name, answer := range map[string]string{"not JSON": `status`, "empty": ``, "not UTF-8": "{\"status\":\"\xff\"}"} {
		if got := verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentProduction, answer); got != `{"status":21009}` {
			t.Errorf("endpoint, %s: %q, want status 21009", name, got)
		}
	}
}

func TestTheEndpointAnswerPassesThroughByteForByte(t *testing.T) {
	verifier := mirrorVerifier(t, nil)
	answer := "{\"status\": 0,\n  \"environment\":\"Sandbox\",\"receipt\":{\"quantity\":1.0,\"id\":\"\\u00e9\"} }\n"
	for _, environment := range []applereceipt.Environment{applereceipt.EnvironmentProduction, applereceipt.EnvironmentSandbox} {
		if got := verifier.VerifyReceiptEndpoint(environment, answer); got != answer {
			t.Errorf("%s: %q, want %q", environment, got, answer)
		}
	}
}

func TestAnEnvironmentOtherThanTheTwoIsStatus21009(t *testing.T) {
	verifier := mirrorVerifier(t, nil)
	for _, environment := range []applereceipt.Environment{"", "Xcode", "production", "LocalTesting"} {
		if got := verifier.VerifyReceiptEndpoint(environment, `{"status":0}`); got != `{"status":21009}` {
			t.Errorf("environment %q: %q, want status 21009", environment, got)
		}
	}
}

func TestATrapIsInternalErrorAndTheVerifierKeepsAnswering(t *testing.T) {
	verifier := mirrorVerifier(t, nil)
	// The double traps on an input that starts with '!'.
	for i := 0; i < 3; i++ {
		_, err := verifier.VerifyReceipt("!boom")
		requireReason(t, err, applereceipt.ReasonInternalError)
		requireMessage(t, err, "trapped")
		var trap *host.TrapError
		if !errors.As(err, &trap) {
			t.Fatalf("the failure's cause is not a trap: %v", err)
		}
		if _, err := verifier.VerifySignedData("!boom"); !errors.As(err, &trap) {
			t.Fatalf("signed data: the failure's cause is not a trap: %v", err)
		}
		if got := verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentProduction, "!boom"); got != `{"status":21009}` {
			t.Fatalf("endpoint after a trap: %q", got)
		}
		// The instance that trapped is gone; the next call gets another.
		if _, err := verifier.VerifyReceipt(`{"verified":true,"payload":{},"environment":null}`); err != nil {
			t.Fatalf("after a trap: %v", err)
		}
	}
}

func TestTheClockIsReadOnceBeforeTheInputEveryCall(t *testing.T) {
	var reads atomic.Int64
	config := applereceipt.NewConfig(applereceipt.ConfigOptions{Clock: func() int64 {
		reads.Add(1)
		return 1_722_945_600_000
	}})
	verifier := mirrorVerifier(t, config)
	answers := []string{`{"verified":true,"payload":{},"environment":null}`, `{"verified":false,"reason":"MALFORMED","message":""}`, "!trap", ""}
	for i, input := range answers {
		verifier.VerifyReceipt(input)
		verifier.VerifySignedData(input)
		verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, input)
		if got := reads.Load(); got != int64(3*(i+1)) {
			t.Fatalf("after %d calls the clock was read %d times, want once per call", 3*(i+1), got)
		}
	}
}

func TestAClockThatBreaksIsInternalErrorWhateverTheInput(t *testing.T) {
	// The input would trap the double; the clock is read first, so the
	// verdict is the clock's.
	for name, clock := range map[string]func() int64{
		"panics":           func() int64 { panic("no clock today") },
		"panics with nil":  func() int64 { panic(nil) },
		"before 1970":      func() int64 { return -1 },
		"before 1970, far": func() int64 { return -1 << 62 },
	} {
		verifier := mirrorVerifier(t, applereceipt.NewConfig(applereceipt.ConfigOptions{Clock: clock}))
		_, err := verifier.VerifyReceipt("!trap")
		requireReason(t, err, applereceipt.ReasonInternalError)
		if strings.Contains(err.Error(), "trapped") || !strings.Contains(err.Error(), "clock") {
			t.Errorf("%s: %v", name, err)
		}
		_, err = verifier.VerifySignedData("!trap")
		requireReason(t, err, applereceipt.ReasonInternalError)
		if got := verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentProduction, "!trap"); got != `{"status":21009}` {
			t.Errorf("%s: endpoint %q", name, got)
		}
	}
}

func TestTheDefaultRootsAreAnEmptyListAndCustomRootsAreTheirDER(t *testing.T) {
	// The double refuses an init configuration over 100 bytes: three roots,
	// or one, are far over; {"roots":[]} is 12.
	if _, err := applereceipt.NewVerifierOverModule(applereceipt.DefaultConfig(), mirrorModule(t)); err != nil {
		t.Fatalf("the default Config was refused: %v", err)
	}
	explicit := applereceipt.NewConfig(applereceipt.ConfigOptions{Roots: []*x509.Certificate{parseFixtureCertificate(t, "jws-root")}})
	_, err := applereceipt.NewVerifierOverModule(explicit, mirrorModule(t))
	if err == nil || !strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), "the double refuses") {
		t.Fatalf("a Config with explicit roots reached init as an empty list: %v", err)
	}
	var plain *applereceipt.Failure
	if errors.As(err, &plain) {
		t.Error("a configuration refusal is a *Failure, not a plain error")
	}
}

func TestMisuseIsAPlainErrorAtCreate(t *testing.T) {
	for name, config := range map[string]*applereceipt.Config{
		"a nil Config":         nil,
		"an empty root set":    applereceipt.NewConfig(applereceipt.ConfigOptions{Roots: []*x509.Certificate{}}),
		"a nil root":           applereceipt.NewConfig(applereceipt.ConfigOptions{Roots: []*x509.Certificate{nil}}),
		"a root with no bytes": applereceipt.NewConfig(applereceipt.ConfigOptions{Roots: []*x509.Certificate{{}}}),
		"a root that is junk":  applereceipt.NewConfig(applereceipt.ConfigOptions{Roots: []*x509.Certificate{{Raw: []byte("not a certificate")}}}),
	} {
		verifier, err := applereceipt.NewVerifier(config)
		if err == nil || verifier != nil {
			t.Errorf("%s: created a Verifier", name)
			continue
		}
		if _, isFailure := applereceipt.ReasonOf(err); isFailure {
			t.Errorf("%s: a verdict, not a programming error: %v", name, err)
		}
	}
}

// a module that is not aprv:verifier@0.1.0: it exports the init of 0.9.0
// and a cabi_realloc, nothing else.
var wrongVersionModule = mustHex("0061736d01000000010f0260027f7f017f60047f7f7f7f017f03030200010503010001073b03066d656d6f727902001f617072763a76657269666965722f76657269667940302e392e3023696e697400000c636162695f7265616c6c6f6300010a0b02040041000b040041000b")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestAModuleOfAnotherABIVersionFailsCreateNamingTheVersion(t *testing.T) {
	verifier, err := applereceipt.NewVerifierOverModule(applereceipt.DefaultConfig(), wrongVersionModule)
	if err == nil || verifier != nil {
		t.Fatal("created a Verifier over a module of another ABI version")
	}
	for _, want := range []string{"aprv:verifier@0.1.0", "aprv:verifier/verify@0.9.0#init"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %q: %v", want, err)
		}
	}
	if _, isFailure := applereceipt.ReasonOf(err); isFailure {
		t.Errorf("an ABI mismatch is a verdict: %v", err)
	}
}

func TestAVerifierNotMadeByNewVerifierAnswersInternalErrorNotAPanic(t *testing.T) {
	var verifier applereceipt.Verifier
	_, err := verifier.VerifyReceipt("x")
	requireReason(t, err, applereceipt.ReasonInternalError)
	_, err = verifier.VerifySignedData("x")
	requireReason(t, err, applereceipt.ReasonInternalError)
	if got := verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentProduction, "x"); got != `{"status":21009}` {
		t.Errorf("endpoint: %q", got)
	}
}

func TestTheEmbeddedModuleIsBoundAndAnswersTheEmptyInputsAsValues(t *testing.T) {
	// Not a verdict test: the real module is created and every entry point
	// answers something for the smallest inputs without an error escaping.
	verifier, err := applereceipt.NewVerifier(applereceipt.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := verifier.VerifyReceipt(""); payload != nil || err == nil {
		t.Errorf("an empty receipt verified: %v", err)
	}
	if payload, err := verifier.VerifySignedData(""); payload != nil || err == nil {
		t.Errorf("an empty JWS verified: %v", err)
	}
	if got := verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentProduction, ""); !strings.Contains(got, `"status":`) {
		t.Errorf("an empty endpoint body: %q", got)
	}
}

func TestAHandBuiltJSONPayloadStatesTheEnvironmentItIsGiven(t *testing.T) {
	sandbox := applereceipt.EnvironmentSandbox
	payload := applereceipt.NewJSONPayload(`{"environment":"Production"}`, &sandbox)
	sandbox = applereceipt.EnvironmentProduction
	if environment := payload.Environment(); environment == nil || *environment != applereceipt.EnvironmentSandbox {
		t.Fatalf("environment %v, want the Sandbox it was given", environment)
	}
	*payload.Environment() = applereceipt.EnvironmentProduction
	if *payload.Environment() != applereceipt.EnvironmentSandbox {
		t.Fatal("a caller changed the payload through the pointer Environment returned")
	}
	if applereceipt.NewJSONPayload(`{"environment":"Sandbox"}`, nil).Environment() != nil {
		t.Fatal("nothing reads the environment from the JSON")
	}
}
