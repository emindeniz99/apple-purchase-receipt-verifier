package applereceipt_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// Every input this library decodes or parses is capped BEFORE the
// expensive step, with the same fixed numbers every port uses: base64
// decoding, CMS parsing and JSON parsing all allocate in proportion to
// their input, and none of that work sits behind a signature check. Each
// cap is pinned three ways: one unit over is refused by the cap itself
// (its own message, and an allocation far below what the skipped step
// would have cost), exactly at the cap is not refused by the cap, and the
// exact output a caller sees.
//
// The resource-bounds shared cases (fixtures/cases-0.7.json, run by
// conformance_test.go) additionally pin the byte-floor and node-floor
// receipts end to end; this file pins the boundary of each numeric cap.

// capAllocationBudget is what a refusal may allocate. Each skipped step
// would allocate at least a large fraction of its input, and every input
// here is at least 256 KiB.
const capAllocationBudget = 64 << 10

// The request and receipt caps are Apple's: its verifyReceipt answers a
// 3,145,728-byte request body and refuses a 3,145,729-byte one with HTTP
// 413 (measured 2026-09-23), and no receipt it accepts can be larger than
// the body that carries it. fixtures/cases-0.7.schema.json holds every
// port to them.
func TestCapNumbersMatchTheOtherPorts(t *testing.T) {
	for _, entry := range []struct {
		name      string
		got, want int
	}{
		{"MaxReceiptBytes", applereceipt.MaxReceiptBytes, 3145728},
		{"MaxRequestBytes", applereceipt.MaxRequestBytes, 3145728},
		{"MaxJWSBytes", applereceipt.MaxJWSBytes, 262144},
		{"MaxJSONNestingDepth", applereceipt.MaxJSONNestingDepth, 64},
	} {
		if entry.got != entry.want {
			t.Errorf("%s = %d, want %d (the number every port uses)", entry.name, entry.got, entry.want)
		}
	}
}

// requireEndpointStatus checks the parsed status field: a StatusOK
// response carries a full receipt body, so this cannot be exact string
// equality the way a failure's `{"status":N}` short form could be.
func requireEndpointStatus(t *testing.T, response string, status int) {
	t.Helper()
	if got := endpointStatus(t, response); got != status {
		t.Fatalf("response = %.120s, want status %d", response, status)
	}
}

// padToLength appends newlines to place a genuine receipt's string one past
// the cap. receipt-data is canonical base64 only, so such a string is
// refused with or without the cap; the message shows which one answered.
func padToLength(encoded string, length int) string {
	return encoded + strings.Repeat("\n", length-len(encoded))
}

// receiptOfSize builds a genuine signed receipt of exactly size bytes by
// growing an unmodelled attribute.
func receiptOfSize(t *testing.T, pki receiptPKI, size int) []byte {
	t.Helper()
	base := standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())
	pad := 0
	for i := 0; i < 4; i++ {
		der := pki.receipt(t, append(base[:len(base):len(base)], attr(9999, make([]byte, pad)))...)
		if len(der) == size {
			return der
		}
		pad += size - len(der)
	}
	t.Fatalf("could not build a receipt of exactly %d bytes", size)
	return nil
}

// --- receipt base64 string: 3 MiB, before the decode ---------------------

func TestReceiptBase64CapIsCheckedBeforeDecoding(t *testing.T) {
	pki := newReceiptPKI(t)
	verifier := verifierFor(t, pki.anchors())
	genuine := applereceiptBase64(pki.receipt(t))

	// Canonical base64 admits nothing around the data, so the string at the
	// cap is a genuine receipt whose base64 is exactly the cap: 3/4 of it
	// in DER, no padding.
	atCap := base64.StdEncoding.EncodeToString(receiptOfSize(t, pki, applereceipt.MaxReceiptBytes/4*3))
	if len(atCap) != applereceipt.MaxReceiptBytes {
		t.Fatalf("built a %d-character receipt string, want %d", len(atCap), applereceipt.MaxReceiptBytes)
	}
	if _, err := verifier.VerifyReceipt(atCap); err != nil {
		t.Fatalf("a receipt string of exactly the cap was refused: %v", err)
	}
	// Not exercised through the endpoint here: MaxRequestBytes equals
	// MaxReceiptBytes, so wrapping a receipt-data string at its own cap in
	// `{"receipt-data":"..."}` already exceeds the REQUEST cap on the
	// wrapper bytes alone. TestRequestBodyCapIsCheckedBeforeParsing pins
	// that boundary with a receipt small enough to leave room for it.

	// One over, and made of valid base64 so that a decode, had it run,
	// would have allocated 2.25 MiB.
	overCap := strings.Repeat("QUFB", applereceipt.MaxReceiptBytes/4) + "Q"
	const message = "receipt exceeds the maximum accepted size of 3145728 bytes"
	var err error
	allocated := allocatedBy(func() { _, err = verifier.VerifyReceipt(overCap) })
	requireReason(t, err, applereceipt.ReasonTooLarge)
	requireMessage(t, err, "receipt exceeds the maximum accepted size of 3145728 bytes")
	if allocated > capAllocationBudget {
		t.Errorf("refusing an over-cap string allocated %d bytes; the decode ran", allocated)
	}

	// A genuine receipt padded one character past the cap: the message
	// shows the cap answered, not the decode that would refuse the padding.
	_, err = verifier.VerifyReceipt(padToLength(genuine, applereceipt.MaxReceiptBytes+1))
	requireMessage(t, err, message)

	overCapRequest := `{"receipt-data":"` + overCap + `"}`
	var response string
	allocated = allocatedBy(func() {
		response = verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, overCapRequest)
	})
	requireEndpointStatus(t, response, applereceipt.StatusMalformedReceiptData)
	if allocated > capAllocationBudget {
		t.Errorf("the endpoint allocated %d bytes refusing an over-cap receipt-data", allocated)
	}
}

// --- request body: 3 MiB, before the JSON parse --------------------------

// bodyOfLength wraps receipt-data in a request body of exactly length
// bytes, padded with JSON whitespace.
func bodyOfLength(receiptData string, length int) string {
	head := `{"receipt-data":"` + receiptData + `"`
	return head + strings.Repeat(" ", length-len(head)-1) + "}"
}

func TestRequestBodyCapIsCheckedBeforeParsing(t *testing.T) {
	pki := newReceiptPKI(t)
	verifier := verifierFor(t, pki.anchors())
	genuine := applereceiptBase64(pki.receipt(t))

	atCap := bodyOfLength(genuine, applereceipt.MaxRequestBytes)
	requireEndpointStatus(t,
		verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, atCap), applereceipt.StatusOK)

	overCap := bodyOfLength(genuine, applereceipt.MaxRequestBytes+1)
	var response string
	allocated := allocatedBy(func() {
		response = verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, overCap)
	})
	requireEndpointStatus(t, response, applereceipt.StatusMalformedReceiptData)
	if allocated > capAllocationBudget {
		t.Errorf("refusing an over-cap body allocated %d bytes; the JSON parse ran", allocated)
	}

	// The size is decided first: a body over the cap that is also nested
	// too deep and not JSON at all is still StatusMalformedReceiptData, the
	// answer Apple gives (413) before it reads anything.
	junk := strings.Repeat("[", applereceipt.MaxRequestBytes+1)
	requireEndpointStatus(t,
		verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, junk), applereceipt.StatusMalformedReceiptData)
}

// twoBytePadding is exactly n bytes of U+00E9 (two bytes each in UTF-8),
// with one ASCII character when n is odd.
func twoBytePadding(n int) string {
	pad := strings.Repeat("é", n/2)
	if n%2 == 1 {
		pad += "a"
	}
	return pad
}

// Apple's limit counts UTF-8 bytes, not characters. A body padded with
// U+00E9 to one byte over the cap is barely half the cap in characters, so
// a character count would let it through; the same shape one byte shorter
// verifies. The padding sits in password, which is accepted and never
// read.
func TestRequestBodyIsMeasuredInUTF8BytesNotCharacters(t *testing.T) {
	pki := newReceiptPKI(t)
	verifier := verifierFor(t, pki.anchors())
	genuine := applereceiptBase64(pki.receipt(t))
	limit := applereceipt.MaxRequestBytes
	bodyWith := func(padding string) string {
		return `{"receipt-data":"` + genuine + `","password":"` + padding + `"}`
	}
	fixed := len(bodyWith(""))

	over := bodyWith(twoBytePadding(limit + 1 - fixed))
	if len(over) != limit+1 {
		t.Fatalf("built a %d byte body, want %d", len(over), limit+1)
	}
	if chars := utf8.RuneCountInString(over); chars >= limit/2+fixed {
		t.Fatalf("the over-cap body is %d characters; a character count must call it far under the cap", chars)
	}
	requireEndpointStatus(t,
		verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, over), applereceipt.StatusMalformedReceiptData)

	at := bodyWith(twoBytePadding(limit - fixed))
	if len(at) != limit {
		t.Fatalf("built a %d byte body, want %d", len(at), limit)
	}
	requireEndpointStatus(t,
		verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, at), applereceipt.StatusOK)
}

// --- request body nesting: 64, counted before the JSON parse ------------

func nested(depth int) string {
	return strings.Repeat("[", depth) + strings.Repeat("]", depth)
}

func TestRequestBodyNestingIsCountedBeforeParsing(t *testing.T) {
	pki := newReceiptPKI(t)
	verifier := verifierFor(t, pki.anchors())
	genuine := applereceiptBase64(pki.receipt(t))
	body := func(prefix string) string {
		return `{` + prefix + `"receipt-data":"` + genuine + `"}`
	}

	// The body object is one level, so 63 arrays inside it is exactly 64.
	requireEndpointStatus(t, verifier.VerifyReceiptEndpoint(
		applereceipt.EnvironmentSandbox, body(`"pad":`+nested(63)+`,`)), applereceipt.StatusOK)
	requireEndpointStatus(t, verifier.VerifyReceiptEndpoint(
		applereceipt.EnvironmentSandbox, body(`"pad":`+nested(64)+`,`)), applereceipt.StatusMalformedReceiptData)

	// Brackets inside a string are data. An escaped backslash ends before
	// the closing quote, so the brackets after that string DO count.
	requireEndpointStatus(t, verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox,
		body(`"pad":"\"`+strings.Repeat("[", 1000)+`",`)), applereceipt.StatusOK)
	requireEndpointStatus(t, verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox,
		body(`"a":"\\","pad":`+nested(64)+`,`)), applereceipt.StatusMalformedReceiptData)

	// A body nested far past what encoding/json would still accept is
	// refused in one pass without the parser allocating per level.
	deep := body(`"pad":` + nested(200000) + `,`)
	var response string
	allocated := allocatedBy(func() { response = verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, deep) })
	requireEndpointStatus(t, response, applereceipt.StatusMalformedReceiptData)
	// VerifyReceiptEndpoint takes a string, so one copy into a []byte is
	// unavoidable (proportional to the input) before the nesting scan
	// even starts; the invariant this pins is that nothing beyond that is
	// paid: no per-level allocation from an actual recursive JSON parse.
	if budget := 2*uint64(len(deep)) + capAllocationBudget; allocated > budget {
		t.Errorf("refusing a deeply nested body allocated %d bytes (budget %d); the JSON parse ran", allocated, budget)
	}
}

// --- JWS: 256 KiB before any split, and 64 levels before each parse -----

// jwsHeaderJSON is a genuine header with extra members spliced in.
func jwsHeaderJSON(t *testing.T, p jwsPKI, extra string) []byte {
	t.Helper()
	chain, err := json.Marshal([]string{
		base64.StdEncoding.EncodeToString(p.leaf.der),
		base64.StdEncoding.EncodeToString(p.intermediate.der),
		base64.StdEncoding.EncodeToString(p.root.der),
	})
	if err != nil {
		t.Fatal(err)
	}
	return []byte(`{"alg":"ES256",` + extra + `"x5c":` + string(chain) + `}`)
}

// jwsPayloadJSON is a genuine transaction payload with extra members
// spliced in.
func jwsPayloadJSON(t *testing.T, extra string) []byte {
	t.Helper()
	claims, err := json.Marshal(transactionClaims())
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(`{`+extra), claims[1:]...)
}

// signedJWSOfLength builds a genuine JWS of exactly length characters by
// growing a payload member. Unpadded base64url cannot be 1 mod 4 long, so
// the header is grown by up to three characters until the payload length
// needed is one base64url can have.
func signedJWSOfLength(t *testing.T, p jwsPKI, length int) string {
	t.Helper()
	for headerPad := 0; headerPad < 4; headerPad++ {
		header := jwsHeaderJSON(t, p, `"pad":"`+strings.Repeat("h", headerPad)+`",`)
		want := length - base64.RawURLEncoding.EncodedLen(len(header)) - 2 - 86
		for n := want*3/4 - 2; n <= want*3/4+2; n++ {
			if base64.RawURLEncoding.EncodedLen(n) != want {
				continue
			}
			base := jwsPayloadJSON(t, `"pad":"",`)
			payload := jwsPayloadJSON(t, `"pad":"`+strings.Repeat("p", n-len(base))+`",`)
			jws := signRawJWS(t, p.leaf, header, payload)
			if len(jws) != length {
				t.Fatalf("built a %d character JWS, want %d", len(jws), length)
			}
			return jws
		}
	}
	t.Fatalf("could not build a JWS of exactly %d characters", length)
	return ""
}

func TestJWSSizeCapIsCheckedBeforeSplitting(t *testing.T) {
	pki := newJWSPKI(t)
	verifier := verifierFor(t, pki.anchorSlice())

	if _, err := verifier.VerifySignedData(signedJWSOfLength(t, pki, applereceipt.MaxJWSBytes)); err != nil {
		t.Fatalf("a genuine JWS of exactly the cap was refused: %v", err)
	}

	const message = "jws exceeds the maximum accepted size of 262144 bytes"
	_, err := verifier.VerifySignedData(signedJWSOfLength(t, pki, applereceipt.MaxJWSBytes+1))
	requireReason(t, err, applereceipt.ReasonTooLarge)
	requireMessage(t, err, message)

	// All dots: a split, had it run, would have answered "got 262146
	// segments" and allocated one string header per segment. The size cap
	// is checked first, so it never runs.
	dots := strings.Repeat(".", applereceipt.MaxJWSBytes+1)
	var allocErr error
	allocated := allocatedBy(func() { _, allocErr = verifier.VerifySignedData(dots) })
	requireMessage(t, allocErr, message)
	if allocated > capAllocationBudget {
		t.Errorf("refusing an over-cap JWS allocated %d bytes; the split ran", allocated)
	}
}

// The header's nesting is checked immediately: a header that nests too
// deep is ReasonMalformed before the chain or the signature is ever
// touched.
func TestJWSHeaderNestingIsCountedBeforeParsing(t *testing.T) {
	pki := newJWSPKI(t)
	verifier := verifierFor(t, pki.anchorSlice())
	genuinePayload := jwsPayloadJSON(t, "")
	const message = "header exceeds a JSON bound"

	// 63 arrays inside the header object (one level) is exactly 64; signed
	// genuinely, so it must verify outright.
	shallow := signRawJWS(t, pki.leaf, jwsHeaderJSON(t, pki, `"pad":`+nested(63)+`,`), genuinePayload)
	if _, err := verifier.VerifySignedData(shallow); err != nil {
		t.Fatalf("a genuine JWS nested exactly 64 deep was refused: %v", err)
	}

	deep64 := signRawJWS(t, pki.leaf, jwsHeaderJSON(t, pki, `"pad":`+nested(64)+`,`), genuinePayload)
	_, err := verifier.VerifySignedData(deep64)
	requireReason(t, err, applereceipt.ReasonMalformed)
	requireMessage(t, err, message)

	// Deep enough that encoding/json would allocate visibly per level, and
	// still under the size cap.
	deep := signRawJWS(t, pki.leaf, jwsHeaderJSON(t, pki, `"pad":`+nested(90000)+`,`), genuinePayload)
	var deepErr error
	allocated := allocatedBy(func() { _, deepErr = verifier.VerifySignedData(deep) })
	requireMessage(t, deepErr, message)
	if budget := uint64(len(deep)) + capAllocationBudget; allocated > budget {
		t.Errorf("refusing a deeply nested header allocated %d bytes; the JSON parse ran", allocated)
	}
}

// The payload's nesting is a different shape (owner, 2026-09-27): reading
// it never itself fails verification, so a too-deep payload is carried
// past the chain and signature checks and only surfaces as
// UNREADABLE_PAYLOAD once the signature over it has genuinely verified.
func TestJWSPayloadNestingIsCarriedPastTheSignatureCheck(t *testing.T) {
	pki := newJWSPKI(t)
	verifier := verifierFor(t, pki.anchorSlice())
	genuineHeader := jwsHeaderJSON(t, pki, "")

	shallow := signRawJWS(t, pki.leaf, genuineHeader, jwsPayloadJSON(t, `"pad":`+nested(63)+`,`))
	if _, err := verifier.VerifySignedData(shallow); err != nil {
		t.Fatalf("a genuine JWS nested exactly 64 deep was refused: %v", err)
	}

	deep64 := signRawJWS(t, pki.leaf, genuineHeader, jwsPayloadJSON(t, `"pad":`+nested(64)+`,`))
	_, err := verifier.VerifySignedData(deep64)
	requireReason(t, err, applereceipt.ReasonUnreadablePayload)

	deep := signRawJWS(t, pki.leaf, genuineHeader, jwsPayloadJSON(t, `"pad":`+nested(90000)+`,`))
	var deepErr error
	allocated := allocatedBy(func() { _, deepErr = verifier.VerifySignedData(deep) })
	requireReason(t, deepErr, applereceipt.ReasonUnreadablePayload)
	// A larger multiple than the header case: unlike a too-deep header,
	// reading the payload never itself fails, so the full chain and
	// signature check (proportional to the input: three certificates
	// parsed, a P-256 verify over the whole signing input) runs BEFORE
	// the nesting cap is even consulted. What must still not happen is a
	// per-level allocation from an actual recursive JSON parse.
	if budget := 10*uint64(len(deep)) + capAllocationBudget; allocated > budget {
		t.Errorf("refusing a deeply nested payload allocated %d bytes (budget %d); the JSON parse ran", allocated, budget)
	}
}
