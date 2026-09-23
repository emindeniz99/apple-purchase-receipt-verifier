package applereceipt_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
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
// decoding, CMS parsing and JSON parsing all allocate in
// proportion to their input, and none of that work sits behind a
// signature check. Each cap is pinned three ways: one unit over is refused
// by the cap itself (its own message, and an allocation far below what the
// skipped step would have cost), exactly at the cap is not refused by the
// cap, and the exact output a caller sees.

// capAllocationBudget is what a refusal may allocate. Each skipped step
// would allocate at least a large fraction of its input, and every input
// here is at least 256 KiB.
const capAllocationBudget = 64 << 10

// The request and receipt caps are Apple's: its verifyReceipt answers a
// 3,145,728-byte request body and refuses a 3,145,729-byte one with HTTP
// 413 (measured 2026-09-23), and no receipt it accepts can be larger than
// the body that carries it. fixtures/cases.json holds every port to them.
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

func requireMessage(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %q, got no error", want)
	}
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

// requireRefusal21002 pins everything a caller of the endpoint sees for a
// refusal: status, reason, message and the rendered body byte for byte.
func requireRefusal21002(t *testing.T, result *applereceipt.VerifyReceiptResult,
	reason applereceipt.Reason, message string) {
	t.Helper()
	if result.Status() != applereceipt.StatusMalformed || result.Reason() != reason {
		t.Fatalf("status %d reason %s, want 21002 %s (%v)", result.Status(), result.Reason(), reason, result.Err())
	}
	requireMessage(t, result.Err(), message)
	if got := string(result.JSON()); got != `{"status":21002}` {
		t.Fatalf("body = %s, want {\"status\":21002}", got)
	}
}

func requireVerifiedBody(t *testing.T, result *applereceipt.VerifyReceiptResult) {
	t.Helper()
	if result.Status() != applereceipt.StatusOK {
		t.Fatalf("status %d reason %s (%v), want 0", result.Status(), result.Reason(), result.Err())
	}
}

// padToLength appends newlines to place a genuine receipt's string one past
// the cap. receipt-data is canonical base64 only, so such a string is
// refused with or without the cap; the message shows which one answered.
func padToLength(encoded string, length int) string {
	return encoded + strings.Repeat("\n", length-len(encoded))
}

// --- receipt base64 string: 3 MiB, before the decode ---------------------

func TestReceiptBase64CapIsCheckedBeforeDecoding(t *testing.T) {
	pki := newReceiptPKI(t)
	verifier := receiptVerifier(t, pki, "com.example.app")
	endpoint := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, fixedClock)
	genuine := receiptOfType(t, pki, "ProductionSandbox")

	// Canonical base64 admits nothing around the data, so the string at the
	// cap is a genuine receipt whose base64 is exactly the cap: 3/4 of it
	// in DER, no padding.
	atCap := base64.StdEncoding.EncodeToString(receiptOfSize(t, pki, applereceipt.MaxReceiptBytes/4*3))
	if len(atCap) != applereceipt.MaxReceiptBytes {
		t.Fatalf("built a %d-character receipt string, want %d", len(atCap), applereceipt.MaxReceiptBytes)
	}
	if _, err := verifier.VerifyBase64(atCap); err != nil {
		t.Fatalf("a receipt string of exactly the cap was refused: %v", err)
	}
	if _, err := verifier.VerifyBase64WithDeviceGUID(atCap, nil); err == nil ||
		strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("at the cap the device check, not the cap, must answer: %v", err)
	}
	requireVerifiedBody(t, endpoint.VerifyReceiptData(atCap))

	// One over, and made of valid base64 so that a decode, had it run,
	// would have allocated 2.25 MiB.
	overCap := strings.Repeat("QUFB", applereceipt.MaxReceiptBytes/4) + "Q"
	const message = "INVALID_RECEIPT_FORMAT: receipt base64 exceeds the 3145728 byte limit"
	for _, entry := range []struct {
		name string
		call func() error
	}{
		{"VerifyBase64", func() error { _, err := verifier.VerifyBase64(overCap); return err }},
		{"VerifyBase64WithDeviceGUID", func() error {
			_, err := verifier.VerifyBase64WithDeviceGUID(overCap, []byte("guid"))
			return err
		}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			var err error
			allocated := allocatedBy(func() { err = entry.call() })
			requireReason(t, err, applereceipt.ReasonInvalidReceiptFormat)
			requireMessage(t, err, message)
			if allocated > capAllocationBudget {
				t.Errorf("refusing an over-cap string allocated %d bytes; the decode ran", allocated)
			}
		})
	}

	// A genuine receipt padded one character past the cap: the message
	// shows the cap answered, not the decode that would refuse the padding.
	_, err := verifier.VerifyBase64(padToLength(genuine, applereceipt.MaxReceiptBytes+1))
	requireMessage(t, err, message)

	var result *applereceipt.VerifyReceiptResult
	allocated := allocatedBy(func() { result = endpoint.VerifyReceiptData(overCap) })
	requireRefusal21002(t, result, applereceipt.ReasonInvalidReceiptFormat, message)
	if allocated > capAllocationBudget {
		t.Errorf("the endpoint allocated %d bytes refusing an over-cap receipt-data", allocated)
	}
}

// --- receipt DER: 3 MiB, before the CMS parse ----------------------------

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

func TestReceiptDERCapIsCheckedBeforeParsing(t *testing.T) {
	pki := newReceiptPKI(t)
	verifier := receiptVerifier(t, pki, "com.example.app")

	atCap := receiptOfSize(t, pki, applereceipt.MaxReceiptBytes)
	if _, err := verifier.Verify(atCap); err != nil {
		t.Fatalf("a genuine receipt of exactly the cap was refused: %v", err)
	}
	if _, err := applereceipt.VerifyReceiptCore(atCap, pki.anchors()); err != nil {
		t.Fatalf("VerifyReceiptCore refused a genuine receipt of exactly the cap: %v", err)
	}

	// Genuine in every respect but its size, so only the cap can refuse it.
	overCap := receiptOfSize(t, pki, applereceipt.MaxReceiptBytes+1)
	const message = "INVALID_RECEIPT_FORMAT: receipt exceeds the 3145728 byte limit"
	for _, entry := range []struct {
		name string
		call func() error
	}{
		{"Verify", func() error { _, err := verifier.Verify(overCap); return err }},
		{"VerifyWithDeviceGUID", func() error {
			_, err := verifier.VerifyWithDeviceGUID(overCap, []byte("guid"))
			return err
		}},
		{"VerifyReceiptCore", func() error {
			_, err := applereceipt.VerifyReceiptCore(overCap, pki.anchors())
			return err
		}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			var err error
			allocated := allocatedBy(func() { err = entry.call() })
			requireReason(t, err, applereceipt.ReasonInvalidReceiptFormat)
			requireMessage(t, err, message)
			if allocated > capAllocationBudget {
				t.Errorf("refusing an over-cap receipt allocated %d bytes; the parse ran", allocated)
			}
		})
	}
}

// --- request body: 3 MiB, before the JSON parse --------------------------

// bodyOfLength wraps receipt-data in a request body of exactly length
// bytes, padded with JSON whitespace.
func bodyOfLength(receiptData string, length int) []byte {
	head := `{"receipt-data":"` + receiptData + `"`
	return []byte(head + strings.Repeat(" ", length-len(head)-1) + "}")
}

func TestRequestBodyCapIsCheckedBeforeParsing(t *testing.T) {
	pki := newReceiptPKI(t)
	endpoint := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, fixedClock)
	genuine := receiptOfType(t, pki, "ProductionSandbox")

	atCap := bodyOfLength(genuine, applereceipt.MaxRequestBytes)
	requireVerifiedBody(t, endpoint.VerifyReceiptBody(atCap))

	overCap := bodyOfLength(genuine, applereceipt.MaxRequestBytes+1)
	var result *applereceipt.VerifyReceiptResult
	allocated := allocatedBy(func() { result = endpoint.VerifyReceiptBody(overCap) })
	requireRefusal21002(t, result, applereceipt.ReasonRequestTooLarge,
		"REQUEST_TOO_LARGE: the request body exceeds the 3145728 byte limit")
	if allocated > capAllocationBudget {
		t.Errorf("refusing an over-cap body allocated %d bytes; the JSON parse ran", allocated)
	}
	if got := string(endpoint.VerifyReceiptJSON(overCap)); got != `{"status":21002}` {
		t.Fatalf("VerifyReceiptJSON = %s, want {\"status\":21002}", got)
	}

	// The size is decided first: a body over the cap that is also nested
	// too deep and not JSON at all is still REQUEST_TOO_LARGE, the answer
	// Apple gives (413) before it reads anything.
	junk := []byte(strings.Repeat("[", applereceipt.MaxRequestBytes+1))
	requireRefusal21002(t, endpoint.VerifyReceiptBody(junk), applereceipt.ReasonRequestTooLarge,
		"REQUEST_TOO_LARGE: the request body exceeds the 3145728 byte limit")
}

// twoBytePadding is exactly n bytes of U+00E9 (two bytes each in UTF-8),
// with one ASCII character when n is odd.
func twoBytePadding(n int) string {
	pad := strings.Repeat("\u00e9", n/2)
	if n%2 == 1 {
		pad += "a"
	}
	return pad
}

// Apple's limit counts UTF-8 bytes, not characters. A body padded with
// U+00E9 to one byte over the cap is barely half the cap in characters, so
// a character count would let it through; the same shape one byte shorter
// verifies. The padding sits in password, which is accepted and never read.
func TestRequestBodyIsMeasuredInUTF8BytesNotCharacters(t *testing.T) {
	pki := newReceiptPKI(t)
	endpoint := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, fixedClock)
	genuine := receiptOfType(t, pki, "ProductionSandbox")
	limit := applereceipt.MaxRequestBytes
	bodyWith := func(padding string) []byte {
		return []byte(`{"receipt-data":"` + genuine + `","password":"` + padding + `"}`)
	}
	fixed := len(bodyWith(""))

	over := bodyWith(twoBytePadding(limit + 1 - fixed))
	if len(over) != limit+1 {
		t.Fatalf("built a %d byte body, want %d", len(over), limit+1)
	}
	if chars := utf8.RuneCount(over); chars >= limit/2+fixed {
		t.Fatalf("the over-cap body is %d characters; a character count must call it far under the cap", chars)
	}
	requireRefusal21002(t, endpoint.VerifyReceiptBody(over), applereceipt.ReasonRequestTooLarge,
		"REQUEST_TOO_LARGE: the request body exceeds the 3145728 byte limit")

	at := bodyWith(twoBytePadding(limit - fixed))
	if len(at) != limit {
		t.Fatalf("built a %d byte body, want %d", len(at), limit)
	}
	requireVerifiedBody(t, endpoint.VerifyReceiptBody(at))
}

// --- request body nesting: 64, counted before the JSON parse ------------

func nested(depth int) string {
	return strings.Repeat("[", depth) + strings.Repeat("]", depth)
}

func TestRequestBodyNestingIsCountedBeforeParsing(t *testing.T) {
	pki := newReceiptPKI(t)
	endpoint := endpointFor(t, pki.anchors(), applereceipt.EnvironmentSandbox, fixedClock)
	genuine := receiptOfType(t, pki, "ProductionSandbox")
	body := func(prefix string) []byte {
		return []byte(`{` + prefix + `"receipt-data":"` + genuine + `"}`)
	}
	const message = "MALFORMED_REQUEST: the request body nests deeper than 64 levels"

	// The body object is one level, so 63 arrays inside it is exactly 64.
	requireVerifiedBody(t, endpoint.VerifyReceiptBody(body(`"pad":`+nested(63)+`,`)))
	requireRefusal21002(t, endpoint.VerifyReceiptBody(body(`"pad":`+nested(64)+`,`)),
		applereceipt.ReasonMalformedRequest, message)

	// Brackets inside a string are data. An escaped backslash ends before
	// the closing quote, so the brackets after that string DO count.
	requireVerifiedBody(t, endpoint.VerifyReceiptBody(body(`"pad":"\"`+strings.Repeat("[", 1000)+`",`)))
	requireRefusal21002(t, endpoint.VerifyReceiptBody(body(`"a":"\\","pad":`+nested(64)+`,`)),
		applereceipt.ReasonMalformedRequest, message)

	// A body nested far past what encoding/json would still accept is
	// refused in one pass without the parser allocating per level.
	deep := body(`"pad":` + nested(200000) + `,`)
	var result *applereceipt.VerifyReceiptResult
	allocated := allocatedBy(func() { result = endpoint.VerifyReceiptBody(deep) })
	requireRefusal21002(t, result, applereceipt.ReasonMalformedRequest, message)
	if allocated > capAllocationBudget {
		t.Errorf("refusing a deeply nested body allocated %d bytes; the JSON parse ran", allocated)
	}
}

// --- the byte-floor fixture ----------------------------------------------

// The normative floor receipt (1 MiB of DER) must verify through every
// verifier entry point. Its base64 is about 1.38 MB, so its JSON body is
// well under the 3 MiB request cap and the body path verifies it too.
func TestByteFloorReceiptVerifiesThroughEveryEntryPoint(t *testing.T) {
	var config caseConfig
	for _, kase := range mustCases(t).Cases {
		if kase.ID == "receipt/verify-at-the-byte-floor" {
			config = kase.Config
		}
	}
	if config.BundleID == nil {
		t.Fatal("receipt/verify-at-the-byte-floor is missing from fixtures/cases.json")
	}
	roots := trustedRootsFor(t, config.TrustedRoots)
	der := fixtureBytes(t, "receipt-byte-floor")
	encoded := base64.StdEncoding.EncodeToString(der)

	verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
		TrustedRoots: roots, BundleID: *config.BundleID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(der); err != nil {
		t.Fatalf("Verify refused the byte floor: %v", err)
	}
	if _, err := verifier.VerifyBase64(encoded); err != nil {
		t.Fatalf("VerifyBase64 refused the byte floor: %v", err)
	}

	endpoint := endpointFor(t, roots, applereceipt.EnvironmentSandbox, fixedClock)
	if status := endpoint.VerifyReceiptData(encoded).Status(); status == applereceipt.StatusMalformed {
		t.Fatalf("VerifyReceiptData answered 21002 for the byte floor")
	}
	body, err := json.Marshal(map[string]string{"receipt-data": encoded})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > applereceipt.MaxRequestBytes {
		t.Fatalf("the byte floor's body is %d bytes, over the request cap", len(body))
	}
	if status := endpoint.VerifyReceiptBody(body).Status(); status == applereceipt.StatusMalformed {
		t.Fatalf("VerifyReceiptBody answered 21002 for the byte floor")
	}
}

// --- JWS: 256 KiB before any split, and 64 levels before each parse -----

func signRawJWS(t *testing.T, p jwsPKI, header, payload []byte) string {
	t.Helper()
	headerB64 := base64.RawURLEncoding.EncodeToString(header)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	key, ok := p.leaf.key.(*ecdsa.PrivateKey)
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
			jws := signRawJWS(t, p, header, payload)
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
	verifier := jwsVerifierFor(t, pki.anchorSlice(), nil)

	if _, err := verifier.VerifyRaw(signedJWSOfLength(t, pki, applereceipt.MaxJWSBytes)); err != nil {
		t.Fatalf("a genuine JWS of exactly the cap was refused: %v", err)
	}

	const message = "INVALID_JWS_FORMAT: jws exceeds the 262144 byte limit"
	_, err := verifier.VerifyRaw(signedJWSOfLength(t, pki, applereceipt.MaxJWSBytes+1))
	requireReason(t, err, applereceipt.ReasonInvalidJWSFormat)
	requireMessage(t, err, message)

	// All dots: a split, had it run, would have answered "got 262146
	// segments" and allocated one string header per segment (4 MiB).
	dots := strings.Repeat(".", applereceipt.MaxJWSBytes+1)
	for _, entry := range []struct {
		name string
		call func() error
	}{
		{"VerifyRaw", func() error { _, err := verifier.VerifyRaw(dots); return err }},
		{"VerifyTransaction", func() error { _, err := verifier.VerifyTransaction(dots); return err }},
		{"VerifyAppTransaction", func() error { _, err := verifier.VerifyAppTransaction(dots); return err }},
	} {
		t.Run(entry.name, func(t *testing.T) {
			var err error
			allocated := allocatedBy(func() { err = entry.call() })
			requireMessage(t, err, message)
			if allocated > capAllocationBudget {
				t.Errorf("refusing an over-cap JWS allocated %d bytes; the split ran", allocated)
			}
		})
	}
}

func TestJWSNestingIsCountedBeforeParsing(t *testing.T) {
	pki := newJWSPKI(t)
	verifier := jwsVerifierFor(t, pki.anchorSlice(), nil)
	genuineHeader := jwsHeaderJSON(t, pki, "")
	genuinePayload := jwsPayloadJSON(t, "")

	// The object is one level, so 63 arrays inside it is exactly 64; each
	// JWS is genuinely signed, so at 64 it must verify outright.
	for _, entry := range []struct {
		name            string
		header, payload func(depth int) []byte
		message         string
	}{
		{
			"header",
			func(depth int) []byte { return jwsHeaderJSON(t, pki, `"pad":`+nested(depth)+`,`) },
			func(int) []byte { return genuinePayload },
			"INVALID_JWS_FORMAT: header nests deeper than 64 levels",
		},
		{
			"payload",
			func(int) []byte { return genuineHeader },
			func(depth int) []byte { return jwsPayloadJSON(t, `"pad":`+nested(depth)+`,`) },
			"INVALID_JWS_FORMAT: payload nests deeper than 64 levels",
		},
	} {
		t.Run(entry.name, func(t *testing.T) {
			if _, err := verifier.VerifyRaw(signRawJWS(t, pki, entry.header(63), entry.payload(63))); err != nil {
				t.Fatalf("a genuine JWS nested exactly 64 deep was refused: %v", err)
			}
			_, err := verifier.VerifyRaw(signRawJWS(t, pki, entry.header(64), entry.payload(64)))
			requireReason(t, err, applereceipt.ReasonInvalidJWSFormat)
			requireMessage(t, err, entry.message)

			// Deep enough that encoding/json would allocate visibly per
			// level, and still under the size cap.
			deep := signRawJWS(t, pki, entry.header(90000), entry.payload(90000))
			allocated := allocatedBy(func() { _, err = verifier.VerifyRaw(deep) })
			requireMessage(t, err, entry.message)
			// The base64url decode of the deep segment itself is paid (the
			// counter reads decoded JSON); only the parse must be skipped.
			if budget := uint64(len(deep)) + capAllocationBudget; allocated > budget {
				t.Errorf("refusing a deeply nested %s allocated %d bytes; the JSON parse ran", entry.name, allocated)
			}
		})
	}
}
