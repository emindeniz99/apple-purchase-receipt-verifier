package applereceipt_test

// Runs every vector in fixtures/cases.json, the normative
// cross-language conformance set for the 0.7 API, through the three
// public Verifier methods. The two base64 decoders have no public entry
// point, so the decodeBase64 groups run through the methods that use them
// (see runDecodeBase64).
//
// This adapter knows nothing about any individual case. It loads the
// file, resolves fixture ids to bytes and checks their recorded digest,
// builds a Config from the case's trusted roots, revocation settings and
// clock, dispatches on operation, and evaluates the expectation on the JSON
// the library returns: ReceiptPayload.ToJSON(), JsonPayload.JSON() or the
// endpoint's response body. buildConfig cases build the Config and a
// Verifier, and check that NewVerifier refuses it or reports the two
// revocation values the case states. The file's top-level comment defines the semantics
// implemented here. There is no skip list, no case count in the source,
// and no per-case fix-up: a vector that disagrees with the library is a
// bug report against one of the two, never something to special-case
// here.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/host"
)

const casesFileName = "cases.json"

// --- the vector file -------------------------------------------------------

type fixtureEntry struct {
	Path          string `json:"path"`
	Role          string `json:"role"`
	Codec         string `json:"codec"`
	ContentSHA256 string `json:"contentSha256"`
}

type trustedRootsSpec struct {
	Source   string   `json:"source"`
	Fixtures []string `json:"fixtures"`
}

// revocationSpec is a config's revocation member: lists and issuers are
// fixture ids (an id may repeat), distrust entries are passed exactly as
// written, malformed ones included.
type revocationSpec struct {
	Lists    []string `json:"lists"`
	Issuers  []string `json:"issuers"`
	Distrust []struct {
		Issuer string `json:"issuer"`
		Serial string `json:"serial"`
	} `json:"distrust"`
}

type caseConfigSpec struct {
	TrustedRoots trustedRootsSpec `json:"trustedRoots"`
	Revocation   *revocationSpec  `json:"revocation"`
	Environment  string           `json:"environment"`
}

type clockSpec struct {
	Now string `json:"now"`
}

type caseInputSpec struct {
	Fixture     string   `json:"fixture"`
	RequestBody string   `json:"requestBody"`
	Texts       []string `json:"texts"`
	// TrustedRoots and Revocation are a buildConfig case's configuration.
	TrustedRoots *trustedRootsSpec `json:"trustedRoots"`
	Revocation   *revocationSpec   `json:"revocation"`
}

type caseExpectedSpec struct {
	Status                string         `json:"status"`
	Reason                string         `json:"reason"`
	MessageMustNotContain []int          `json:"messageMustNotContain"`
	Fields                map[string]any `json:"fields"`
	Lengths               map[string]any `json:"lengths"`
	ToJSON                *string        `json:"toJson"`
	BytesHex              string         `json:"bytesHex"`
	// Environment is what an ok verifyReceipt or verifySignedData result
	// states beside its payload: "Production", "Sandbox" or null. Raw, so
	// a missing member (empty) and null stay apart.
	Environment json.RawMessage `json:"environment"`
	// OneOf marks a port-defined case (owner, 2026-09-27): the outcome,
	// "ok" or the reason, or at the endpoint the response's /status (a
	// json.Number), must be one of these, and the call must not crash. No
	// field is pinned.
	OneOf []any `json:"oneOf"`
	// RevocationURLs and RevocationValidUntil are what an ok buildConfig
	// case reports: the URLs in order, and an instant
	// (YYYY-MM-DDTHH:MM:SSZ) or null, raw so a missing member stays apart.
	RevocationURLs       []string        `json:"revocationUrls"`
	RevocationValidUntil json.RawMessage `json:"revocationValidUntil"`
}

type conformanceCase struct {
	ID          string           `json:"id"`
	LegacyID    string           `json:"legacyId"`
	Description string           `json:"description"`
	Operation   string           `json:"operation"`
	Decoders    []string         `json:"decoders"`
	Input       caseInputSpec    `json:"input"`
	Config      *caseConfigSpec  `json:"config"`
	Clock       *clockSpec       `json:"clock"`
	Expected    caseExpectedSpec `json:"expected"`
	Fault       string           `json:"fault"`
	MaxMillis   *int             `json:"maxMillis"`
	Tags        []string         `json:"tags"`
}

type casesDocument struct {
	Schema        string                  `json:"$schema"`
	SchemaVersion int                     `json:"schemaVersion"`
	Comment       string                  `json:"comment"`
	Fixtures      map[string]fixtureEntry `json:"fixtures"`
	Cases         []conformanceCase       `json:"cases"`
}

// --- locating and decoding fixtures ----------------------------------------

// fixturesDir is APRV_FIXTURES_DIR when set; otherwise it walks up from
// this test's working directory until a fixtures/ directory holding the
// vectors appears, never a hard-coded "../../.." literal, so moving the
// port does not silently point the suite at nothing.
func fixturesDir(t testing.TB) string {
	t.Helper()
	if dir := os.Getenv("APRV_FIXTURES_DIR"); dir != "" {
		return dir
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("harness error: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "fixtures")
		if _, err := os.Stat(filepath.Join(candidate, casesFileName)); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("harness error: no fixtures/%s above the working directory", casesFileName)
		}
		dir = parent
	}
}

func loadCases(t testing.TB) (string, casesDocument) {
	t.Helper()
	dir := fixturesDir(t)
	data, err := os.ReadFile(filepath.Join(dir, casesFileName))
	if err != nil {
		t.Fatalf("harness error: cannot read %s: %v", casesFileName, err)
	}
	var parsed casesDocument
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		t.Fatalf("harness error: cannot parse %s: %v", casesFileName, err)
	}
	if parsed.SchemaVersion != 3 {
		t.Fatalf("harness error: %s is schemaVersion %d, this adapter implements 3",
			casesFileName, parsed.SchemaVersion)
	}
	return dir, parsed
}

func stripWhitespace(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	for _, r := range text {
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// fixtureBytes are the decoded logical bytes of a registered fixture,
// checked against the digest the registry records for them, so fixture
// bytes and the registry cannot drift apart unnoticed.
func fixtureBytesIn(t testing.TB, dir string, fixtures map[string]fixtureEntry, id string) []byte {
	t.Helper()
	entry, ok := fixtures[id]
	if !ok {
		t.Fatalf("harness error: %s registers no fixture %q", casesFileName, id)
	}
	raw, err := os.ReadFile(filepath.Join(dir, entry.Path))
	if err != nil {
		t.Fatalf("harness error: cannot read fixture %q (%s): %v", id, entry.Path, err)
	}
	var bytes []byte
	switch entry.Codec {
	case "raw", "text":
		bytes = raw
	case "base64":
		decoded, derr := base64.StdEncoding.DecodeString(stripWhitespace(string(raw)))
		if derr != nil {
			t.Fatalf("harness error: fixture %q is not valid base64: %v", id, derr)
		}
		bytes = decoded
	case "utf8":
		bytes = []byte(strings.TrimSpace(string(raw)))
	default:
		t.Fatalf("harness error: unknown fixture codec %q on %q", entry.Codec, id)
	}
	sum := sha256.Sum256(bytes)
	if hex.EncodeToString(sum[:]) != entry.ContentSHA256 {
		t.Fatalf("fixture %q (%s, codec %s) has drifted: %s records contentSha256 %s, "+
			"the decoded bytes hash to %s",
			id, entry.Path, entry.Codec, casesFileName, entry.ContentSHA256, hex.EncodeToString(sum[:]))
	}
	return bytes
}

// checkWholeRegistry proves every registered fixture matches its
// contentSha256, so a fixture no case happens to reference does not drift
// unnoticed.
func checkWholeRegistry(t testing.TB, dir string, fixtures map[string]fixtureEntry) {
	t.Helper()
	if len(fixtures) == 0 {
		t.Fatalf("harness error: %s registers no fixtures", casesFileName)
	}
	for id := range fixtures {
		fixtureBytesIn(t, dir, fixtures, id)
	}
}

// receiptString is the string verifyReceipt gets, and the endpoint's
// receipt-data: a text fixture verbatim, exactly as a client sent it; any
// other fixture holds DER, encoded as canonical base64.
func receiptString(t testing.TB, dir string, fixtures map[string]fixtureEntry, id string) string {
	t.Helper()
	bytes := fixtureBytesIn(t, dir, fixtures, id)
	if fixtures[id].Codec == "text" {
		return string(bytes)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

// --- config ------------------------------------------------------------

func buildConfig(t testing.TB, dir string, fixtures map[string]fixtureEntry, spec *caseConfigSpec, clock *clockSpec) *applereceipt.Config {
	t.Helper()
	if spec == nil {
		t.Fatalf("harness error: no config")
	}
	opts := applereceipt.ConfigOptions{}
	switch spec.TrustedRoots.Source {
	case "defaults":
	case "fixtures":
		opts.Roots = certificatesIn(t, dir, fixtures, spec.TrustedRoots.Fixtures)
	default:
		t.Fatalf("harness error: unknown trustedRoots source %q", spec.TrustedRoots.Source)
	}
	if revocation := spec.Revocation; revocation != nil {
		for _, id := range revocation.Lists {
			opts.RevocationLists = append(opts.RevocationLists, fixtureBytesIn(t, dir, fixtures, id))
		}
		if len(revocation.Issuers) > 0 {
			opts.RevocationIssuers = certificatesIn(t, dir, fixtures, revocation.Issuers)
		}
		for _, entry := range revocation.Distrust {
			opts.Distrust = append(opts.Distrust, applereceipt.RevokedCertificate{Issuer: entry.Issuer, Serial: entry.Serial})
		}
	}
	if clock != nil {
		now := parseInstantMs(t, clock.Now)
		opts.Clock = func() int64 { return now }
	}
	return applereceipt.NewConfig(opts)
}

// certificatesIn parses certificate fixtures, the way a caller holds roots
// and revocation issuers in this package: as *x509.Certificate.
func certificatesIn(t testing.TB, dir string, fixtures map[string]fixtureEntry, ids []string) []*x509.Certificate {
	t.Helper()
	certificates := make([]*x509.Certificate, 0, len(ids))
	for _, id := range ids {
		cert, err := x509.ParseCertificate(fixtureBytesIn(t, dir, fixtures, id))
		if err != nil {
			t.Fatalf("harness error: certificate %q does not parse: %v", id, err)
		}
		certificates = append(certificates, cert)
	}
	return certificates
}

// parseInstantMs reads YYYY-MM-DDTHH:MM:SSZ to epoch milliseconds, the
// only form the schema allows for clock.now.
func parseInstantMs(t testing.TB, text string) int64 {
	t.Helper()
	if len(text) != 20 {
		t.Fatalf("harness error: bad clock %q", text)
	}
	digit := func(from, n int) int64 {
		v := int64(0)
		for i := from; i < from+n; i++ {
			v = v*10 + int64(text[i]-'0')
		}
		return v
	}
	year, month, day := digit(0, 4), digit(5, 2), digit(8, 2)
	hour, minute, second := digit(11, 2), digit(14, 2), digit(17, 2)
	// Howard Hinnant's days_from_civil.
	y := year
	if month <= 2 {
		y--
	}
	era := y
	if y < 0 {
		era = y - 399
	}
	era /= 400
	yoe := y - era*400
	mp := (month + 9) % 12
	doy := (153*mp+2)/5 + day - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	days := era*146_097 + doe - 719_468
	return ((days*24+hour)*60+minute)*60_000 + second*1000
}

func buildVerifier(t testing.TB, config *applereceipt.Config) *applereceipt.Verifier {
	t.Helper()
	verifier, err := applereceipt.NewVerifier(config)
	if err != nil {
		t.Fatalf("harness error: config refused: %v", err)
	}
	return verifier
}

// --- expectations ------------------------------------------------------

// resolvePointer is an RFC 6901 pointer with one extension: a token
// [key=value] selects the single array element whose member key is the
// JSON string value, and the case fails unless exactly one matches.
func resolvePointer(root any, pointer string) (value any, present bool, err error) {
	rest, ok := strings.CutPrefix(pointer, "/")
	if !ok {
		return nil, false, fmt.Errorf("harness error: %q is not a pointer", pointer)
	}
	current := root
	if rest == "" {
		return current, true, nil
	}
	for _, raw := range strings.Split(rest, "/") {
		if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
			selector := raw[1 : len(raw)-1]
			if key, wanted, ok := strings.Cut(selector, "="); ok {
				items, ok := current.([]any)
				if !ok {
					return nil, false, fmt.Errorf("%s: %s needs an array", pointer, raw)
				}
				var matches []any
				for _, item := range items {
					obj, ok := item.(map[string]any)
					if ok {
						if s, ok := obj[key].(string); ok && s == wanted {
							matches = append(matches, item)
						}
					}
				}
				if len(matches) != 1 {
					return nil, false, fmt.Errorf("%s: %s must select exactly one element, selected %d",
						pointer, raw, len(matches))
				}
				current = matches[0]
				continue
			}
		}
		token := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch c := current.(type) {
		case map[string]any:
			next, ok := c[token]
			if !ok {
				return nil, false, nil
			}
			current = next
		case []any:
			index, ierr := strconv.Atoi(token)
			if ierr != nil || index < 0 || index >= len(c) {
				return nil, false, nil
			}
			current = c[index]
		default:
			return nil, false, nil
		}
	}
	return current, true, nil
}

// jsonEqual compares a "want" value from the case file (json.Number for
// every number, since the document is decoded with UseNumber) against a
// "got" value from the library's own output, decoded the same way.
// Numbers compare exactly by value; everything else compares
// structurally.
func jsonEqual(want, got any) bool {
	switch w := want.(type) {
	case nil:
		return got == nil
	case json.Number:
		g, ok := got.(json.Number)
		if !ok {
			return false
		}
		// Compared by value, not by spelling: 1722945600000 and
		// 1722945600000.0 are the same claim. Both sides are read as exact
		// rationals, never through int64 or float64, so 2^63 does not
		// equal 2^63-1 and no digit of a 19-digit id is rounded away.
		wr, wok := new(big.Rat).SetString(w.String())
		gr, gok := new(big.Rat).SetString(g.String())
		return wok && gok && wr.Cmp(gr) == 0
	case string:
		g, ok := got.(string)
		return ok && g == w
	case bool:
		g, ok := got.(bool)
		return ok && g == w
	case map[string]any:
		g, ok := got.(map[string]any)
		return ok && maps.EqualFunc(w, g, jsonEqual)
	case []any:
		g, ok := got.([]any)
		return ok && slices.EqualFunc(w, g, jsonEqual)
	default:
		return false
	}
}

func describe(value any, present bool) string {
	if !present {
		return "absent"
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(encoded)
}

// check evaluates every fields and lengths expectation against actual,
// returning every mismatch rather than stopping at the first.
func check(id string, expected caseExpectedSpec, actual any) []string {
	var failures []string
	for pointer, want := range expected.Fields {
		got, present, err := resolvePointer(actual, pointer)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s %v", id, err))
			continue
		}
		ok := (want == nil && (!present || got == nil)) || (present && jsonEqual(want, got))
		if !ok {
			failures = append(failures, fmt.Sprintf("%s %s: expected %s but got %s",
				id, pointer, describe(want, true), describe(got, present)))
		}
	}
	for pointer, want := range expected.Lengths {
		got, present, err := resolvePointer(actual, pointer)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s %v", id, err))
			continue
		}
		arr, isArray := got.([]any)
		wantNumber, isNumber := want.(json.Number)
		wantLen, _ := wantNumber.Int64()
		if !present || !isArray || !isNumber || int64(len(arr)) != wantLen {
			failures = append(failures, fmt.Sprintf("%s %s: expected an array of %s but got %s",
				id, pointer, describe(want, true), describe(got, present)))
		}
	}
	return failures
}

func parseJSONAny(t testing.TB, id, text string) any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		t.Fatalf("%s: the library returned JSON that does not parse (%v): %s", id, err, text)
	}
	return value
}

// --- decodeBase64 --------------------------------------------------------

// runDecodeBase64 runs every text of the group through the Verifier method
// that uses each decoder it names, and reports every text that landed on
// the wrong side of the rule, by decoder, index and escaped text, rather
// than stopping at the first.
//
// 0.7 exposes no public decoder, and this port has none of its own, so the
// only observable is which side of the base64 rule a text falls on: a text
// the group expects to decode must not be refused as base64 (whatever the
// bytes it decodes to are, they are not a receipt or a certificate, and
// fail later for that), and a text the group expects to be refused must be
// refused as base64. The refusal is told apart by its reason and by the
// word "base64" in the core's message ("receipt is not valid base64",
// "x5c entry is not valid base64"), or "receipt is empty" for an empty
// receipt. What the bytes decode to (bytesHex) is
// not observable here, and is not checked.
//
//   - receipt-data goes through VerifyReceipt, which refuses as MALFORMED;
//   - x5c goes through VerifySignedData, as all three entries of the x5c
//     header member of an otherwise empty JWS, which refuses as
//     INVALID_CERTIFICATE.
func runDecodeBase64(t testing.TB, c conformanceCase) {
	if len(c.Input.Texts) == 0 {
		t.Fatalf("harness error: decodeBase64 needs input.texts")
	}
	if len(c.Decoders) == 0 {
		t.Fatalf("harness error: decodeBase64 needs decoders")
	}
	ok := c.Expected.Status == "ok"
	if ok {
		if c.Expected.BytesHex == "" {
			t.Fatalf("harness error: an ok group with no bytesHex")
		}
	} else if c.Expected.Reason != "MALFORMED" {
		t.Fatalf("harness error: an error group states a reason other than MALFORMED")
	}
	verifier := buildVerifier(t, applereceipt.NewConfig(applereceipt.ConfigOptions{}))
	for _, decoderName := range c.Decoders {
		for index, text := range c.Input.Texts {
			at := fmt.Sprintf("%s %s texts[%d] %q", c.ID, decoderName, index, text)
			var err error
			var refusal applereceipt.Reason
			switch decoderName {
			case "receipt-data":
				_, err = verifier.VerifyReceipt(text)
				refusal = applereceipt.ReasonMalformed
			case "x5c":
				_, err = verifier.VerifySignedData(x5cProbe(t, text))
				refusal = applereceipt.ReasonInvalidCertificate
			default:
				t.Fatalf("harness error: no decoder %q", decoderName)
			}
			refused := refusedAsBase64(err, refusal)
			switch {
			case ok && refused:
				t.Errorf("%s was refused as base64 (%v), want it decoded", at, err)
			case !ok && !refused:
				t.Errorf("%s was not refused as base64 (%v), want it refused", at, err)
			}
		}
	}
}

// refusedAsBase64 reports whether err is the base64 rule refusing a text:
// a *Failure with the decoder's reason and a message that names base64.
func refusedAsBase64(err error, refusal applereceipt.Reason) bool {
	var failure *applereceipt.Failure
	if !errors.As(err, &failure) || failure.Reason != refusal {
		return false
	}
	message := strings.ToLower(failure.Message)
	// An empty receipt-data has a message of its own, and is still refused.
	return strings.Contains(message, "base64") || message == "receipt is empty"
}

// x5cProbe is a compact JWS whose header carries text as each of its three
// x5c entries (the core refuses any other count before it decodes one): the
// smallest input that sends text to the x5c decoder. Nothing about it is
// signed; it never gets past the certificates.
func x5cProbe(t testing.TB, text string) string {
	t.Helper()
	if !utf8.ValidString(text) {
		t.Fatalf("harness error: %q is not UTF-8, so no JWS header can carry it", text)
	}
	entry, err := json.Marshal(text)
	if err != nil {
		t.Fatalf("harness error: %v", err)
	}
	segment := base64.RawURLEncoding.EncodeToString
	return segment([]byte(`{"alg":"ES256","x5c":[`+string(entry)+`,`+string(entry)+`,`+string(entry)+`]}`)) + "." + segment([]byte(`{}`)) + "." + segment(make([]byte, 64))
}

// --- one case --------------------------------------------------------------

// ran records which case ids actually ran, so the coverage check after
// the run is a fact rather than a loop-shaped assumption.
var (
	ranMu sync.Mutex
	ran   []string
)

func recordRan(id string) {
	ranMu.Lock()
	ran = append(ran, id)
	ranMu.Unlock()
}

func runCase(t testing.TB, dir string, fixtures map[string]fixtureEntry, c conformanceCase) {
	recordRan(c.ID)
	switch c.Operation {
	case "decodeBase64":
		runDecodeBase64(t, c)
		return
	case "buildConfig":
		runBuildConfig(t, dir, fixtures, c)
		return
	}
	verifier := buildVerifier(t, buildConfig(t, dir, fixtures, c.Config, c.Clock))
	expected := c.Expected

	var actual any
	switch c.Operation {
	case "verifyReceiptEndpoint":
		var environment applereceipt.Environment
		var envText string
		if c.Config != nil {
			envText = c.Config.Environment
		}
		switch envText {
		case "PRODUCTION":
			environment = applereceipt.EnvironmentProduction
		case "SANDBOX":
			environment = applereceipt.EnvironmentSandbox
		default:
			t.Fatalf("%s: harness error: environment %q", c.ID, envText)
		}
		var body string
		switch {
		case c.Input.RequestBody != "":
			body = string(fixtureBytesIn(t, dir, fixtures, c.Input.RequestBody))
		case c.Input.Fixture != "":
			receiptData := receiptString(t, dir, fixtures, c.Input.Fixture)
			encoded, err := json.Marshal(map[string]string{"receipt-data": receiptData})
			if err != nil {
				t.Fatalf("%s: harness error: %v", c.ID, err)
			}
			body = string(encoded)
		default:
			t.Fatalf("%s: harness error: no input", c.ID)
		}
		response := verifier.VerifyReceiptEndpoint(environment, body)
		actual = parseJSONAny(t, c.ID, response)
		if expected.OneOf != nil {
			// Port-defined within a list: the response's /status must be
			// listed, and nothing else is pinned.
			doc, _ := actual.(map[string]any)
			status := doc["status"]
			if !slices.Contains(expected.OneOf, status) {
				t.Fatalf("%s: answered status %v, want one of %v", c.ID, status, expected.OneOf)
			}
			return
		}
		if _, pinned := expected.Fields["/status"]; !pinned {
			t.Fatalf("%s: harness error: /status not pinned", c.ID)
		}

	case "verifyReceipt", "verifySignedData":
		if c.Input.Fixture == "" {
			t.Fatalf("%s: harness error: no fixture", c.ID)
		}
		var input string
		if c.Operation == "verifyReceipt" {
			input = receiptString(t, dir, fixtures, c.Input.Fixture)
		} else {
			input = string(fixtureBytesIn(t, dir, fixtures, c.Input.Fixture))
		}
		call := func() (string, *applereceipt.Environment, error) {
			if c.Operation == "verifyReceipt" {
				payload, err := verifier.VerifyReceipt(input)
				if err != nil {
					return "", nil, err
				}
				return payload.ToJSON(), payload.Environment, nil
			}
			payload, err := verifier.VerifySignedData(input)
			if err != nil {
				return "", nil, err
			}
			return payload.JSON(), payload.Environment(), nil
		}

		var jsonText string
		var environment *applereceipt.Environment
		var callErr error
		if c.MaxMillis == nil {
			jsonText, environment, callErr = call()
		} else {
			_, _, _ = call() // warm-up
			start := time.Now()
			jsonText, environment, callErr = call()
			if elapsed, budget := time.Since(start), time.Duration(*c.MaxMillis)*time.Millisecond; elapsed > budget {
				t.Fatalf("%s: took %v, over the %dms budget", c.ID, elapsed, *c.MaxMillis)
			}
		}

		if expected.OneOf != nil {
			outcome := "ok"
			if callErr != nil {
				failure, ok := callErr.(*applereceipt.Failure)
				if !ok {
					t.Fatalf("%s: escaped as %T, not a *Failure: %v", c.ID, callErr, callErr)
				}
				outcome = string(failure.Reason)
			}
			if !slices.Contains(expected.OneOf, any(outcome)) {
				t.Fatalf("%s: answered %s, want one of %v: %v", c.ID, outcome, expected.OneOf, callErr)
			}
			return
		}

		switch expected.Status {
		case "error":
			if callErr == nil {
				t.Fatalf("%s: expected %s but the operation verified", c.ID, expected.Reason)
			}
			want := expected.Reason
			if want == "" {
				t.Fatalf("%s: harness error: no reason", c.ID)
			}
			reason, _ := applereceipt.ReasonOf(callErr)
			if string(reason) != want {
				t.Fatalf("%s: expected %s but got %v", c.ID, want, callErr)
			}
			if len(expected.MessageMustNotContain) > 0 {
				failure, ok := callErr.(*applereceipt.Failure)
				if !ok {
					t.Fatalf("%s: harness error: %v is not a *Failure", c.ID, callErr)
				}
				for _, codePoint := range expected.MessageMustNotContain {
					for _, r := range failure.Message {
						if int(r) == codePoint {
							t.Fatalf("%s: the failure message contains U+%04X: %q",
								c.ID, codePoint, failure.Message)
						}
					}
				}
			}
			return
		case "ok":
			if callErr != nil {
				t.Fatalf("%s: expected ok but got %v", c.ID, callErr)
			}
			actual = parseJSONAny(t, c.ID, jsonText)
			// Same value, not same bytes: whitespace, key order and
			// escaping are free (docs/design/0.7-api.md "Our JSON").
			if expected.ToJSON != nil && !reflect.DeepEqual(parseJSONAny(t, c.ID, *expected.ToJSON), actual) {
				t.Fatalf("%s: toJson value\n  expected %s\n  but got  %s", c.ID, *expected.ToJSON, jsonText)
			}
			checkEnvironment(t, c.ID, expected.Environment, environment)
		default:
			t.Fatalf("%s: harness error: unknown status %q", c.ID, expected.Status)
		}

	default:
		t.Fatalf("%s: harness error: unknown operation %q", c.ID, c.Operation)
	}

	for _, failure := range check(c.ID, expected, actual) {
		t.Error(failure)
	}
}

// runBuildConfig builds the case's configuration into a Verifier. An error
// case must be refused by NewVerifier with the module's refusal, a
// *host.InitRefusedError, not a *Failure (the message is not checked); an
// ok case must build and report the case's revocationUrls, in order, and
// revocationValidUntil.
func runBuildConfig(t testing.TB, dir string, fixtures map[string]fixtureEntry, c conformanceCase) {
	if c.Input.TrustedRoots == nil {
		t.Fatalf("%s: harness error: buildConfig needs input.trustedRoots", c.ID)
	}
	config := buildConfig(t, dir, fixtures,
		&caseConfigSpec{TrustedRoots: *c.Input.TrustedRoots, Revocation: c.Input.Revocation}, c.Clock)
	verifier, err := applereceipt.NewVerifier(config)
	switch c.Expected.Status {
	case "error":
		if err == nil {
			t.Fatalf("%s: the configuration built, want it refused", c.ID)
		}
		if _, isFailure := applereceipt.ReasonOf(err); isFailure {
			t.Fatalf("%s: a refused configuration is a *Failure, want a plain error: %v", c.ID, err)
		}
		// The module's refusal, not a wrapper-side misuse check or a host
		// failure: any other error would pass these cases for the wrong reason.
		var refused *host.InitRefusedError
		if !errors.As(err, &refused) {
			t.Fatalf("%s: the configuration was refused, but not by the module (%T), want *host.InitRefusedError: %v", c.ID, err, err)
		}
	case "ok":
		if err != nil {
			t.Fatalf("%s: the configuration was refused: %v", c.ID, err)
		}
		if c.Expected.RevocationURLs == nil || len(c.Expected.RevocationValidUntil) == 0 {
			t.Fatalf("%s: harness error: an ok buildConfig case states no revocationUrls or revocationValidUntil", c.ID)
		}
		if got := verifier.RevocationURLs(); !slices.Equal(got, c.Expected.RevocationURLs) {
			t.Errorf("%s: RevocationURLs %q, want %q", c.ID, got, c.Expected.RevocationURLs)
		}
		var want *string
		if err := json.Unmarshal(c.Expected.RevocationValidUntil, &want); err != nil {
			t.Fatalf("%s: harness error: revocationValidUntil %s is not a string or null", c.ID, c.Expected.RevocationValidUntil)
		}
		until, ok := verifier.RevocationValidUntil()
		switch {
		case want == nil && ok:
			t.Errorf("%s: RevocationValidUntil %s, want none", c.ID, until.Format(time.RFC3339Nano))
		case want != nil && !ok:
			t.Errorf("%s: RevocationValidUntil none, want %s", c.ID, *want)
		case want != nil && until.UnixMilli() != parseInstantMs(t, *want):
			t.Errorf("%s: RevocationValidUntil %s, want %s", c.ID, until.Format(time.RFC3339Nano), *want)
		}
	default:
		t.Fatalf("%s: harness error: unknown status %q", c.ID, c.Expected.Status)
	}
}

// checkEnvironment compares an ok result's environment with the case's
// expected.environment: "Production", "Sandbox", or null for nil.
func checkEnvironment(t testing.TB, id string, want json.RawMessage, got *applereceipt.Environment) {
	t.Helper()
	if len(want) == 0 {
		t.Fatalf("%s: harness error: an ok case states no environment", id)
	}
	var wantText *string
	if err := json.Unmarshal(want, &wantText); err != nil {
		t.Fatalf("%s: harness error: environment %s is not a string or null", id, want)
	}
	switch {
	case wantText == nil && got == nil:
	case wantText == nil:
		t.Fatalf("%s: environment %q, want null", id, *got)
	case got == nil:
		t.Fatalf("%s: environment null, want %q", id, *wantText)
	case string(*got) != *wantText:
		t.Fatalf("%s: environment %q, want %q", id, *got, *wantText)
	}
}

// --- the runner --------------------------------------------------------

func TestConformance(t *testing.T) {
	// Reset between runs in the same process (go test -count=2, or a
	// caller running TestConformance more than once): ran is
	// package-level state, and a stale coverage list would otherwise
	// fail the self-check below with a mysterious mismatch.
	ranMu.Lock()
	ran = nil
	ranMu.Unlock()

	dir, file := loadCases(t)
	checkWholeRegistry(t, dir, file.Fixtures)

	for _, c := range file.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			runCase(t, dir, file.Fixtures, c)
		})
	}

	if len(ran) != len(file.Cases) {
		t.Fatalf("coverage self-check: %d cases ran, %d are in %s",
			len(ran), len(file.Cases), casesFileName)
	}
	seen := make(map[string]bool, len(ran))
	for _, id := range ran {
		seen[id] = true
	}
	var missing []string
	for _, c := range file.Cases {
		if !seen[c.ID] {
			missing = append(missing, c.ID)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("coverage self-check: %d of %d cases did not run: %s",
			len(missing), len(file.Cases), strings.Join(missing, ", "))
	}
	t.Logf("%s: %d cases ran, %d fixtures registered, 0 skipped",
		casesFileName, len(file.Cases), len(file.Fixtures))
}

// Every reason a case expects must be one of the exported Reason values,
// so a typo in the case file surfaces here, named, rather than as a
// mysterious mismatch inside one case.
func TestEveryExpectedReasonIsInTheVocabulary(t *testing.T) {
	known := map[string]bool{}
	for _, reason := range applereceipt.AllReasons() {
		known[string(reason)] = true
	}
	_, file := sharedCases(t)
	for _, c := range file.Cases {
		if c.Expected.Reason != "" && !known[c.Expected.Reason] {
			t.Errorf("%s expects reason %q, which is not in the exported vocabulary",
				c.ID, c.Expected.Reason)
		}
	}
}

// The case pinning download_id at 2^63-1 is there to catch a value
// rounded through a double, so the comparison must round nothing itself:
// a near miss in the last digit is a mismatch, a different spelling of
// the same value is not.
func TestJSONEqualComparesNumbersExactly(t *testing.T) {
	for _, c := range []struct {
		want, got string
		equal     bool
	}{
		{"9223372036854775807", "9223372036854775807", true},
		{"9223372036854775807", "9223372036854775808", false},
		{"9223372036854775808", "9223372036854775809", false},
		{"18446744073709551615", "18446744073709551614", false},
		{"9007199254740993", "9007199254740992", false},
		{"1722945600000", "1722945600000.0", true},
		{"1.5", "15e-1", true},
	} {
		if got := jsonEqual(json.Number(c.want), json.Number(c.got)); got != c.equal {
			t.Errorf("jsonEqual(%s, %s) = %v, want %v", c.want, c.got, got, c.equal)
		}
	}
}
