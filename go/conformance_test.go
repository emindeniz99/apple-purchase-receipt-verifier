package applereceipt_test

// Runs every vector in fixtures/cases-0.7.json, the normative
// cross-language conformance set for the 0.7 API, through the three
// public Verifier methods and the two base64 decoders.
//
// This adapter knows nothing about any individual case. It loads the
// file, resolves fixture ids to bytes and checks their recorded digest,
// builds a Config from the case's trusted roots and clock, dispatches on
// operation, and evaluates the expectation on the JSON the library
// returns: ReceiptPayload.ToJSON(), JsonPayload.JSON() or the endpoint's
// response body. The file's top-level comment defines the semantics
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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/chain"
)

const casesFileName = "cases-0.7.json"

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

type caseConfigSpec struct {
	TrustedRoots trustedRootsSpec `json:"trustedRoots"`
	Environment  string           `json:"environment"`
}

type clockSpec struct {
	Now string `json:"now"`
}

type caseInputSpec struct {
	Fixture     string   `json:"fixture"`
	RequestBody string   `json:"requestBody"`
	Texts       []string `json:"texts"`
}

type caseExpectedSpec struct {
	Status                string         `json:"status"`
	Reason                string         `json:"reason"`
	MessageMustNotContain []int          `json:"messageMustNotContain"`
	Fields                map[string]any `json:"fields"`
	Lengths               map[string]any `json:"lengths"`
	ToJSON                *string        `json:"toJson"`
	BytesHex              string         `json:"bytesHex"`
	// AnyOutcome marks a port-defined case (owner, 2026-09-27): the port
	// may verify or refuse with any reason, as long as it does not crash,
	// does not answer INTERNAL_ERROR, and finishes within maxMillis. No
	// status, reason or field is pinned.
	AnyOutcome bool `json:"anyOutcome"`
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
	if parsed.SchemaVersion != 2 {
		t.Fatalf("harness error: %s is schemaVersion %d, this adapter implements 2",
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
		roots := make([]*x509.Certificate, 0, len(spec.TrustedRoots.Fixtures))
		for _, id := range spec.TrustedRoots.Fixtures {
			der := fixtureBytesIn(t, dir, fixtures, id)
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("harness error: root %q does not parse: %v", id, err)
			}
			roots = append(roots, cert)
		}
		opts.Roots = roots
	default:
		t.Fatalf("harness error: unknown trustedRoots source %q", spec.TrustedRoots.Source)
	}
	if clock != nil {
		now := parseInstantMs(t, clock.Now)
		opts.Clock = func() int64 { return now }
	}
	return applereceipt.NewConfig(opts)
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
// Numbers compare by value, integers exactly; everything else compares
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
		// 1722945600000.0 are the same claim. Exact int64 comparison only
		// when BOTH sides parse as a literal integer, so a 19-digit id
		// keeps its exact digits; otherwise (either side has a fraction or
		// an exponent) fall back to float64, which is what "the same
		// number" means once either spelling is not a bare integer.
		wi, werr := w.Int64()
		gi, gerr := g.Int64()
		if werr == nil && gerr == nil {
			return wi == gi
		}
		wf, wferr := w.Float64()
		gf, gferr := g.Float64()
		return wferr == nil && gferr == nil && wf == gf
	case string:
		g, ok := got.(string)
		return ok && g == w
	case bool:
		g, ok := got.(bool)
		return ok && g == w
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for k, wv := range w {
			gv, present := g[k]
			if !present || !jsonEqual(wv, gv) {
				return false
			}
		}
		return true
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !jsonEqual(w[i], g[i]) {
				return false
			}
		}
		return true
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

// runDecodeBase64 runs every text of the group through every decoder it
// names and reports every text that got the wrong answer, by decoder,
// index and escaped text, rather than stopping at the first.
func runDecodeBase64(t testing.TB, c conformanceCase) {
	if len(c.Input.Texts) == 0 {
		t.Fatalf("harness error: decodeBase64 needs input.texts")
	}
	if len(c.Decoders) == 0 {
		t.Fatalf("harness error: decodeBase64 needs decoders")
	}
	ok := c.Expected.Status == "ok"
	var want string
	if ok {
		if c.Expected.BytesHex == "" {
			t.Fatalf("harness error: an ok group with no bytesHex")
		}
		want = c.Expected.BytesHex
	} else if c.Expected.Reason == "MALFORMED" {
		want = ""
	} else {
		t.Fatalf("harness error: an error group states a reason other than MALFORMED")
	}
	for _, decoderName := range c.Decoders {
		var decode func(string) ([]byte, error)
		var refusal applereceipt.Reason
		switch decoderName {
		case "receipt-data":
			decode, refusal = applereceipt.DecodeReceiptDataForTest, applereceipt.ReasonMalformed
		case "x5c":
			decode, refusal = applereceipt.DecodeX5CEntryForTest, applereceipt.ReasonInvalidCertificate
		default:
			t.Fatalf("harness error: no decoder %q", decoderName)
		}
		for index, text := range c.Input.Texts {
			at := fmt.Sprintf("%s %s texts[%d] %q", c.ID, decoderName, index, text)
			bytes, err := decode(text)
			switch {
			case err == nil && !ok:
				t.Errorf("%s was accepted (decoded to %x)", at, bytes)
			case err == nil && hex.EncodeToString(bytes) != want:
				t.Errorf("%s decoded to %x, want %s", at, bytes, want)
			case err != nil && ok:
				t.Errorf("%s was refused (%v), want ok", at, err)
			default:
				if err != nil {
					if reason, _ := applereceipt.ReasonOf(err); reason != refusal {
						t.Errorf("%s: reason %s, want %s", at, reason, refusal)
					}
				}
			}
		}
	}
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
	if c.Operation == "decodeBase64" {
		runDecodeBase64(t, c)
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
		if _, pinned := expected.Fields["/status"]; !pinned {
			t.Fatalf("%s: harness error: /status not pinned", c.ID)
		}
		response := verifier.VerifyReceiptEndpoint(environment, body)
		actual = parseJSONAny(t, c.ID, response)

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
		call := func() (string, error) {
			if c.Operation == "verifyReceipt" {
				payload, err := verifier.VerifyReceipt(input)
				if err != nil {
					return "", err
				}
				return payload.ToJSON(), nil
			}
			payload, err := verifier.VerifySignedData(input)
			if err != nil {
				return "", err
			}
			return payload.JSON(), nil
		}

		var jsonText string
		var callErr error
		if c.MaxMillis == nil {
			jsonText, callErr = call()
		} else {
			_, _ = call() // warm-up
			start := time.Now()
			used := chain.KeysUsedDuring(func() {
				jsonText, callErr = call()
			})
			elapsed := time.Since(start)
			budget := time.Duration(*c.MaxMillis) * time.Millisecond
			if elapsed > budget {
				t.Fatalf("%s: took %v, over the %dms budget", c.ID, elapsed, *c.MaxMillis)
			}
			// The direct form of the budget: every stranger in these
			// cases carries a key far over the 8192-bit cap, so an SPKI
			// that large among the keys used means a stranger's key
			// reached a signature check. An 8192-bit RSA SPKI is about
			// 1,050 bytes.
			for _, spki := range used {
				if len(spki) > 1100 {
					t.Fatalf("%s: a %d-byte stranger key checked a signature", c.ID, len(spki))
				}
			}
		}

		if expected.AnyOutcome {
			if callErr != nil {
				failure, ok := callErr.(*applereceipt.Failure)
				if !ok {
					t.Fatalf("%s: escaped as %T, not a *Failure: %v", c.ID, callErr, callErr)
				}
				if failure.Reason == applereceipt.ReasonInternalError {
					t.Fatalf("%s: answered INTERNAL_ERROR, which anyOutcome forbids: %v", c.ID, callErr)
				}
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
			if expected.ToJSON != nil && *expected.ToJSON != jsonText {
				t.Fatalf("%s: toJson\n  expected %s\n  but got  %s", c.ID, *expected.ToJSON, jsonText)
			}
			actual = parseJSONAny(t, c.ID, jsonText)
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
