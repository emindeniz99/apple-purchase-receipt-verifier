package applereceipt_test

// Runs fixtures/cases.json — the normative cross-language conformance
// vectors — against this implementation.
//
// The adapter below knows nothing about any individual case. It loads the
// file, resolves fixture ids to bytes and checks their digests, builds a
// verifier from the generic config, dispatches on "operation", normalizes
// the result and reads the reason off a failure. There is no skip list,
// no hardcoded case count and no per-case fixup: a case this adapter
// cannot map is a hard harness failure. A vector that disagrees with the
// library is a bug report against one of the two; it is never something
// to special-case here.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	// The endpoint renders _pst dates, which needs the IANA database.
	// Carrying it in the test binary rather than in the library keeps the
	// ~450 KB off every consumer that never touches the endpoint, while
	// making the suite runnable on an image with no /usr/share/zoneinfo.
	_ "time/tzdata"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// --- the vectors file ----------------------------------------------------

type casesFile struct {
	Schema        string             `json:"$schema"`
	Comment       string             `json:"comment"`
	SchemaVersion int                `json:"schemaVersion"`
	Fixtures      map[string]fixture `json:"fixtures"`
	Cases         []conformanceCase  `json:"cases"`
}

type fixture struct {
	Path          string `json:"path"`
	Role          string `json:"role"`
	Codec         string `json:"codec"`
	ContentSHA256 string `json:"contentSha256"`
}

type trustedRootsSpec struct {
	Source   string   `json:"source"`
	Name     string   `json:"name"`
	Fixtures []string `json:"fixtures"`
}

type caseConfig struct {
	TrustedRoots         trustedRootsSpec           `json:"trustedRoots"`
	BundleID             *string                    `json:"bundleId"`
	AcceptedEnvironments []applereceipt.Environment `json:"acceptedEnvironments"`
	AppAppleID           *int64                     `json:"appAppleId"`
	MaxSignedAgeSeconds  *int64                     `json:"maxSignedAgeSeconds"`
	DeviceGUIDHex        *string                    `json:"deviceGuidHex"`
	Environment          applereceipt.Environment   `json:"environment"`
}

type expectation struct {
	Status string              `json:"status"`
	Reason applereceipt.Reason `json:"reason"`
	Fields map[string]any      `json:"fields"`
}

type conformanceCase struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Operation   string `json:"operation"`
	Input       struct {
		Fixture string `json:"fixture"`
	} `json:"input"`
	Config caseConfig `json:"config"`
	Clock  *struct {
		Now string `json:"now"`
	} `json:"clock"`
	Expected expectation `json:"expected"`
	Fault    string      `json:"fault"`
	Tags     []string    `json:"tags"`
}

// fixturesDir walks up from the working directory looking for
// fixtures/cases.json, rather than hardcoding "../fixtures": the test
// binary's working directory is the package directory today, and a
// relative literal is exactly the thing that breaks when that changes or
// when the suite is run from a different root.
var fixturesDir = sync.OnceValues(func() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, "fixtures", "cases.json")
		if _, err := os.Stat(candidate); err == nil {
			return filepath.Join(dir, "fixtures"), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no fixtures/cases.json found above the working directory")
		}
		dir = parent
	}
})

var loadCases = sync.OnceValues(func() (*casesFile, error) {
	dir, err := fixturesDir()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		return nil, err
	}
	var parsed casesFile
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	// Unknown members would mean the schema moved under us.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&parsed); err != nil {
		return nil, err
	}
	return &parsed, nil
})

func mustCases(t testing.TB) *casesFile {
	t.Helper()
	parsed, err := loadCases()
	if err != nil {
		t.Fatalf("harness error: loading fixtures/cases.json: %v", err)
	}
	return parsed
}

// --- fixture bytes -------------------------------------------------------

type fixtureCache struct {
	mu    sync.Mutex
	bytes map[string][]byte
}

var cache = fixtureCache{bytes: map[string][]byte{}}

// fixtureBytes decodes a registered fixture to its logical bytes and
// checks them against the digest the registry records.
//
// contentSha256 is not documentation. It is the only mechanical defence
// against this whole suite going green while verifying edited fixture
// bytes: a fixture that is regenerated, re-encoded or quietly changed
// would silently alter what every pinned field means. The digest is over
// the DECODED bytes — the same bytes handed to the library.
func fixtureBytes(t testing.TB, id string) []byte {
	t.Helper()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cached, ok := cache.bytes[id]; ok {
		return cached
	}
	parsed := mustCases(t)
	entry, ok := parsed.Fixtures[id]
	if !ok {
		t.Fatalf("harness error: cases.json registers no fixture %q", id)
	}
	dir, err := fixturesDir()
	if err != nil {
		t.Fatalf("harness error: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(entry.Path)))
	if err != nil {
		t.Fatalf("harness error: reading fixture %q: %v", id, err)
	}
	var decoded []byte
	switch entry.Codec {
	case "raw", "text":
		// text is raw's twin for string-taking entry points: the file
		// bytes verbatim, untrimmed — whitespace, CRLF and a 0-byte file
		// all pass through unchanged, because pinning what a port does
		// with exactly what a client sent is the point of this codec.
		decoded = raw
	case "base64":
		decoded = decodeBase64Strict(t, id, stripWhitespace(string(raw)))
	case "utf8":
		decoded = []byte(strings.TrimSpace(string(raw)))
	default:
		t.Fatalf("harness error: unknown fixture codec %q", entry.Codec)
	}
	if entry.ContentSHA256 == "" {
		t.Fatalf("fixture %q (%s) records no contentSha256", id, entry.Path)
	}
	sum := sha256.Sum256(decoded)
	if got := hex.EncodeToString(sum[:]); got != entry.ContentSHA256 {
		t.Fatalf("fixture %q (%s, codec %s) has drifted: cases.json records contentSha256 %s, "+
			"the decoded bytes hash to %s", id, entry.Path, entry.Codec, entry.ContentSHA256, got)
	}
	cache.bytes[id] = decoded
	return decoded
}

// fixtureCodec reports a registered fixture's codec, so an operation
// adapter can tell a text fixture (bytes handed to a string entry point
// verbatim) from a raw or base64 one without re-deriving it from the
// already-decoded bytes.
func fixtureCodec(t *testing.T, id string) string {
	t.Helper()
	parsed := mustCases(t)
	entry, ok := parsed.Fixtures[id]
	if !ok {
		t.Fatalf("harness error: cases.json registers no fixture %q", id)
	}
	return entry.Codec
}

func stripWhitespace(text string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, text)
}

func decodeBase64Strict(t testing.TB, id, text string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		t.Fatalf("harness error: fixture %q is not base64: %v", id, err)
	}
	return decoded
}

// Read before any case runs: a fixture no case happens to reference would
// otherwise drift unnoticed, and the registry as a whole is what is being
// guarded.
func TestEveryRegisteredFixtureMatchesItsDigest(t *testing.T) {
	parsed := mustCases(t)
	if len(parsed.Fixtures) == 0 {
		t.Fatal("cases.json must register fixtures")
	}
	for id := range parsed.Fixtures {
		fixtureBytes(t, id)
	}
}

func TestSchemaVersionIsTheOneThisAdapterUnderstands(t *testing.T) {
	if got := mustCases(t).SchemaVersion; got != 1 {
		t.Fatalf("cases.json schemaVersion is %d; this adapter was written against 1", got)
	}
}

// Every reason a vector expects must be one of the eleven exported
// constants, so a typo in the file surfaces here rather than as a
// mysterious mismatch inside one case.
func TestEveryExpectedReasonIsInTheVocabulary(t *testing.T) {
	known := map[applereceipt.Reason]bool{}
	for _, reason := range applereceipt.AllReasons() {
		known[reason] = true
	}
	for _, kase := range mustCases(t).Cases {
		if kase.Expected.Reason != "" && !known[kase.Expected.Reason] {
			t.Errorf("%s expects reason %q, which is not in the exported vocabulary",
				kase.ID, kase.Expected.Reason)
		}
	}
}

// --- config -> API -------------------------------------------------------

// verifyRaw enforces no claim, so its cases may omit bundleId and
// acceptedEnvironments — but the constructor still demands both. These
// substitutes match nothing any fixture carries, so a claim check that
// leaked into VerifyRaw shows up as a failure rather than as a silent
// pass. An empty string or "all four environments" would hide exactly
// that bug.
const unmatchableBundleID = "conformance.unset.bundle.id"

var unmatchableEnvironments = []applereceipt.Environment{applereceipt.EnvironmentLocalTesting}

func trustedRootsFor(t *testing.T, spec trustedRootsSpec) []*x509.Certificate {
	t.Helper()
	switch spec.Source {
	case "builtin":
		switch spec.Name {
		case "apple-jws-roots":
			return applereceipt.AppleJWSRoots()
		case "apple-receipt-roots":
			return applereceipt.AppleReceiptRoots()
		default:
			t.Fatalf("harness error: unknown builtin root set %q", spec.Name)
		}
	case "fixtures":
		roots := make([]*x509.Certificate, 0, len(spec.Fixtures))
		for _, id := range spec.Fixtures {
			cert, err := x509.ParseCertificate(fixtureBytes(t, id))
			if err != nil {
				t.Fatalf("harness error: fixture %q is not a certificate: %v", id, err)
			}
			roots = append(roots, cert)
		}
		return roots
	default:
		t.Fatalf("harness error: unknown trustedRoots source %q", spec.Source)
	}
	return nil
}

func jwsVerifier(t *testing.T, config caseConfig, clock func() time.Time) *applereceipt.JWSVerifier {
	t.Helper()
	bundleID := unmatchableBundleID
	if config.BundleID != nil {
		bundleID = *config.BundleID
	}
	environments := unmatchableEnvironments
	if len(config.AcceptedEnvironments) > 0 {
		environments = config.AcceptedEnvironments
	}
	var maxSignedAge time.Duration
	if config.MaxSignedAgeSeconds != nil {
		// The one unit conversion in the whole adapter, and it lives here
		// rather than in any case.
		maxSignedAge = time.Duration(*config.MaxSignedAgeSeconds) * time.Second
	}
	verifier, err := applereceipt.NewJWSVerifier(applereceipt.JWSVerifierOptions{
		TrustedRoots:         trustedRootsFor(t, config.TrustedRoots),
		BundleID:             bundleID,
		AcceptedEnvironments: environments,
		AppAppleID:           config.AppAppleID,
		MaxSignedAge:         maxSignedAge,
		Now:                  clock,
	})
	if err != nil {
		t.Fatalf("harness error: building a JWSVerifier: %v", err)
	}
	return verifier
}

// operations dispatches on the case's "operation". Every operation takes
// the case's clock (nil when it pins none) and hands it to the library's
// clock seam; an operation with no seam rejects a case that pins one
// instead of silently running on the system clock. codec is the input
// fixture's codec — only verifyReceiptEndpoint needs it, to tell a text
// fixture (receipt-data goes in verbatim) from a raw or base64 one
// (re-encoded as canonical base64, as the schema documents on "input").
var operations = map[string]func(t *testing.T, config caseConfig, input []byte, codec string, clock func() time.Time) (any, error){
	"verifyTransaction": func(t *testing.T, config caseConfig, input []byte, codec string, clock func() time.Time) (any, error) {
		return jwsVerifier(t, config, clock).VerifyTransaction(string(input))
	},
	"verifyAppTransaction": func(t *testing.T, config caseConfig, input []byte, codec string, clock func() time.Time) (any, error) {
		return jwsVerifier(t, config, clock).VerifyAppTransaction(string(input))
	},
	"verifyRaw": func(t *testing.T, config caseConfig, input []byte, codec string, clock func() time.Time) (any, error) {
		return jwsVerifier(t, config, clock).VerifyRaw(string(input))
	},
	"verifyReceipt": func(t *testing.T, config caseConfig, input []byte, codec string, clock func() time.Time) (any, error) {
		if clock != nil {
			t.Fatalf("harness error: verifyReceipt has no clock seam, but the case pins one")
		}
		if config.BundleID == nil {
			t.Fatalf("harness error: a verifyReceipt case must configure a bundleId")
		}
		verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
			TrustedRoots: trustedRootsFor(t, config.TrustedRoots),
			BundleID:     *config.BundleID,
		})
		if err != nil {
			t.Fatalf("harness error: building a ReceiptVerifier: %v", err)
		}
		if config.DeviceGUIDHex == nil {
			return verifier.Verify(input)
		}
		guid, err := hex.DecodeString(*config.DeviceGUIDHex)
		if err != nil {
			t.Fatalf("harness error: deviceGuidHex is not hex: %v", err)
		}
		return verifier.VerifyWithDeviceGUID(input, guid)
	},
	// The string form of verifyReceipt: the input fixture is always text
	// (the schema requires it), and fixtureBytes already hands back that
	// text's bytes verbatim, so string(input) is exactly what a client
	// sent — no re-encoding, which is the whole point of this operation.
	"verifyReceiptBase64": func(t *testing.T, config caseConfig, input []byte, codec string, clock func() time.Time) (any, error) {
		if clock != nil {
			t.Fatalf("harness error: verifyReceiptBase64 has no clock seam, but the case pins one")
		}
		if codec != "text" {
			t.Fatalf("harness error: a verifyReceiptBase64 case must name a text fixture, got codec %q", codec)
		}
		if config.BundleID == nil {
			t.Fatalf("harness error: a verifyReceiptBase64 case must configure a bundleId")
		}
		verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
			TrustedRoots: trustedRootsFor(t, config.TrustedRoots),
			BundleID:     *config.BundleID,
		})
		if err != nil {
			t.Fatalf("harness error: building a ReceiptVerifier: %v", err)
		}
		if config.DeviceGUIDHex == nil {
			return verifier.VerifyBase64(string(input))
		}
		guid, err := hex.DecodeString(*config.DeviceGUIDHex)
		if err != nil {
			t.Fatalf("harness error: deviceGuidHex is not hex: %v", err)
		}
		return verifier.VerifyBase64WithDeviceGUID(string(input), guid)
	},
	"verifyReceiptEndpoint": func(t *testing.T, config caseConfig, input []byte, codec string, clock func() time.Time) (any, error) {
		endpoint, err := applereceipt.NewVerifyReceiptEndpoint(applereceipt.VerifyReceiptEndpointOptions{
			TrustedRoots: trustedRootsFor(t, config.TrustedRoots),
			Environment:  config.Environment,
			Now:          clock,
		})
		if err != nil {
			t.Fatalf("harness error: building a VerifyReceiptEndpoint: %v", err)
		}
		// A text fixture's bytes go into receipt-data verbatim, exactly as
		// a client would send them; a raw or base64 fixture is re-encoded
		// as canonical base64, because fixtureBytes already decoded it and
		// there is no "original string" left to pin.
		receiptData := base64.StdEncoding.EncodeToString(input)
		if codec == "text" {
			receiptData = string(input)
		}
		return endpoint.VerifyReceipt(applereceipt.VerifyReceiptRequest{
			ReceiptData: receiptData,
		}), nil
	},
}

func caseClock(t *testing.T, kase conformanceCase) func() time.Time {
	t.Helper()
	if kase.Clock == nil {
		return nil
	}
	at, err := time.Parse(time.RFC3339, kase.Clock.Now)
	if err != nil {
		t.Fatalf("harness error: unparseable clock %q: %v", kase.Clock.Now, err)
	}
	return func() time.Time { return at }
}

// --- one case ------------------------------------------------------------

func runCase(t *testing.T, kase conformanceCase) {
	operation, ok := operations[kase.Operation]
	if !ok {
		t.Fatalf("harness error: no adapter for operation %q", kase.Operation)
	}
	input := fixtureBytes(t, kase.Input.Fixture)
	codec := fixtureCodec(t, kase.Input.Fixture)

	result, err := operation(t, kase.Config, input, codec, caseClock(t, kase))
	if err != nil {
		// Only a *VerificationError carries a canonical Reason. Anything
		// else is a defect in the library or in this harness and must
		// never be read as one of the expected reasons.
		var verr *applereceipt.VerificationError
		if !errors.As(err, &verr) {
			t.Fatalf("harness error: %s returned %T (%v), which is not a *VerificationError",
				kase.Operation, err, err)
		}
		if kase.Expected.Status != "error" {
			t.Fatalf("expected success but got %s: %v", verr.Reason, err)
		}
		if verr.Reason != kase.Expected.Reason {
			t.Fatalf("reason: got %s, want %s (%v)", verr.Reason, kase.Expected.Reason, err)
		}
		return
	}
	if kase.Expected.Status != "ok" {
		t.Fatalf("expected %s but the call returned a value", kase.Expected.Reason)
	}
	actual := normalize(result)
	for path, want := range kase.Expected.Fields {
		got, found := resolvePath(t, actual, path)
		if want == nil {
			// null means "absent or unset".
			if found && got != nil {
				t.Errorf("%s: expected absent, got %#v", path, got)
			}
			continue
		}
		if !found {
			t.Errorf("%s: expected %#v, but the path resolved to nothing", path, want)
			continue
		}
		if !equalValue(got, want) {
			t.Errorf("%s: got %#v, want %#v", path, got, want)
		}
	}
}

// ranCases records which case ids actually executed, so the coverage
// self-check below is a fact rather than a loop-shaped assumption.
var ranCases sync.Map

// subtestFilter reports the -run pattern when it selects subtests (it
// contains a "/"), and "" otherwise.
func subtestFilter() string {
	f := flag.Lookup("test.run")
	if f == nil {
		return ""
	}
	pattern := f.Value.String()
	if strings.Contains(pattern, "/") {
		return pattern
	}
	return ""
}

func TestConformance(t *testing.T) {
	parsed := mustCases(t)
	if len(parsed.Cases) == 0 {
		t.Fatal("cases.json must contain cases")
	}
	for _, kase := range parsed.Cases {
		kase := kase
		t.Run(kase.ID, func(t *testing.T) {
			ranCases.Store(kase.ID, true)
			runCase(t, kase)
		})
	}

	// Coverage self-check: every case in the file ran, asserted against
	// the parsed set and never against a literal count, so a silently
	// dropped case or operation cannot hide. Skips are not tolerated —
	// there is no code path in this adapter that produces one.
	//
	// The only thing that can legitimately leave cases unrun is an
	// explicit subtest filter on the command line, so the check stands
	// down for that and says so rather than reporting a false failure.
	if filter := subtestFilter(); filter != "" {
		t.Logf("-run %q filters subtests; the coverage self-check is only meaningful on a full run", filter)
		return
	}
	var missing []string
	for _, kase := range parsed.Cases {
		if _, ok := ranCases.Load(kase.ID); !ok {
			missing = append(missing, kase.ID)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%d of %d cases did not run: %s",
			len(missing), len(parsed.Cases), strings.Join(missing, ", "))
	}

	// Every operation the schema defines must have been exercised: an
	// operation with no adapter would otherwise only surface if a case
	// happened to use it.
	seen := map[string]int{}
	for _, kase := range parsed.Cases {
		seen[kase.Operation]++
	}
	for _, operation := range []string{
		"verifyTransaction", "verifyAppTransaction", "verifyRaw",
		"verifyReceipt", "verifyReceiptBase64", "verifyReceiptEndpoint",
	} {
		if seen[operation] == 0 {
			t.Errorf("no case exercised operation %q", operation)
		}
		if _, ok := operations[operation]; !ok {
			t.Errorf("this adapter has no dispatch entry for operation %q", operation)
		}
	}
	t.Logf("ran %d conformance cases over %d fixtures (%v)",
		len(parsed.Cases), len(parsed.Fixtures), seen)
}

// --- result normalization ------------------------------------------------

var (
	timeType       = reflect.TypeOf(time.Time{})
	jsonNumberType = reflect.TypeOf(json.Number(""))
)

// normalize renders a returned value into the language-neutral shape the
// field paths are written against: dates as ISO-8601 UTC, byte fields as
// lowercase hex (also mirrored under "<name>Hex", the spelling cases.json
// uses), maps as objects keyed by the stringified key, structs as objects
// keyed by their json tag.
func normalize(value any) any { return normalizeValue(reflect.ValueOf(value)) }

func normalizeValue(rv reflect.Value) any {
	if !rv.IsValid() {
		return nil
	}
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return normalizeValue(rv.Elem())
	}
	switch rv.Type() {
	case timeType:
		return isoUTC(rv.Interface().(time.Time))
	case jsonNumberType:
		number := rv.Interface().(json.Number)
		if i, err := number.Int64(); err == nil {
			return i
		}
		f, err := number.Float64()
		if err != nil {
			return number.String()
		}
		return f
	}
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return hex.EncodeToString(byteSlice(rv))
		}
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return nil
		}
		out := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out[i] = normalizeValue(rv.Index(i))
		}
		return out
	case reflect.Map:
		if rv.IsNil() {
			return nil
		}
		out := make(map[string]any, rv.Len())
		for _, key := range rv.MapKeys() {
			out[fmt.Sprint(key.Interface())] = normalizeValue(rv.MapIndex(key))
		}
		return out
	case reflect.Struct:
		return normalizeStruct(rv)
	case reflect.String:
		return rv.String()
	case reflect.Bool:
		return rv.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int64(rv.Uint())
	case reflect.Float32, reflect.Float64:
		return rv.Float()
	}
	return rv.Interface()
}

func normalizeStruct(rv reflect.Value) map[string]any {
	out := map[string]any{}
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		if !field.IsExported() {
			continue
		}
		name, omitEmpty := jsonFieldName(field)
		if name == "-" {
			continue
		}
		value := rv.Field(i)
		if omitEmpty && value.IsZero() {
			continue
		}
		out[name] = normalizeValue(value)
		// cases.json spells a byte field "<name>Hex"; mirror it so both
		// spellings resolve to the same lowercase hex.
		if value.Kind() == reflect.Slice && value.Type().Elem().Kind() == reflect.Uint8 {
			out[name+"Hex"] = out[name]
		}
	}
	return out
}

func jsonFieldName(field reflect.StructField) (string, bool) {
	tag, ok := field.Tag.Lookup("json")
	if !ok || tag == "" {
		return field.Name, false
	}
	parts := strings.Split(tag, ",")
	name := parts[0]
	if name == "" {
		name = field.Name
	}
	for _, opt := range parts[1:] {
		if opt == "omitempty" {
			return name, true
		}
	}
	return name, false
}

func byteSlice(rv reflect.Value) []byte {
	if rv.Kind() == reflect.Slice {
		return rv.Bytes()
	}
	out := make([]byte, rv.Len())
	for i := range out {
		out[i] = byte(rv.Index(i).Uint())
	}
	return out
}

// isoUTC renders an instant as ISO-8601 UTC, dropping a zero millisecond
// component — the spelling cases.json uses.
func isoUTC(at time.Time) string {
	at = at.UTC()
	if at.Nanosecond() == 0 {
		return at.Format("2006-01-02T15:04:05Z")
	}
	return at.Format("2006-01-02T15:04:05.000Z")
}

// --- field paths ---------------------------------------------------------

// A path step is either a name (bundleId, length) or a bracket ([9999],
// [0], [productId=com.example.app.vip]). Bracket contents may hold dots,
// so a plain strings.Split(".") is wrong.
var pathStep = regexp.MustCompile(`^(?:\.?([^.\[\]]+)|\[([^\]]+)\])`)

type step struct {
	bracket bool
	value   string
}

func pathSteps(t *testing.T, path string) []step {
	t.Helper()
	var steps []step
	rest := path
	for rest != "" {
		match := pathStep.FindStringSubmatch(rest)
		if match == nil {
			t.Fatalf("harness error: unparseable field path %q", path)
		}
		if match[1] != "" {
			steps = append(steps, step{value: match[1]})
		} else {
			steps = append(steps, step{bracket: true, value: match[2]})
		}
		rest = rest[len(match[0]):]
	}
	return steps
}

// resolvePath walks the documented grammar: a.b, x.length, [9999][0] and
// list[key=value].field. It reports whether the path resolved at all, so
// "absent" and "present but nil" stay distinguishable.
func resolvePath(t *testing.T, root any, path string) (any, bool) {
	t.Helper()
	current := root
	for _, s := range pathSteps(t, path) {
		if current == nil {
			return nil, false
		}
		if !s.bracket {
			if s.value == "length" {
				if list, ok := current.([]any); ok {
					current = int64(len(list))
					continue
				}
			}
			object, ok := current.(map[string]any)
			if !ok {
				return nil, false
			}
			value, present := object[s.value]
			if !present {
				return nil, false
			}
			current = value
			continue
		}
		if key, want, isSelector := strings.Cut(s.value, "="); isSelector && key != "" {
			list, ok := current.([]any)
			if !ok {
				t.Fatalf("%s: [%s] does not select from a list", path, s.value)
			}
			var matches []any
			for _, element := range list {
				object, ok := element.(map[string]any)
				if ok && fmt.Sprint(object[key]) == want {
					matches = append(matches, element)
				}
			}
			if len(matches) != 1 {
				t.Fatalf("%s: [%s] must select exactly one element, selected %d",
					path, s.value, len(matches))
			}
			current = matches[0]
			continue
		}
		if list, ok := current.([]any); ok {
			index, err := strconv.Atoi(s.value)
			if err != nil || index < 0 || index >= len(list) {
				return nil, false
			}
			current = list[index]
			continue
		}
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		value, present := object[s.value]
		if !present {
			return nil, false
		}
		current = value
	}
	return current, true
}

// equalValue compares a normalized value against the JSON literal a case
// pins. Numbers arrive from JSON as float64 and from the library as
// int64, so numeric comparison widens; nothing else is coerced.
func equalValue(got, want any) bool {
	switch wanted := want.(type) {
	case string:
		text, ok := got.(string)
		return ok && text == wanted
	case bool:
		value, ok := got.(bool)
		return ok && value == wanted
	case float64:
		switch value := got.(type) {
		case int64:
			return float64(value) == wanted
		case float64:
			return value == wanted
		}
		return false
	}
	return reflect.DeepEqual(got, want)
}
