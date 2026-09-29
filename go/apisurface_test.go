package applereceipt_test

import (
	"crypto/x509"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// Structural gates. A code review habit is not a control; these are.

// forbiddenImports are the packages that would let this library reach the
// network or the operating system trust store. None of them may appear in
// any file the library compiles.
var forbiddenImports = map[string]string{
	"net":                      "no network, ever (PLAN.md D12)",
	"net/http":                 "no network, ever (PLAN.md D12)",
	"net/url":                  "nothing here has a URL",
	"golang.org/x/crypto/ocsp": "revocation checking is disabled by design",
	"os/exec":                  "a verification library runs no subprocesses",
	"crypto/tls":               "no network, ever",
	"os":                       "trust anchors are embedded, never read at call time",
	"io/ioutil":                "trust anchors are embedded, never read at call time",
	"path/filepath":            "trust anchors are embedded, never read at call time",
}

// forbiddenIdentifiers would reintroduce the platform trust evaluation
// the hand-written path builder exists to avoid.
var forbiddenIdentifiers = []string{
	"x509.SystemCertPool",
	"x509.NewCertPool",
	"x509.CertPool",
	"x509.VerifyOptions",
	"CheckSignatureFrom",
	"SetDefaultPaths",
}

// libraryFiles are the non-test Go files a consumer compiles. One command
// is excluded by name, since the library never imports it:
// internal/corpusrun, the corpus runner that reads a calls file.
func libraryFiles(t *testing.T) []string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "testdata", "tools", "corpusrun":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 8 {
		t.Fatalf("only found %d library files; the walk is wrong", len(files))
	}
	return files
}

func TestLibraryImportsNothingForbidden(t *testing.T) {
	fileSet := token.NewFileSet()
	for _, path := range libraryFiles(t) {
		file, err := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, spec := range file.Imports {
			name, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if why, forbidden := forbiddenImports[name]; forbidden {
				t.Errorf("%s imports %q: %s", filepath.Base(path), name, why)
			}
		}
	}
}

func TestLibraryMentionsNoForbiddenIdentifier(t *testing.T) {
	for _, path := range libraryFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		// Identifiers only, so the comment that explains WHY the platform
		// verifier is never called does not trip the gate enforcing it.
		text := stripComments(t, path, source)
		for _, identifier := range forbiddenIdentifiers {
			if strings.Contains(text, identifier) {
				t.Errorf("%s uses %s outside a comment; the path builder is hand-written "+
					"precisely so the platform verifier is never reached",
					filepath.Base(path), identifier)
			}
		}
	}
}

// This package is a wrapper: aprv.wasm decides, and no file here parses
// ASN.1, reads a certificate, checks a signature, validates base64 or walks
// a chain. The imports a verifier would need are refused outright, and the
// few that only carry data are allowed in the one file that carries it.
// This is the Go half of the one-implementation gate of
// docs/rust-core/ARCHITECTURE.md section 9; CI runs a cruder grep beside it.
var verificationImports = map[string][]string{
	"encoding/asn1":    nil,
	"encoding/pem":     nil,
	"crypto/ecdsa":     nil,
	"crypto/ed25519":   nil,
	"crypto/elliptic":  nil,
	"crypto/rsa":       nil,
	"crypto/dsa":       nil,
	"crypto/sha1":      nil,
	"crypto/sha512":    nil,
	"crypto/hmac":      nil,
	"crypto/subtle":    nil,
	"math/big":         nil,
	"crypto/x509/pkix": nil,
	"crypto/x509":      {"config.go"}, // the Config's trust-anchor type, and .Raw
	"crypto/sha256":    {"wasm.go"},   // pins the embedded module
	"encoding/hex":     {"wasm.go"},
	"encoding/base64":  {"receiptpayload.go", "config.go"}, // the wire's bytes fields, and init's roots
}

func TestLibraryHoldsNoVerificationLogic(t *testing.T) {
	fileSet := token.NewFileSet()
	for _, path := range libraryFiles(t) {
		file, err := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, spec := range file.Imports {
			name, _ := strconv.Unquote(spec.Path.Value)
			allowed, listed := verificationImports[name]
			if !listed {
				continue
			}
			if !slices.Contains(allowed, filepath.Base(path)) {
				t.Errorf("%s imports %q: a wrapper holds no verification logic (allowed only in %v)",
					filepath.Base(path), name, allowed)
			}
		}
	}
}

// Of what crypto/x509 offers, the library uses the certificate type and its
// .Raw DER, nothing else: the Apple roots are compiled into the module, so
// no file here reads a certificate. Nothing checks a signature, builds a
// path or reads a name.
func TestNoCertificateIsEverParsed(t *testing.T) {
	for _, path := range libraryFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := stripComments(t, path, source)
		for _, identifier := range []string{"x509.ParseCertificate", "x509.ParseCertificates", "x509.ParseCertificateRequest"} {
			if strings.Contains(text, identifier) {
				t.Errorf("%s uses %s: the wrapper reads no certificate; the module holds the roots", filepath.Base(path), identifier)
			}
		}
	}
}

func stripComments(t *testing.T, path string, source []byte) string {
	t.Helper()
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var out strings.Builder
	ast.Inspect(file, func(node ast.Node) bool {
		if identifier, ok := node.(*ast.Ident); ok {
			out.WriteString(identifier.Name)
			out.WriteByte(' ')
		}
		if selector, ok := node.(*ast.SelectorExpr); ok {
			if pkg, ok := selector.X.(*ast.Ident); ok {
				out.WriteString(pkg.Name + "." + selector.Sel.Name)
				out.WriteByte(' ')
			}
		}
		return true
	})
	return out.String()
}

// The published module has one dependency, wazero, pinned to an exact
// release, and wazero itself has none: "audit the supply chain" is still a
// short answer, and a second requirement fails here.
func TestModuleDependsOnlyOnWazero(t *testing.T) {
	source, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	var requires []string
	for _, line := range strings.Split(string(source), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "require "); ok {
			requires = append(requires, rest)
		}
	}
	if len(requires) != 1 || !strings.HasPrefix(requires[0], "github.com/tetratelabs/wazero v1.") ||
		strings.Contains(requires[0], "//") || strings.Contains(string(source), "require (") {
		t.Errorf("go.mod requires %q; want exactly github.com/tetratelabs/wazero at one release:\n%s", requires, source)
	}
	sums, err := os.ReadFile("go.sum")
	if err != nil {
		t.Fatalf("go.sum is missing: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		if !strings.HasPrefix(line, "github.com/tetratelabs/wazero ") {
			t.Errorf("go.sum names another module: %s", line)
		}
	}
	if !strings.Contains(string(source), "module github.com/emindeniz99/apple-purchase-receipt-verifier/go") {
		t.Errorf("the module path is not the published one:\n%s", source)
	}
}

// The bounds are the core's, and this package only states them. The
// numbers are Apple's own for the two 3 MiB caps (measured 2026-09-23: a
// 3,145,728-byte request body is answered and one byte more gets HTTP 413)
// and the same in every port (fixtures/cases.schema.json, 0.7-api.md,
// Bounds).
func TestCapNumbersMatchTheOtherPorts(t *testing.T) {
	for _, entry := range []struct {
		name      string
		got, want int
	}{
		{"MaxReceiptBytes", applereceipt.MaxReceiptBytes, 3145728},
		{"MaxRequestBytes", applereceipt.MaxRequestBytes, 3145728},
		{"MaxJWSBytes", applereceipt.MaxJWSBytes, 262144},
		{"MaxJSONNestingDepth", applereceipt.MaxJSONNestingDepth, 64},
		{"MaxJSONMemberNameLength", applereceipt.MaxJSONMemberNameLength, 50000},
		{"MaxJSONNumberDigits", applereceipt.MaxJSONNumberDigits, 1000},
	} {
		if entry.got != entry.want {
			t.Errorf("%s = %d, want %d (the number every port uses)", entry.name, entry.got, entry.want)
		}
	}
}

// The public API shape, asserted by compiling against it. Any signature
// change breaks this file, which is the point: the surface is a contract
// shared with the other ports at the 0.7 API (docs/design/0.7-api.md).
func TestPublicAPIShape(t *testing.T) {
	var (
		_ func(*applereceipt.Config) (*applereceipt.Verifier, error) = applereceipt.NewVerifier
		_ func() *applereceipt.Config                                = applereceipt.DefaultConfig
		_ func(applereceipt.ConfigOptions) *applereceipt.Config      = applereceipt.NewConfig
		_ func(error) (applereceipt.Reason, bool)                    = applereceipt.ReasonOf
		_ func() []applereceipt.Reason                               = applereceipt.AllReasons
		_ string                                                     = applereceipt.Version
	)

	config := &applereceipt.Config{}
	var (
		_ func() []*x509.Certificate = config.Roots
		_ func() func() int64        = config.Clock
	)

	verifier := &applereceipt.Verifier{}
	var (
		_ func(string) (*applereceipt.ReceiptPayload, error) = verifier.VerifyReceipt
		_ func(string) (*applereceipt.JSONPayload, error)    = verifier.VerifySignedData
		_ func(applereceipt.Environment, string) string      = verifier.VerifyReceiptEndpoint
	)

	payload := &applereceipt.JSONPayload{}
	var (
		_ func() string = payload.JSON
		_ func() string = payload.String
	)
	_ = applereceipt.NewJSONPayload("{}")

	failure := &applereceipt.Failure{}
	var (
		_ func() string       = failure.Error
		_ func() error        = failure.Unwrap
		_ func(error) bool    = failure.Is
		_ applereceipt.Reason = failure.Reason
		_ string              = failure.Message
		_ error               = failure.Cause
	)

	// The status codes this port's endpoint can produce, and only these.
	for _, status := range []int{
		applereceipt.StatusOK,
		applereceipt.StatusMalformedReceiptData,
		applereceipt.StatusNotAuthenticated,
		applereceipt.StatusSandboxReceiptOnProduction,
		applereceipt.StatusProductionReceiptOnSandbox,
		applereceipt.StatusInternalDataAccessError,
	} {
		switch status {
		case 0, 21002, 21003, 21007, 21008, 21009:
		default:
			t.Errorf("unexpected status constant %d", status)
		}
	}

	// The two environments the 0.7 API models, spelled as Apple spells
	// them. Xcode and LocalTesting are gone: nothing an offline verifier
	// checks distinguishes them from Sandbox (docs/design/0.7-api.md).
	for environment, want := range map[applereceipt.Environment]string{
		applereceipt.EnvironmentProduction: "Production",
		applereceipt.EnvironmentSandbox:    "Sandbox",
	} {
		if string(environment) != want || environment.String() != want {
			t.Errorf("environment %q is spelled wrong", want)
		}
	}

	// The eight-reason vocabulary, by symbol rather than by string (the
	// exact tokens are pinned in errors_test.go).
	var reasons = []applereceipt.Reason{
		applereceipt.ReasonMalformed,
		applereceipt.ReasonTooLarge,
		applereceipt.ReasonInvalidSignature,
		applereceipt.ReasonUntrustedChain,
		applereceipt.ReasonInvalidCertificate,
		applereceipt.ReasonInvalidCertificatePurpose,
		applereceipt.ReasonUnreadablePayload,
		applereceipt.ReasonInternalError,
	}
	if len(reasons) != len(applereceipt.AllReasons()) {
		t.Errorf("this file's reason list and AllReasons() have drifted apart")
	}
}
