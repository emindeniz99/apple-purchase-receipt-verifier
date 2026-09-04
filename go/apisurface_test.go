package applereceipt_test

import (
	"crypto/x509"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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

// libraryFiles are the non-test Go files a consumer compiles. The
// generator under internal/gencerts is excluded by name: it is a
// `go generate` command, never imported by the library, and reading
// certs/ from disk is its entire job.
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
			case "testdata", "tools", "gencerts":
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

// The published module has no third-party dependencies at all, which is
// what makes "audit the supply chain" a one-line answer.
func TestModuleHasNoDependencies(t *testing.T) {
	source, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if strings.Contains(text, "require") {
		t.Fatalf("go.mod has grown a require block:\n%s", text)
	}
	if _, err := os.Stat("go.sum"); err == nil {
		t.Error("go.sum exists; the library module is supposed to have no dependencies")
	}
	if !strings.Contains(text, "module github.com/emindeniz99/apple-purchase-receipt-verifier/go") {
		t.Errorf("the module path is not the published one:\n%s", text)
	}
}

// The public API shape, asserted by compiling against it. Any signature
// change breaks this file, which is the point: the surface is a contract
// shared with four other ports.
func TestPublicAPIShape(t *testing.T) {
	var (
		_ func(applereceipt.JWSVerifierOptions) (*applereceipt.JWSVerifier, error)                     = applereceipt.NewJWSVerifier
		_ func(applereceipt.ReceiptVerifierOptions) (*applereceipt.ReceiptVerifier, error)             = applereceipt.NewReceiptVerifier
		_ func(applereceipt.VerifyReceiptEndpointOptions) (*applereceipt.VerifyReceiptEndpoint, error) = applereceipt.NewVerifyReceiptEndpoint
		_ func([]byte, []*x509.Certificate) (*applereceipt.AppReceipt, error)                          = applereceipt.VerifyReceiptCore
		_ func() []*x509.Certificate                                                                   = applereceipt.AppleJWSRoots
		_ func() []*x509.Certificate                                                                   = applereceipt.AppleReceiptRoots
		_ func(error) (applereceipt.Reason, bool)                                                      = applereceipt.ReasonOf
		_ func() []applereceipt.Reason                                                                 = applereceipt.AllReasons
	)

	jws := &applereceipt.JWSVerifier{}
	var (
		_ func(string) (*applereceipt.TransactionPayload, error)    = jws.VerifyTransaction
		_ func(string) (*applereceipt.AppTransactionPayload, error) = jws.VerifyAppTransaction
		_ func(string) (applereceipt.Claims, error)                 = jws.VerifyRaw
	)

	receipts := &applereceipt.ReceiptVerifier{}
	// The device-GUID matrix is complete: every input form is reachable
	// with and without the GUID.
	var (
		_ func([]byte) (*applereceipt.AppReceipt, error)         = receipts.Verify
		_ func([]byte, []byte) (*applereceipt.AppReceipt, error) = receipts.VerifyWithDeviceGUID
		_ func(string) (*applereceipt.AppReceipt, error)         = receipts.VerifyBase64
		_ func(string, []byte) (*applereceipt.AppReceipt, error) = receipts.VerifyBase64WithDeviceGUID
	)

	endpoint := &applereceipt.VerifyReceiptEndpoint{}
	var (
		_ func(applereceipt.VerifyReceiptRequest) applereceipt.VerifyReceiptResponse = endpoint.VerifyReceipt
		_ func([]byte) []byte                                                        = endpoint.VerifyReceiptJSON
	)

	payload := &applereceipt.TransactionPayload{}
	var _ func(time.Time) bool = payload.IsActiveAt

	// The status codes this port can produce, and only these.
	for _, status := range []int{
		applereceipt.StatusOK,
		applereceipt.StatusMalformed,
		applereceipt.StatusNotAuthenticated,
		applereceipt.StatusSandboxReceiptOnProduction,
		applereceipt.StatusProductionReceiptOnSandbox,
		applereceipt.StatusInternal,
	} {
		switch status {
		case 0, 21002, 21003, 21007, 21008, 21009:
		default:
			t.Errorf("unexpected status constant %d", status)
		}
	}

	// The four environments, spelled as Apple spells them.
	for environment, want := range map[applereceipt.Environment]string{
		applereceipt.EnvironmentProduction:   "Production",
		applereceipt.EnvironmentSandbox:      "Sandbox",
		applereceipt.EnvironmentXcode:        "Xcode",
		applereceipt.EnvironmentLocalTesting: "LocalTesting",
	} {
		if string(environment) != want || environment.String() != want {
			t.Errorf("environment %q is spelled wrong", want)
		}
	}
}
