package applereceipt_test

import (
	"crypto/x509"
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
// network, a subprocess or the file system. None of them may appear in any
// file the library compiles. The crypto, X.509 and ASN.1 packages (crypto/tls
// and golang.org/x/crypto among them) are banned for every wrapper in one
// place, tools/check-one-implementation.mjs.
var forbiddenImports = map[string]string{
	"net":           "no network, ever (PLAN.md D12)",
	"net/http":      "no network, ever (PLAN.md D12)",
	"net/url":       "nothing here has a URL",
	"os/exec":       "a verification library runs no subprocesses",
	"os":            "trust anchors are embedded, never read at call time",
	"io/ioutil":     "trust anchors are embedded, never read at call time",
	"path/filepath": "trust anchors are embedded, never read at call time",
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

// This package is a wrapper: aprv.wasm decides, and no file here parses
// ASN.1, reads a certificate, checks a signature, validates base64 or walks
// a chain. The crypto, X.509 and ASN.1 packages are refused for every
// wrapper by tools/check-one-implementation.mjs (docs/rust-core/
// ARCHITECTURE.md section 9). The encodings below are not crypto, so that
// gate allows them; here each is held to the files that only carry data
// with it.
var verificationImports = map[string][]string{
	"encoding/hex":    {"wasm.go"},
	"encoding/base64": {"receiptpayload.go", "config.go"}, // the wire's bytes fields, and init's roots
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

// The published module has one dependency, wazero, pinned to an exact
// release. wazero's own one requirement, golang.org/x/sys (from wazero
// v1.11), is the only other module in the graph, and only as indirect:
// "audit the supply chain" is still a short answer, and any other
// requirement, or x/sys required directly, fails here.
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
	direct := len(requires) >= 1 && strings.HasPrefix(requires[0], "github.com/tetratelabs/wazero v1.") &&
		!strings.Contains(requires[0], "//")
	indirect := len(requires) == 1 ||
		(len(requires) == 2 && strings.HasPrefix(requires[1], "golang.org/x/sys v0.") &&
			strings.HasSuffix(requires[1], " // indirect"))
	if !direct || !indirect || strings.Contains(string(source), "require (") {
		t.Errorf("go.mod requires %q; want exactly github.com/tetratelabs/wazero at one release,"+
			" and at most golang.org/x/sys as indirect:\n%s", requires, source)
	}
	sums, err := os.ReadFile("go.sum")
	if err != nil {
		t.Fatalf("go.sum is missing: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		if !strings.HasPrefix(line, "github.com/tetratelabs/wazero ") && !strings.HasPrefix(line, "golang.org/x/sys ") {
			t.Errorf("go.sum names another module: %s", line)
		}
	}
	if !strings.Contains(string(source), "module github.com/emindeniz99/apple-purchase-receipt-verifier/go") {
		t.Errorf("the module path is not the published one:\n%s", source)
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
	var _ func() string = payload.JSON
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
