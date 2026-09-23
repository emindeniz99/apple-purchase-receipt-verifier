package applereceipt

// The cross-port benchmark: the same six operations on the same two
// genuine sandbox receipts in every port, named after the Java JMH
// benchmarks in java-bench/ (BENCHMARKS.md at the repository root has the
// table). It lives in the internal test package only so decodeBase64, the
// library's own receipt-data decoder, can be timed on its own; every
// other benchmark goes through the exported API.
//
//	go test -run '^$' -bench '^BenchmarkCrossPort$' -benchtime 1s -count 5 .

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type crossPortFixture struct {
	name       string
	bundleID   string
	inAppCount int
	sha256     string
}

// The bundle ids, in-app counts and digests fixtures/cases.json pins.
var crossPortFixtures = []crossPortFixture{
	{"receipt-sandbox-g5", "dev.bonzer.weeka.app", 2,
		"bebb16e2a17104d973eeef08177003f2c3303a19ddced83b42df349b4ac25ee0"},
	{"receipt-sandbox-legacy", "com.nutcall.alert", 187,
		"ec62c6bd4a34bd8e56b11e675bf5a28319ce69b71d050e73344bab22f46799a8"},
}

type crossPortInputs struct {
	der, tampered       []byte
	base64, request     string
	verifier            *ReceiptVerifier
	sandbox, production *VerifyReceiptEndpoint
}

func BenchmarkCrossPort(b *testing.B) {
	roots := AppleReceiptRoots()
	for _, fixture := range crossPortFixtures {
		in := crossPortSetUp(b, fixture, roots)
		b.Run("decodeBase64/"+fixture.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if decodeBase64(in.base64, MaxReceiptBytes) == nil {
					b.Fatal("decode failed")
				}
			}
		})
		b.Run("core/"+fixture.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := VerifyReceiptCore(in.der, roots); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("verifierBase64/"+fixture.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := in.verifier.VerifyBase64(in.base64); err != nil {
					b.Fatal(err)
				}
			}
		})
		body := []byte(in.request)
		b.Run("endpointJson/"+fixture.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				in.sandbox.VerifyReceiptJSON(body)
			}
		})
		request := VerifyReceiptRequest{ReceiptData: in.base64}
		b.Run("retryViaResult/"+fixture.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := in.production.VerifyReceipt(request).JSONFor(EnvironmentSandbox); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("rejectTamperedSignature/"+fixture.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := VerifyReceiptCore(in.tampered, roots); err == nil {
					b.Fatal("the tampered receipt verified")
				}
			}
		})
	}
}

// crossPortSetUp prepares every input and runs each call once, failing
// unless it gives the answer the conformance suite expects, so no
// benchmark can time a fast failure by accident.
func crossPortSetUp(b *testing.B, fixture crossPortFixture, roots []*x509.Certificate) crossPortInputs {
	b.Helper()
	dir, err := crossPortFixturesDir()
	if err != nil {
		b.Fatal(err)
	}
	text, err := os.ReadFile(filepath.Join(dir, "public-receipts", fixture.name+".b64"))
	if err != nil {
		b.Fatal(err)
	}
	// The files are line-wrapped; strip the line breaks before a strict decode.
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(text)), ""))
	if err != nil {
		b.Fatal(err)
	}
	digest := sha256.Sum256(der)
	if hex.EncodeToString(digest[:]) != fixture.sha256 {
		b.Fatalf("%s does not match its contentSha256 in cases.json", fixture.name)
	}
	in := crossPortInputs{der: der, tampered: crossPortTamper(b, der)}
	in.base64 = base64.StdEncoding.EncodeToString(der)
	in.request = `{"receipt-data":"` + in.base64 + `"}`
	in.verifier, err = NewReceiptVerifier(ReceiptVerifierOptions{TrustedRoots: roots, BundleID: fixture.bundleID})
	if err != nil {
		b.Fatal(err)
	}
	fixed := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	in.sandbox, err = NewVerifyReceiptEndpoint(VerifyReceiptEndpointOptions{
		TrustedRoots: roots, Environment: EnvironmentSandbox, Now: fixed})
	if err != nil {
		b.Fatal(err)
	}
	in.production, err = NewVerifyReceiptEndpoint(VerifyReceiptEndpointOptions{
		TrustedRoots: roots, Environment: EnvironmentProduction, Now: fixed})
	if err != nil {
		b.Fatal(err)
	}

	if !bytes.Equal(decodeBase64(in.base64, MaxReceiptBytes), der) {
		b.Fatal("decodeBase64 did not return the fixture's DER")
	}
	for _, verify := range []func() (*AppReceipt, error){
		func() (*AppReceipt, error) { return VerifyReceiptCore(der, roots) },
		func() (*AppReceipt, error) { return in.verifier.VerifyBase64(in.base64) },
	} {
		receipt, err := verify()
		if err != nil {
			b.Fatal(err)
		}
		if receipt.BundleID != fixture.bundleID || len(receipt.InAppPurchases) != fixture.inAppCount {
			b.Fatalf("unexpected receipt %s with %d in-app purchases",
				receipt.BundleID, len(receipt.InAppPurchases))
		}
	}
	if out := in.sandbox.VerifyReceiptJSON([]byte(in.request)); !bytes.HasPrefix(out, []byte(`{"status":0,`)) {
		b.Fatalf("endpointJson answered %.80s", out)
	}
	retry, err := in.production.VerifyReceipt(VerifyReceiptRequest{ReceiptData: in.base64}).JSONFor(EnvironmentSandbox)
	if err != nil || !bytes.HasPrefix(retry, []byte(`{"status":0,"environment":"Sandbox",`)) {
		b.Fatalf("retryViaResult answered %.80s (%v)", retry, err)
	}
	_, err = VerifyReceiptCore(in.tampered, roots)
	if reason, _ := ReasonOf(err); reason != ReasonInvalidSignature {
		b.Fatalf("the tampered receipt was answered with %v", err)
	}
	return in
}

// crossPortTamper flips one bit in the middle of the SignerInfo signature,
// the byte java-bench's flipSignatureByte flips. In both fixtures the
// signature is a 256-byte OCTET STRING that ends the DER (openssl
// asn1parse shows it), so the middle byte is 128 from the end; setup
// then proves the flip lands in the signature by requiring
// INVALID_SIGNATURE.
func crossPortTamper(b *testing.B, der []byte) []byte {
	b.Helper()
	if len(der) < 256 {
		b.Fatal("receipt too short to hold a 256-byte signature")
	}
	tampered := bytes.Clone(der)
	tampered[len(tampered)-128] ^= 0x01
	return tampered
}

func crossPortFixturesDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "fixtures", "cases.json")); err == nil {
			return filepath.Join(dir, "fixtures"), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no fixtures/cases.json above the working directory")
		}
		dir = parent
	}
}
