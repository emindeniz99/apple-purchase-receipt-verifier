package applereceipt_test

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// A deterministic mutation pass over the genuine receipts and the genuine
// JWS.
//
// Fuzzing is the other half of this (see fuzz_test.go), but a fuzzer that
// runs for sixty seconds in CI is not a regression test: it explores a
// different corpus every time and it does not run at all on `go test`.
// This suite runs on every build, always over the same bytes, so a
// regression reproduces exactly.
//
// Two invariants, and the second is the interesting one:
//
//  1. Nothing but a *Failure ever escapes, and nothing panics.
//  2. A mutation may leave the answer unchanged (a few bytes of a CMS
//     blob are genuinely not consulted, see the CMS signature-algorithm
//     tests), but it may never change what a verified receipt says.
//     "Nothing forged is ever accepted" is the property; "every mutation
//     is rejected" would be a claim about the encoding rather than about
//     security.

type mutationTarget struct {
	name        string
	fixture     string
	roots       func(t *testing.T) []*x509.Certificate
	flipStride  int
	cutStride   int
	spliceStrid int
}

func receiptMutationTargets() []mutationTarget {
	return []mutationTarget{
		{
			name: "generated receipt", fixture: "receipt",
			roots: func(t *testing.T) []*x509.Certificate {
				return []*x509.Certificate{parseFixtureCertificate(t, "receipt-root")}
			},
			flipStride: 3, cutStride: 17, spliceStrid: 29,
		},
		{
			name: "genuine sandbox receipt (SHA-256 chain)", fixture: "public-receipt-sandbox-g5",
			roots:      func(t *testing.T) []*x509.Certificate { return applereceipt.AppleRoots() },
			flipStride: 11, cutStride: 61, spliceStrid: 97,
		},
		{
			name: "genuine legacy receipt (SHA-1 chain)", fixture: "public-receipt-sandbox-legacy",
			roots:      func(t *testing.T) []*x509.Certificate { return applereceipt.AppleRoots() },
			flipStride: 211, cutStride: 1021, spliceStrid: 2039,
		},
	}
}

// mutations builds the deterministic mutation set for one input: single
// byte flips at a fixed stride, truncations at a fixed stride, and byte
// insertions at a fixed stride.
func mutations(input []byte, target mutationTarget) [][]byte {
	var out [][]byte
	for i := 0; i < len(input); i += target.flipStride {
		for _, mask := range []byte{0x01, 0xff} {
			mutated := bytes.Clone(input)
			mutated[i] ^= mask
			out = append(out, mutated)
		}
	}
	for cut := 1; cut < len(input); cut += target.cutStride {
		out = append(out, bytes.Clone(input[:cut]))
	}
	for at := 0; at < len(input); at += target.spliceStrid {
		mutated := make([]byte, 0, len(input)+1)
		mutated = append(mutated, input[:at]...)
		mutated = append(mutated, 0x41)
		mutated = append(mutated, input[at:]...)
		out = append(out, mutated)
	}
	// Trailing garbage, which the parser must refuse rather than ignore.
	out = append(out, append(bytes.Clone(input), 0x00))
	out = append(out, append(bytes.Clone(input), bytes.Repeat([]byte{0xff}, 64)...))
	return out
}

func TestMutatedReceiptsNeverChangeTheAnswer(t *testing.T) {
	total := 0
	accepted := 0
	for _, target := range receiptMutationTargets() {
		target := target
		t.Run(target.name, func(t *testing.T) {
			input := fixtureBytes(t, target.fixture)
			roots := target.roots(t)
			verifier := verifierFor(t, roots)
			genuine, err := verifier.VerifyReceipt(applereceiptBase64(input))
			if err != nil {
				t.Fatalf("the unmutated fixture must verify: %v", err)
			}
			want := genuine.ToJSON()

			cases := mutations(input, target)
			localAccepted := 0
			for i, mutated := range cases {
				result, err := verifyReceiptSafely(verifier, mutated)
				if err != nil {
					var failure *applereceipt.Failure
					if !errors.As(err, &failure) {
						t.Fatalf("mutation %d escaped as %T: %v", i, err, err)
					}
					continue
				}
				localAccepted++
				if got := result.ToJSON(); got != want {
					t.Fatalf("mutation %d verified with a DIFFERENT receipt:\n%s\n%s", i, want, got)
				}
			}
			total += len(cases)
			accepted += localAccepted
			t.Logf("%d mutations; %d left the answer byte-identical, the rest were rejected",
				len(cases), localAccepted)
		})
	}
	t.Logf("%d receipt mutations in total, %d accepted without changing the answer", total, accepted)
}

// verifyReceiptSafely turns a panic into an error so the mutation loop can
// report which input caused it instead of taking the run down. The
// library contains its own panics; this is the harness proving it.
func verifyReceiptSafely(verifier *applereceipt.Verifier, input []byte) (result *applereceipt.ReceiptPayload, err error) {
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = fmt.Errorf("PANIC escaped the library: %v", r)
		}
	}()
	return verifier.VerifyReceipt(applereceiptBase64(input))
}

func TestMutatedJWSNeverVerify(t *testing.T) {
	input := fixtureBytes(t, "transaction")
	root := parseFixtureCertificate(t, "jws-root")
	verifier := verifierFor(t, []*x509.Certificate{root})
	genuine, err := verifier.VerifySignedData(string(input))
	if err != nil {
		t.Fatalf("the unmutated JWS must verify: %v", err)
	}
	want := genuine.JSON()

	cases := mutations(input, mutationTarget{flipStride: 3, cutStride: 13, spliceStrid: 23})
	accepted := 0
	for i, mutated := range cases {
		result, err := verifyJWSSafely(verifier, string(mutated))
		if err != nil {
			var failure *applereceipt.Failure
			if !errors.As(err, &failure) {
				t.Fatalf("mutation %d escaped as %T: %v", i, err, err)
			}
			continue
		}
		accepted++
		if got := result.JSON(); got != want {
			t.Fatalf("mutation %d verified with a DIFFERENT payload:\n%s\n%s", i, want, got)
		}
	}
	t.Logf("%d JWS mutations; %d left the answer byte-identical", len(cases), accepted)
	// A JWS is signed end to end: unlike a CMS blob it has no unconsulted
	// structural fields, so every mutation of these bytes must be
	// rejected outright.
	if accepted != 0 {
		t.Fatalf("%d JWS mutations verified; every byte of a compact JWS is covered", accepted)
	}
}

func verifyJWSSafely(verifier *applereceipt.Verifier, input string) (result *applereceipt.JSONPayload, err error) {
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = fmt.Errorf("PANIC escaped the library: %v", r)
		}
	}()
	return verifier.VerifySignedData(input)
}

// The forged-receipt matrix: a receipt whose payload has been swapped for
// an attacker's while keeping the genuine signature, and one signed by an
// attacker's chain while keeping the genuine payload.
func TestForgedReceiptsAreRejected(t *testing.T) {
	genuine := newReceiptPKI(t)
	attacker := newReceiptPKI(t)
	payload := receiptPayload(
		attr(0, derUTF8String("Production")),
		attr(2, derUTF8String("com.example.app")),
		attr(3, derUTF8String("1.2.3")),
	)
	forgedPayload := receiptPayload(
		attr(0, derUTF8String("Production")),
		attr(2, derUTF8String("com.example.app")),
		attr(3, derUTF8String("9.9.9")),
		attr(17, receiptPayload(attr(1702, derUTF8String("com.example.app.everything")))),
	)

	t.Run("attacker payload under the genuine signature", func(t *testing.T) {
		// Rebuilding the CMS around a different payload keeps the
		// signature bytes but breaks the messageDigest binding.
		real := buildCMS(t, cmsSpec{
			content: payload, signer: genuine.leaf,
			certificates: genuine.embedded(), withSignedAttrs: true,
		})
		forged := bytes.Replace(real, payload, forgedPayload, 1)
		if bytes.Equal(real, forged) {
			t.Skip("the payload could not be located in the blob")
		}
		_, err := verifierFor(t, genuine.anchors()).VerifyReceipt(applereceiptBase64(forged))
		if err == nil {
			t.Fatal("a swapped payload must never verify")
		}
	})
	t.Run("attacker chain over the genuine payload", func(t *testing.T) {
		forged := buildCMS(t, cmsSpec{
			content: payload, signer: attacker.leaf,
			certificates: attacker.embedded(), withSignedAttrs: true,
		})
		_, err := verifierFor(t, genuine.anchors()).VerifyReceipt(applereceiptBase64(forged))
		requireReason(t, err, applereceipt.ReasonUntrustedChain)
	})
	t.Run("attacker leaf under the genuine root, without the marker OID", func(t *testing.T) {
		// The forgery hole a developer certificate would otherwise open: it
		// chains through the same intermediate to the same root.
		developer := issueCert(t, certSpec{
			commonName: "Apple Distribution: Some Developer", rsa: true,
		}, genuine.intermediate)
		forged := buildCMS(t, cmsSpec{
			content: forgedPayload, signer: developer,
			certificates:    [][]byte{developer.der, genuine.intermediate.der},
			withSignedAttrs: true,
		})
		_, err := verifierFor(t, genuine.anchors()).VerifyReceipt(applereceiptBase64(forged))
		requireReason(t, err, applereceipt.ReasonInvalidCertificatePurpose)
	})
}
