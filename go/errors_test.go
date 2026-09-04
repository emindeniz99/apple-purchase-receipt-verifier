package applereceipt_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// The eleven reason tokens are normative: they are what fixtures/
// cases.schema.json pins and what every port reports. A typo in one is
// otherwise invisible, so the table is written out by hand here rather
// than derived from the constants.
func TestReasonTokensAreTheCanonicalVocabulary(t *testing.T) {
	want := []string{
		"INVALID_JWS_FORMAT",
		"INVALID_CERTIFICATE",
		"INVALID_CERTIFICATE_PURPOSE",
		"INVALID_CHAIN",
		"INVALID_SIGNATURE",
		"WRONG_BUNDLE_ID",
		"WRONG_ENVIRONMENT",
		"WRONG_APP_APPLE_ID",
		"INVALID_RECEIPT_FORMAT",
		"DEVICE_HASH_MISMATCH",
		"STALE_PAYLOAD",
	}
	got := applereceipt.AllReasons()
	if len(got) != len(want) {
		t.Fatalf("the vocabulary has %d reasons, expected %d", len(got), len(want))
	}
	for i, token := range want {
		if string(got[i]) != token {
			t.Errorf("reason %d: got %q, want %q", i, got[i], token)
		}
		if got[i].String() != token {
			t.Errorf("String() on reason %d: got %q", i, got[i].String())
		}
	}
	// Each named constant sits where the table says it does.
	pairs := map[applereceipt.Reason]string{
		applereceipt.ReasonInvalidJWSFormat:          "INVALID_JWS_FORMAT",
		applereceipt.ReasonInvalidCertificate:        "INVALID_CERTIFICATE",
		applereceipt.ReasonInvalidCertificatePurpose: "INVALID_CERTIFICATE_PURPOSE",
		applereceipt.ReasonInvalidChain:              "INVALID_CHAIN",
		applereceipt.ReasonInvalidSignature:          "INVALID_SIGNATURE",
		applereceipt.ReasonWrongBundleID:             "WRONG_BUNDLE_ID",
		applereceipt.ReasonWrongEnvironment:          "WRONG_ENVIRONMENT",
		applereceipt.ReasonWrongAppAppleID:           "WRONG_APP_APPLE_ID",
		applereceipt.ReasonInvalidReceiptFormat:      "INVALID_RECEIPT_FORMAT",
		applereceipt.ReasonDeviceHashMismatch:        "DEVICE_HASH_MISMATCH",
		applereceipt.ReasonStalePayload:              "STALE_PAYLOAD",
	}
	for reason, token := range pairs {
		if string(reason) != token {
			t.Errorf("%v is spelled %q", token, string(reason))
		}
	}
}

func TestAllReasonsReturnsAFreshSlice(t *testing.T) {
	first := applereceipt.AllReasons()
	first[0] = "TAMPERED"
	if applereceipt.AllReasons()[0] != applereceipt.ReasonInvalidJWSFormat {
		t.Fatal("AllReasons must not hand out the package's own slice")
	}
}

func TestErrorReadingStyles(t *testing.T) {
	pki := newReceiptPKI(t)
	other := newReceiptPKI(t)
	_, err := applereceipt.VerifyReceiptCore(pki.receipt(t), other.anchors())
	if err == nil {
		t.Fatal("expected a failure")
	}

	t.Run("errors.As is the canonical read", func(t *testing.T) {
		var verr *applereceipt.VerificationError
		if !errors.As(err, &verr) {
			t.Fatal("errors.As must extract a *VerificationError")
		}
		if verr.Reason != applereceipt.ReasonInvalidChain {
			t.Fatalf("reason: %s", verr.Reason)
		}
	})
	t.Run("errors.Is on a bare Reason works as sugar", func(t *testing.T) {
		if !errors.Is(err, applereceipt.ReasonInvalidChain) {
			t.Fatal("errors.Is(err, ReasonInvalidChain) must match")
		}
		if errors.Is(err, applereceipt.ReasonInvalidSignature) {
			t.Fatal("errors.Is must not cross-match a different reason")
		}
	})
	t.Run("ReasonOf", func(t *testing.T) {
		reason, ok := applereceipt.ReasonOf(err)
		if !ok || reason != applereceipt.ReasonInvalidChain {
			t.Fatalf("ReasonOf: %v %v", reason, ok)
		}
		if _, ok := applereceipt.ReasonOf(errors.New("something else")); ok {
			t.Fatal("ReasonOf must not claim a reason for a foreign error")
		}
		if _, ok := applereceipt.ReasonOf(nil); ok {
			t.Fatal("ReasonOf(nil) must be false")
		}
	})
	t.Run("the message is REASON: detail", func(t *testing.T) {
		if !strings.HasPrefix(err.Error(), "INVALID_CHAIN: ") {
			t.Fatalf("message form: %q", err.Error())
		}
	})
}

func TestUnwrapReachesTheCause(t *testing.T) {
	cause := errors.New("the underlying problem")
	err := &applereceipt.VerificationError{
		Reason: applereceipt.ReasonInvalidReceiptFormat,
		Detail: "wrapped",
		Err:    cause,
	}
	if !errors.Is(err, cause) {
		t.Fatal("Unwrap must expose the cause to errors.Is")
	}
	if errors.Unwrap(err) != cause {
		t.Fatal("errors.Unwrap must return the cause")
	}
}

func TestNilVerificationErrorDoesNotPanic(t *testing.T) {
	var err *applereceipt.VerificationError
	// Calling a method on a typed nil is a mistake, but it must not take
	// the caller's process down with it.
	if err.Error() == "" {
		t.Fatal("Error() on a nil receiver must say something")
	}
	if errors.Unwrap(err) != nil {
		t.Fatal("Unwrap on a nil receiver must be nil")
	}
	if err.Is(applereceipt.ReasonInvalidChain) {
		t.Fatal("Is on a nil receiver must be false")
	}
}

// Detail strings are logged by integrators, so they must not carry
// receipt bytes, claim values or key material (PLAN.md D11 / S11).
func TestErrorMessagesLeakNothingFromTheInput(t *testing.T) {
	pki := newReceiptPKI(t)
	secret := "com.secret.bundle.identifier"
	der := pki.receipt(t,
		attr(2, derUTF8String(secret)),
		attr(3, derUTF8String("9.9.9-secret-build")),
		attr(17, receiptPayload(
			attr(1702, derUTF8String("com.secret.product")),
			attr(1703, derUTF8String("70000000000042")))),
	)

	var messages []string
	verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
		TrustedRoots: pki.anchors(), BundleID: "com.example.app",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(der); err != nil {
		messages = append(messages, err.Error())
	}
	if _, err := verifier.VerifyWithDeviceGUID(der, []byte("guid")); err != nil {
		messages = append(messages, err.Error())
	}
	other := newReceiptPKI(t)
	if _, err := applereceipt.VerifyReceiptCore(der, other.anchors()); err != nil {
		messages = append(messages, err.Error())
	}
	jwsPKI := newJWSPKI(t)
	claims := transactionClaims()
	claims["bundleId"] = secret
	claims["transactionId"] = "70000000000042"
	jwsVerifier := jwsVerifierFor(t, jwsPKI.anchorSlice(), nil)
	if _, err := jwsVerifier.VerifyTransaction(jwsPKI.sign(t, claims)); err != nil {
		messages = append(messages, err.Error())
	}

	if len(messages) < 4 {
		t.Fatalf("expected four failures to inspect, got %d", len(messages))
	}
	forbidden := []string{secret, "9.9.9-secret-build", "com.secret.product", "70000000000042", "guid"}
	for _, message := range messages {
		for _, needle := range forbidden {
			if strings.Contains(message, needle) {
				t.Errorf("error message leaks %q: %s", needle, message)
			}
		}
	}
}

// Every non-nil error a verification entry point returns is a
// *VerificationError. Constructor argument errors are the one exception,
// and they are a different type on purpose.
func TestOnlyVerificationErrorsEscapeTheEntryPoints(t *testing.T) {
	pki := newReceiptPKI(t)
	receiptVerifier := receiptVerifier(t, pki, "com.example.app")
	jws := newJWSPKI(t)
	jwsVerifier := jwsVerifierFor(t, jws.anchorSlice(), nil)

	hostile := [][]byte{
		nil, {}, []byte("garbage"), derSequence(derInt(1)),
		nestedSequences(100), []byte{0x30, 0x80}, []byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
	}
	calls := []struct {
		name string
		call func([]byte) error
	}{
		{"ReceiptVerifier.Verify", func(b []byte) error {
			_, err := receiptVerifier.Verify(b)
			return err
		}},
		{"ReceiptVerifier.VerifyWithDeviceGUID", func(b []byte) error {
			_, err := receiptVerifier.VerifyWithDeviceGUID(b, []byte("guid"))
			return err
		}},
		{"ReceiptVerifier.VerifyBase64", func(b []byte) error {
			_, err := receiptVerifier.VerifyBase64(string(b))
			return err
		}},
		{"VerifyReceiptCore", func(b []byte) error {
			_, err := applereceipt.VerifyReceiptCore(b, pki.anchors())
			return err
		}},
		{"JWSVerifier.VerifyTransaction", func(b []byte) error {
			_, err := jwsVerifier.VerifyTransaction(string(b))
			return err
		}},
		{"JWSVerifier.VerifyAppTransaction", func(b []byte) error {
			_, err := jwsVerifier.VerifyAppTransaction(string(b))
			return err
		}},
		{"JWSVerifier.VerifyRaw", func(b []byte) error {
			_, err := jwsVerifier.VerifyRaw(string(b))
			return err
		}},
	}
	for _, call := range calls {
		call := call
		t.Run(call.name, func(t *testing.T) {
			for i, input := range hostile {
				err := call.call(input)
				if err == nil {
					t.Fatalf("input %d verified", i)
				}
				var verr *applereceipt.VerificationError
				if !errors.As(err, &verr) {
					t.Fatalf("input %d escaped as %T: %v", i, err, err)
				}
			}
		})
	}
}

func TestVerificationErrorFormatsUsefully(t *testing.T) {
	err := &applereceipt.VerificationError{
		Reason: applereceipt.ReasonWrongEnvironment,
		Detail: "payload environment is not in the accepted set",
	}
	want := "WRONG_ENVIRONMENT: payload environment is not in the accepted set"
	if err.Error() != want {
		t.Fatalf("got %q, want %q", err.Error(), want)
	}
	if fmt.Sprintf("%v", err) != want {
		t.Fatalf("%%v: %q", fmt.Sprintf("%v", err))
	}
}
