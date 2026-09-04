package applereceipt_test

import (
	"errors"
	"fmt"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// Runnable examples double as the API-shape lock: any signature change
// stops them compiling, and `go test` runs the ones with an Output
// comment. They are also what pkg.go.dev shows.

func ExampleJWSVerifier_VerifyTransaction() {
	verifier, err := applereceipt.NewJWSVerifier(applereceipt.JWSVerifierOptions{
		TrustedRoots: applereceipt.AppleJWSRoots(),
		BundleID:     "com.example.app",
		// Include Sandbox: App Review runs production builds against it,
		// so a Production-only accept set rejects purchases during review.
		AcceptedEnvironments: []applereceipt.Environment{
			applereceipt.EnvironmentProduction,
			applereceipt.EnvironmentSandbox,
		},
		// Reject anything Apple signed more than five minutes ago.
		MaxSignedAge: 5 * time.Minute,
	})
	if err != nil {
		panic(err) // a configuration mistake, not a verification verdict
	}

	payload, err := verifier.VerifyTransaction(signedTransactionFromTheClient)
	if err != nil {
		return // reject the purchase; see Example_errorHandling
	}
	if payload.IsActiveAt(time.Now()) {
		grantEntitlement(payload.ProductID)
	}
}

func ExampleReceiptVerifier_Verify() {
	verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
		TrustedRoots: applereceipt.AppleReceiptRoots(),
		BundleID:     "com.example.app",
	})
	if err != nil {
		panic(err)
	}

	// The base64 blob is what a client sends; Verify takes the DER form
	// and VerifyBase64 the transport form.
	receipt, err := verifier.VerifyBase64(base64ReceiptFromTheClient)
	if err != nil {
		return
	}
	for _, purchase := range receipt.InAppPurchases {
		grantEntitlement(purchase.ProductID)
	}
}

func ExampleReceiptVerifier_VerifyWithDeviceGUID() {
	verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
		TrustedRoots: applereceipt.AppleReceiptRoots(),
		BundleID:     "com.example.app",
	})
	if err != nil {
		panic(err)
	}
	// The device's identifierForVendor as raw bytes. Optional: a server
	// does not always have it, and it binds the receipt to one device.
	guid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}
	if _, err := verifier.VerifyWithDeviceGUID(receiptDER, guid); err != nil {
		return
	}
}

func ExampleVerifyReceiptEndpoint_VerifyReceiptJSON() {
	endpoint, err := applereceipt.NewVerifyReceiptEndpoint(applereceipt.VerifyReceiptEndpointOptions{
		TrustedRoots: applereceipt.AppleReceiptRoots(),
		Environment:  applereceipt.EnvironmentProduction,
	})
	if err != nil {
		panic(err)
	}
	// A drop-in for a POST to Apple's deprecated verifyReceipt: the same
	// request body in, the same response body out. No http.Handler ships
	// with this library — wire it into your own mux.
	response := endpoint.VerifyReceiptJSON(requestBodyFromTheClient)
	_ = response
}

func Example_errorHandling() {
	err := &applereceipt.VerificationError{
		Reason: applereceipt.ReasonWrongEnvironment,
		Detail: "payload environment is not in the accepted set",
	}

	// errors.As is the canonical read: it carries the reason, the
	// log-safe detail, and any wrapped cause.
	var verr *applereceipt.VerificationError
	if errors.As(error(err), &verr) {
		switch verr.Reason {
		case applereceipt.ReasonWrongEnvironment:
			fmt.Println("retry against the other environment")
		case applereceipt.ReasonInvalidChain, applereceipt.ReasonInvalidSignature:
			fmt.Println("alert: this is not an Apple-signed payload")
		default:
			fmt.Println("reject:", verr.Reason)
		}
	}

	// errors.Is on a bare Reason is sugar for the single-reason case.
	if errors.Is(error(err), applereceipt.ReasonWrongEnvironment) {
		fmt.Println("same verdict, read the short way")
	}

	// Output:
	// retry against the other environment
	// same verdict, read the short way
}

func Example_customTrustAnchors() {
	// Anchors always come from the caller. AppleJWSRoots() is a
	// convenience, not a default: an integrator running their own root
	// rotation pipeline passes their own certificates, and nothing in
	// this library ever consults the operating system trust store.
	anchors := applereceipt.AppleReceiptRoots()
	fmt.Println(len(anchors), "pinned Apple roots")
	for _, anchor := range anchors {
		fmt.Println(anchor.Subject.CommonName)
	}

	// Output:
	// 3 pinned Apple roots
	// Apple Root CA
	// Apple Root CA - G2
	// Apple Root CA - G3
}

func ExampleTransactionPayload_IsActiveAt() {
	expires := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	payload := &applereceipt.TransactionPayload{
		ProductID:   "com.example.app.subscription",
		ExpiresDate: &expires,
	}
	fmt.Println(payload.IsActiveAt(time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)))
	fmt.Println(payload.IsActiveAt(time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)))

	// Output:
	// true
	// false
}

// Stand-ins so the examples above read like calling code rather than like
// test scaffolding.
var (
	signedTransactionFromTheClient = ""
	base64ReceiptFromTheClient     = ""
	receiptDER                     []byte
	requestBodyFromTheClient       []byte
)

func grantEntitlement(productID string) { _ = productID }
