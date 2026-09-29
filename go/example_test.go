package applereceipt_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// Runnable examples double as the API-shape lock: any signature change
// stops them compiling, and `go test` runs the ones with an Output
// comment. They are also what pkg.go.dev shows.

func ExampleVerifier_VerifySignedData() {
	verifier, err := applereceipt.NewVerifier(applereceipt.DefaultConfig())
	if err != nil {
		panic(err) // a configuration mistake, not a verification verdict
	}

	payload, err := verifier.VerifySignedData(signedTransactionFromTheClient)
	if err != nil {
		return // reject the purchase; see Example_errorHandling
	}
	// No typed JWS models ship with this library: parse JSON() with the
	// JSON library of your choice, into a struct declaring the claims you
	// use. Bundle id, product id, environment and every other business
	// rule is the caller's decision: this call answers only "did Apple
	// sign this".
	var transaction struct {
		ProductID      string `json:"productId"`
		ExpiresDate    *int64 `json:"expiresDate"`
		RevocationDate *int64 `json:"revocationDate"`
	}
	if err := json.Unmarshal([]byte(payload.JSON()), &transaction); err != nil {
		return
	}
	expired := transaction.ExpiresDate != nil && *transaction.ExpiresDate <= time.Now().UnixMilli()
	if transaction.RevocationDate == nil && !expired {
		grantEntitlement(transaction.ProductID)
	}
}

func ExampleVerifier_VerifyReceipt() {
	verifier, err := applereceipt.NewVerifier(applereceipt.DefaultConfig())
	if err != nil {
		panic(err)
	}

	// The base64 blob is what a client sends.
	receipt, err := verifier.VerifyReceipt(base64ReceiptFromTheClient)
	if err != nil {
		return
	}
	for _, purchase := range receipt.InApp {
		if purchase.ProductID != nil {
			grantEntitlement(*purchase.ProductID)
		}
	}
}

func ExampleVerifier_VerifyReceiptEndpoint() {
	verifier, err := applereceipt.NewVerifier(applereceipt.DefaultConfig())
	if err != nil {
		panic(err)
	}
	// A drop-in for a POST to Apple's deprecated verifyReceipt: the same
	// request body in, the same response body out. No http.Handler ships
	// with this library — wire it into your own mux.
	response := verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentProduction, requestBodyFromTheClient)
	_ = response
}

func Example_errorHandling() {
	err := &applereceipt.Failure{
		Reason:  applereceipt.ReasonUntrustedChain,
		Message: "chain does not reach a pinned root",
	}

	// errors.As is the canonical read: it carries the reason, the
	// log-safe message, and any wrapped cause.
	var failure *applereceipt.Failure
	if errors.As(error(err), &failure) {
		switch failure.Reason {
		case applereceipt.ReasonUntrustedChain, applereceipt.ReasonInvalidSignature:
			fmt.Println("alert: this is not an Apple-signed payload")
		default:
			fmt.Println("reject:", failure.Reason)
		}
	}

	// errors.Is on a bare Reason is sugar for the single-reason case.
	if errors.Is(error(err), applereceipt.ReasonUntrustedChain) {
		fmt.Println("same verdict, read the short way")
	}

	// Output:
	// alert: this is not an Apple-signed payload
	// same verdict, read the short way
}

func Example_customTrustAnchors() {
	// Anchors always come from the Config. DefaultConfig trusts the three
	// published Apple roots compiled into the verification module, so it
	// names none of its own: Roots() is nil. An integrator running their
	// own root rotation pipeline passes their own certificates via
	// ConfigOptions.Roots, and nothing in this library ever consults the
	// operating system trust store.
	defaults := applereceipt.DefaultConfig()
	fmt.Println("the defaults use the module's Apple roots:", defaults.Roots() == nil)

	// Output:
	// the defaults use the module's Apple roots: true
}

// Stand-ins so the examples above read like calling code rather than like
// test scaffolding.
var (
	signedTransactionFromTheClient = ""
	base64ReceiptFromTheClient     = ""
	requestBodyFromTheClient       = ""
)

func grantEntitlement(productID string) { _ = productID }
