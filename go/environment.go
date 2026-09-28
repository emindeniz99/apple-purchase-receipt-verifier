package applereceipt

// Environment is one of Apple's two verifyReceipt hosts, spelled exactly
// as Apple's JWS claims and receipt attributes spell it.
//
// The 0.6 Xcode and LocalTesting values are gone: they only ever named JWS
// environment strings, and such payloads are not Apple-signed and fail
// the chain check regardless. A caller that needs the raw string reads it
// from the verified JSON.
type Environment string

// Apple's two verifyReceipt environments.
const (
	EnvironmentProduction Environment = "Production"
	EnvironmentSandbox    Environment = "Sandbox"
)

// String returns Apple's spelling, as the endpoint response writes it.
func (e Environment) String() string { return string(e) }

// FromReceiptType maps a receipt's receipt_type attribute to the
// Environment it names: "Production" and "ProductionVPP" are
// EnvironmentProduction, "ProductionSandbox" and "ProductionVPPSandbox"
// are EnvironmentSandbox, anything else (including "Xcode" and a missing
// value) reports ok false. It states what Apple's value means and decides
// nothing; VerifyReceiptEndpoint uses the same rule for status 21007 and
// 21008.
func FromReceiptType(receiptType string) (Environment, bool) {
	switch receiptType {
	case "Production", "ProductionVPP":
		return EnvironmentProduction, true
	case "ProductionSandbox", "ProductionVPPSandbox":
		return EnvironmentSandbox, true
	default:
		return "", false
	}
}

// FromJWSEnvironment maps a JWS environment claim to the Environment it
// names: "Production" and "Sandbox", anything else reports ok false.
func FromJWSEnvironment(environment string) (Environment, bool) {
	switch environment {
	case "Production":
		return EnvironmentProduction, true
	case "Sandbox":
		return EnvironmentSandbox, true
	default:
		return "", false
	}
}
