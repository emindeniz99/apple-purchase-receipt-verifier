package applereceipt

// Environment is one of Apple's two verifyReceipt hosts, spelled exactly
// as Apple's JWS claims and receipt attributes spell it. It is the
// environment VerifyReceiptEndpoint imitates, and the one a verified
// payload names (ReceiptPayload.Environment, JSONPayload.Environment), as
// the module states it.
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
