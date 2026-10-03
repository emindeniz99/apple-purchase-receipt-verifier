package applereceipt

// JSONPayload is a verified JWS payload: the JSON object Apple signed,
// unchanged, and the environment it names.
//
// The library reads only signedDate from it. Parse JSON() with the JSON
// library of your choice, into a struct declaring the claims you use;
// Apple's claims are epoch milliseconds already. No typed JWS models ship
// with this library: Apple's own app-store-server-library publishes the
// transaction, renewal and notification model classes for languages that
// have one.
type JSONPayload struct {
	json        string
	environment *Environment
}

// NewJSONPayload wraps json and the environment it names (nil for none) as
// a JSONPayload. Public so callers can build one in their own tests; the
// payload states the environment it is given, and nothing reads it from
// json.
func NewJSONPayload(json string, environment *Environment) *JSONPayload {
	return &JSONPayload{json: json, environment: copyEnvironment(environment)}
}

// JSON is the verified payload, exactly as signed.
func (p *JSONPayload) JSON() string { return p.json }

// Environment is the environment the payload names, as the verifier read
// it: from the first of the three places Apple documents that is present,
// the top-level environment (a transaction, renewal info),
// data.environment (an App Store Server Notification V2) and
// summary.environment (a summary notification). "Production" is
// EnvironmentProduction and "Sandbox" EnvironmentSandbox; anything else
// there ("Xcode", "LocalTesting", a value that is not a string), or none
// of the three, is nil. It states what Apple's value means and decides
// nothing. Each call returns a fresh pointer.
func (p *JSONPayload) Environment() *Environment { return copyEnvironment(p.environment) }

func copyEnvironment(environment *Environment) *Environment {
	if environment == nil {
		return nil
	}
	copied := *environment
	return &copied
}
