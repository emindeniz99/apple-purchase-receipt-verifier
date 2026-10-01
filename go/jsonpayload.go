package applereceipt

// JSONPayload is a verified JWS payload: the JSON object Apple signed,
// unchanged.
//
// The library reads only signedDate from it. Parse JSON() with the JSON
// library of your choice, into a struct declaring the claims you use;
// Apple's claims are epoch milliseconds already. No typed JWS models ship
// with this library: Apple's own app-store-server-library publishes the
// transaction, renewal and notification model classes for languages that
// have one.
type JSONPayload struct {
	json string
}

// NewJSONPayload wraps json as a JSONPayload. Public so callers can build
// one in their own tests.
func NewJSONPayload(json string) *JSONPayload { return &JSONPayload{json: json} }

// JSON is the verified payload, exactly as signed.
func (p *JSONPayload) JSON() string { return p.json }
