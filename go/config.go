package applereceipt

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"time"
)

// Config is immutable verifier configuration: the pinned trust anchors and
// the clock.
//
// The clock answers "what time is it now?" and nothing else. The library
// reads it once per call, before it looks at the input, and hands the
// value to the verification module, which uses it in two places: the
// chain check when the receipt or JWS carries no usable signing date, and
// request_date in the endpoint response. A caller-supplied clock must be
// safe to call from several goroutines, and must not answer a time before
// 1970: that is an INTERNAL_ERROR, as a clock that panics is.
type Config struct {
	roots []*x509.Certificate
	clock func() int64
	// builtin marks the default roots: roots is nil and the Verifier sends
	// init an empty list, which means the three Apple roots compiled into
	// the module.
	builtin bool
}

// DefaultConfig is Apple's three pinned roots and the system clock.
//
// The roots are the three published Apple roots compiled into the
// verification module; this package carries no copy of them, so
// Roots() of a DefaultConfig is nil.
func DefaultConfig() *Config {
	return &Config{clock: systemMillis, builtin: true}
}

// ConfigOptions configures a Config.
type ConfigOptions struct {
	// Roots are the pinned anchors, replacing Apple's. Tests use their
	// own. nil means DefaultConfig's roots, the three Apple roots compiled
	// into the module; an explicitly empty non-nil slice is kept as given,
	// and NewVerifier then refuses it: a verifier with no roots would
	// answer UNTRUSTED_CHAIN to everything, and nobody would notice until
	// production.
	Roots []*x509.Certificate

	// Clock is the source of "what time is it now?", as epoch
	// milliseconds. nil means the system clock.
	Clock func() int64
}

// NewConfig builds a Config from opts. A field left unset is
// DefaultConfig's.
func NewConfig(opts ConfigOptions) *Config {
	var roots []*x509.Certificate
	builtin := opts.Roots == nil
	if !builtin {
		roots = append([]*x509.Certificate{}, opts.Roots...)
	}
	clock := opts.Clock
	if clock == nil {
		clock = systemMillis
	}
	return &Config{roots: roots, clock: clock, builtin: builtin}
}

// Roots is the caller's own anchors, an unmodifiable copy, or nil when the
// Config uses the three Apple roots compiled into the module.
func (c *Config) Roots() []*x509.Certificate {
	if c.builtin {
		return nil
	}
	return append([]*x509.Certificate{}, c.roots...)
}

// Clock is the configured clock.
func (c *Config) Clock() func() int64 { return c.clock }

func systemMillis() int64 { return time.Now().UnixMilli() }

// initConfig is init's argument: {"roots":["<base64 DER>", ...]}. An empty
// list means the Apple roots compiled into the module, which is what the
// default Config sends. A caller's own anchors travel as their DER bytes;
// nothing here reads a certificate.
func initConfig(roots []*x509.Certificate, builtin bool) []byte {
	encoded := []string{}
	if !builtin {
		for _, root := range roots {
			encoded = append(encoded, base64.StdEncoding.EncodeToString(root.Raw))
		}
	}
	// Marshal cannot fail on a list of strings.
	out, _ := json.Marshal(struct {
		Roots []string `json:"roots"`
	}{encoded})
	return out
}
