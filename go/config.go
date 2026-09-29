package applereceipt

import (
	"crypto/x509"
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
	// builtin marks the default roots: the Verifier then sends init an
	// empty list, which means the three Apple roots compiled into the
	// module, rather than the copy of them in roots.
	builtin bool
}

// DefaultConfig is Apple's pinned roots and the system clock.
//
// It panics if the bundled roots are missing or fail their pinned SHA-256
// fingerprints (see AppleRoots), which cannot happen without a build that
// already failed this package's own tests: a startup failure, not a
// verification verdict, so it happens once, before any input is read,
// rather than as an error a caller must remember to check on every call.
func DefaultConfig() *Config {
	return &Config{roots: mustAppleRoots(), clock: systemMillis, builtin: true}
}

// ConfigOptions configures a Config.
type ConfigOptions struct {
	// Roots are the pinned anchors, replacing Apple's bundled ones. Tests
	// use their own. nil means DefaultConfig's roots; an explicitly empty
	// non-nil slice is kept as given, and NewVerifier then refuses it: a
	// verifier with no roots would answer UNTRUSTED_CHAIN to everything,
	// and nobody would notice until production.
	Roots []*x509.Certificate

	// Clock is the source of "what time is it now?", as epoch
	// milliseconds. nil means the system clock.
	Clock func() int64
}

// NewConfig builds a Config from opts. A field left unset is
// DefaultConfig's.
func NewConfig(opts ConfigOptions) *Config {
	roots := opts.Roots
	builtin := roots == nil
	if builtin {
		roots = mustAppleRoots()
	} else {
		roots = append([]*x509.Certificate(nil), roots...)
	}
	clock := opts.Clock
	if clock == nil {
		clock = systemMillis
	}
	return &Config{roots: roots, clock: clock, builtin: builtin}
}

// Roots is the pinned anchors, an unmodifiable copy.
func (c *Config) Roots() []*x509.Certificate {
	return append([]*x509.Certificate(nil), c.roots...)
}

// Clock is the configured clock.
func (c *Config) Clock() func() int64 { return c.clock }

func systemMillis() int64 { return time.Now().UnixMilli() }
