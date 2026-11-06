package applereceipt

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"time"
)

// Config is immutable verifier configuration: the pinned trust anchors,
// the revocation settings and the clock.
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
	// init no roots member, which means the three Apple roots compiled into
	// the module.
	builtin bool

	revocationLists   [][]byte
	revocationIssuers []*x509.Certificate
	distrust          []RevokedCertificate
}

// RevokedCertificate names one certificate to refuse, as a revocation key:
// the issuer id of the certificate that issued it and its serial number,
// both in hex. The module checks and normalises both strings when the
// Verifier is built; this type holds them exactly as given.
type RevokedCertificate struct {
	// Issuer is the issuer id: the SHA-256, in hex, of the issuing
	// certificate's subject Name followed by its subjectPublicKeyInfo,
	// both as encoded in that certificate. 64 hex digits, either case.
	Issuer string
	// Serial is the revoked certificate's serial number in hex, either
	// case, with or without leading zeros.
	Serial string
}

// ConfigOptions configures a Config. The zero value is the defaults:
// Apple's three pinned roots and the system clock.
type ConfigOptions struct {
	// Roots are the pinned anchors, replacing Apple's. Tests use their
	// own. nil means the three published Apple roots compiled into the
	// verification module, of which this package carries no copy; an
	// explicitly empty non-nil slice is kept as given, and NewVerifier
	// then refuses it: a verifier with no roots would answer
	// UNTRUSTED_CHAIN to everything, and nobody would notice until
	// production.
	Roots []*x509.Certificate

	// Clock is the source of "what time is it now?", as epoch
	// milliseconds. nil means the system clock.
	Clock func() int64

	// RevocationLists are certificate revocation lists (CRLs) exactly as
	// downloaded (DER), in any order: at most 16, each at most 1 MiB. The
	// URLs to download are the Verifier's RevocationURLs. NewVerifier
	// refuses a list that is not a CRL, is signed by no issuer the
	// verifier knows, or is older than the one this release was built
	// with; a genuine list in a form the module does not support is
	// ignored. nil means none: the list built into the module and
	// Distrust still apply.
	RevocationLists [][]byte

	// RevocationIssuers are CA certificates that sign revocation lists,
	// added to the ones built into the module: a new Apple intermediate,
	// or a test PKI's. Each must chain to a configured root. As with
	// Roots, only each certificate's Raw bytes reach the module.
	RevocationIssuers []*x509.Certificate

	// Distrust is revocation keys to refuse, at most 1,000.
	Distrust []RevokedCertificate
}

// NewConfig builds a Config from opts, the one way to build one. A field
// left unset is the default, so NewConfig(ConfigOptions{}) is Apple's
// three roots and the system clock, and its Roots() is nil.
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
	lists := make([][]byte, 0, len(opts.RevocationLists))
	for _, list := range opts.RevocationLists {
		lists = append(lists, append([]byte{}, list...))
	}
	return &Config{
		roots:             roots,
		clock:             clock,
		builtin:           builtin,
		revocationLists:   lists,
		revocationIssuers: append([]*x509.Certificate{}, opts.RevocationIssuers...),
		distrust:          append([]RevokedCertificate{}, opts.Distrust...),
	}
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

// RevocationLists is a copy of the configured revocation lists, in order;
// empty when there are none.
func (c *Config) RevocationLists() [][]byte {
	lists := make([][]byte, 0, len(c.revocationLists))
	for _, list := range c.revocationLists {
		lists = append(lists, append([]byte{}, list...))
	}
	return lists
}

// RevocationIssuers is a copy of the added revocation issuers, in order;
// empty when there are none.
func (c *Config) RevocationIssuers() []*x509.Certificate {
	return append([]*x509.Certificate{}, c.revocationIssuers...)
}

// Distrust is a copy of the configured distrust entries, in order; empty
// when there are none.
func (c *Config) Distrust() []RevokedCertificate {
	return append([]RevokedCertificate{}, c.distrust...)
}

func systemMillis() int64 { return time.Now().UnixMilli() }

// initConfig is init's argument: {"roots":["<base64 DER>", ...]}, or no
// roots member for the Apple roots compiled into the module, then
// "revocation_lists", "revocation_issuers" and "distrust" when they are
// not empty. The default Config sends {}. A caller's certificates travel
// as their DER bytes and lists as given; nothing here reads a certificate
// or a list, and the distrust strings pass unchanged for the module to
// judge.
func initConfig(config *Config) []byte {
	type distrustEntry struct {
		Issuer string `json:"issuer"`
		Serial string `json:"serial"`
	}
	var init struct {
		Roots             *[]string       `json:"roots,omitempty"`
		RevocationLists   []string        `json:"revocation_lists,omitempty"`
		RevocationIssuers []string        `json:"revocation_issuers,omitempty"`
		Distrust          []distrustEntry `json:"distrust,omitempty"`
	}
	if !config.builtin {
		roots := certificatesDER(config.roots)
		init.Roots = &roots
	}
	for _, list := range config.revocationLists {
		init.RevocationLists = append(init.RevocationLists, base64.StdEncoding.EncodeToString(list))
	}
	if len(config.revocationIssuers) > 0 {
		init.RevocationIssuers = certificatesDER(config.revocationIssuers)
	}
	for _, entry := range config.distrust {
		init.Distrust = append(init.Distrust, distrustEntry(entry))
	}
	// Marshal cannot fail on strings.
	out, _ := json.Marshal(init)
	return out
}

// certificatesDER is each certificate's Raw bytes, base64: the only part of
// a certificate that reaches the module.
func certificatesDER(certificates []*x509.Certificate) []string {
	encoded := []string{}
	for _, certificate := range certificates {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(certificate.Raw))
	}
	return encoded
}
