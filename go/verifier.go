package applereceipt

import (
	"crypto/x509"
	"errors"
)

// Verifier verifies what Apple signed, offline, against the pinned roots
// of a Config. It answers one question: did Apple sign this data, under a
// pinned Apple root? If so, it returns the data. Bundle id, environment,
// product id, device binding, refunds and idempotency are the caller's
// decisions; no method here takes a parameter for any of them.
//
// A Verifier is immutable after construction and safe for concurrent use
// by multiple goroutines. The verify methods never panic for any input: a
// panic inside one is contained and reported by where it happened. Before
// a signature has verified it is ReasonMalformed: input nobody has
// vouched for yet must not be able to raise an internal-error alert at
// will; while the signed payload is being read it is
// ReasonUnreadablePayload; after that, or when the configured clock
// panics, it is ReasonInternalError.
type Verifier struct {
	roots []*x509.Certificate
	clock func() int64
}

// NewVerifier builds a Verifier from config.
//
// A nil config, or one with no trust anchors or a nil one, is a plain error, never a
// *Failure: misconfiguration is a programming mistake, not a verdict about
// any input: a verifier with no roots would answer UNTRUSTED_CHAIN to
// everything, and nobody would notice until production, and a caller
// switching on Reason must never see one.
func NewVerifier(config *Config) (*Verifier, error) {
	if config == nil {
		return nil, errors.New("applereceipt: config must not be nil")
	}
	if len(config.roots) == 0 {
		return nil, errors.New("applereceipt: config has no trust anchors")
	}
	for _, root := range config.roots {
		if root == nil {
			return nil, errors.New("applereceipt: config has a nil trust anchor")
		}
	}
	return &Verifier{
		roots: append([]*x509.Certificate(nil), config.roots...),
		clock: config.clock,
	}, nil
}

// VerifyReceipt verifies a legacy PKCS#7 app receipt, given as the base64
// string a client sends, and decodes its payload.
func (v *Verifier) VerifyReceipt(base64 string) (payload *ReceiptPayload, err error) {
	ctx := newVerifyCtx(v.clock)
	defer ctx.contain(&err)
	return verifyReceipt(base64, v.roots, ctx)
}

// VerifySignedData verifies an Apple-signed compact JWS (StoreKit 2
// jwsRepresentation, signedTransactionInfo / signedRenewalInfo, an
// AppTransaction, or an outer or nested App Store Server Notifications V2
// JWS) and returns its payload, exactly as signed.
func (v *Verifier) VerifySignedData(jws string) (payload *JSONPayload, err error) {
	ctx := newVerifyCtx(v.clock)
	defer ctx.contain(&err)
	return verifySignedData(jws, v.roots, ctx)
}

// VerifyReceiptEndpoint is the response body Apple's deprecated
// verifyReceipt endpoint at environment would return for requestJSON,
// verified offline against the pinned roots instead of by calling Apple.
//
// It never returns an error and never panics: like the real endpoint,
// every failure is the status field inside the returned body.
func (v *Verifier) VerifyReceiptEndpoint(environment Environment, requestJSON string) (out string) {
	ctx := newVerifyCtx(v.clock)
	defer func() {
		if recover() != nil {
			out = statusOnlyResponse(statusForReason(ctx.stage.reason()))
		}
	}()
	return verifyReceiptEndpoint(environment, requestJSON, v.roots, ctx)
}

// --- panic containment and the lazy clock ---------------------------------

// stage is where a verification has reached, for mapping an unexpected
// panic to a verdict: nothing that is only known after a panic, its text
// included, reaches the caller.
type stage int

const (
	// stageBeforeSignature: reading input no signature has vouched for
	// yet.
	stageBeforeSignature stage = iota
	// stagePayloadParse: decoding a payload a trusted signer signed.
	stagePayloadParse
	// stageAfterSignature: everything after that.
	stageAfterSignature
)

func (s stage) reason() Reason {
	switch s {
	case stagePayloadParse:
		return ReasonUnreadablePayload
	case stageAfterSignature:
		return ReasonInternalError
	default:
		return ReasonMalformed
	}
}

func (s stage) message() string {
	switch s {
	case stagePayloadParse:
		return "unexpected failure while reading the signed payload"
	case stageAfterSignature:
		return "unexpected internal failure"
	default:
		return "unexpected failure while reading unverified input"
	}
}

// verifyCtx is the per-call state a verification threads through its call
// graph: which stage it has reached, and a clock read at most once and
// only when a verdict needs it.
type verifyCtx struct {
	stage       stage
	clockFn     func() int64
	haveClock   bool
	clockMillis int64
}

func newVerifyCtx(clockFn func() int64) *verifyCtx {
	return &verifyCtx{stage: stageBeforeSignature, clockFn: clockFn}
}

// enter marks the stage the current verification has reached.
func (c *verifyCtx) enter(s stage) { c.stage = s }

// now is the configured clock's answer, in epoch milliseconds, the same
// value on every call. A clock that panics is ReasonInternalError
// regardless of the current stage: the caller's clock broke, not the
// input.
func (c *verifyCtx) now() (millis int64, err error) {
	if c.haveClock {
		return c.clockMillis, nil
	}
	defer func() {
		if recover() != nil {
			err = newError(ReasonInternalError, "the configured clock panicked")
		}
	}()
	c.clockMillis = c.clockFn()
	c.haveClock = true
	return c.clockMillis, nil
}

// contain turns an unexpected panic anywhere within a verify method into a
// *Failure, judged by the stage the verification had reached. Deferred
// directly in each verify method, so the named error return still holds
// nil until this runs.
func (c *verifyCtx) contain(err *error) {
	if recover() != nil {
		*err = newError(c.stage.reason(), c.stage.message())
	}
}
