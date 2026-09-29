package host

import "sync"

// maxPooledMemory is the largest linear memory an instance may have and
// still be reused. A hostile receipt can grow an instance to well over
// 100 MiB, and memory never shrinks; such an instance is closed instead of
// being kept for the next caller.
var maxPooledMemory uint32 = 64 << 20

// Pool is the instances of one Verifier. Every instance has run init with
// the Pool's configuration once, so the roots are parsed once per
// instance. One instance serves one call at a time; a call that fails
// inside the guest discards its instance, and the next call takes or
// creates another. Instances go when the Pool does: nothing to close.
type Pool struct {
	mod    *module
	config []byte
	pool   sync.Pool
}

// NewPool loads the embedded module (compiled once per process) and makes
// the first instance, which is where init can refuse the configuration
// (*InitRefusedError) and where a module this package cannot bind is
// refused (*ABIError).
func NewPool(config []byte) (*Pool, error) {
	mod, err := loaded()
	if err != nil {
		return nil, err
	}
	return newPool(mod, config)
}

func newPool(mod *module, config []byte) (*Pool, error) {
	p := &Pool{mod: mod, config: append([]byte(nil), config...)}
	g, err := mod.newGuest(p.config)
	if err != nil {
		return nil, err
	}
	p.pool.Put(g)
	return p, nil
}

func (p *Pool) get() (*Guest, error) {
	if g, ok := p.pool.Get().(*Guest); ok {
		return g, nil
	}
	return p.mod.newGuest(p.config)
}

func (p *Pool) put(g *Guest) {
	switch {
	case g.dead:
	case g.memorySize() > maxPooledMemory:
		g.close()
	default:
		p.pool.Put(g)
	}
}

func (p *Pool) call(fn string, args ...any) (string, error) {
	g, err := p.get()
	if err != nil {
		return "", err
	}
	out, err := g.Call(fn, args...)
	p.put(g) // a discarded instance is not put back
	return out, err
}

// VerifyReceipt is verify-receipt: nowMs is the Config clock's answer, read
// by the caller once before it looked at the input; receiptBase64 is the
// receipt-data string's bytes.
func (p *Pool) VerifyReceipt(nowMs uint64, receiptBase64 string) (string, error) {
	return p.call("verify-receipt", nowMs, receiptBase64)
}

// VerifySignedData is verify-signed-data.
func (p *Pool) VerifySignedData(nowMs uint64, jws string) (string, error) {
	return p.call("verify-signed-data", nowMs, jws)
}

// VerifyReceiptEndpoint is verify-receipt-endpoint; env is 0 for
// production and 1 for sandbox, and the guest traps on anything else.
func (p *Pool) VerifyReceiptEndpoint(env uint32, nowMs uint64, requestJSON string) (string, error) {
	return p.call("verify-receipt-endpoint", env, nowMs, requestJSON)
}
