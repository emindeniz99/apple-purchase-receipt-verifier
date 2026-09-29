package applereceipt

import (
	"fmt"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/host"
)

// NewVerifierOverModule is NewVerifier over a module other than the
// embedded aprv.wasm: the facade tests use a test double of the ABI to
// choose the module's answers. It applies the same checks NewVerifier does.
func NewVerifierOverModule(config *Config, module []byte) (*Verifier, error) {
	if err := checkConfig(config); err != nil {
		return nil, err
	}
	pool, err := host.NewPoolFromModule(module, initConfig(config.roots, config.builtin))
	if err != nil {
		return nil, fmt.Errorf("applereceipt: %w", err)
	}
	return &Verifier{pool: pool, clock: config.clock}, nil
}
