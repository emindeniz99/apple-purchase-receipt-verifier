package host

// NewPoolFromModule is NewPool over a module other than the embedded one,
// compiled into a runtime of its own. It exists so the wrapper's tests can
// run its result handling against a test double of the ABI
// (testdata/mirror) and can offer it modules it must refuse; nothing in
// the library calls it.
func NewPoolFromModule(module, config []byte) (*Pool, error) {
	mod, err := compile(module)
	if err != nil {
		return nil, err
	}
	return newPool(mod, config)
}
