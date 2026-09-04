package applereceipt

// Environment is an App Store environment, spelled exactly as Apple's
// JWS claims and receipt attributes spell it.
//
// Environment routing is an accept-set, not a single value (PLAN.md D3):
// App Review runs production builds against sandbox, so a verifier that
// hard-failed on one environment would reject purchases during review.
type Environment string

// The four environments Apple uses.
const (
	EnvironmentProduction   Environment = "Production"
	EnvironmentSandbox      Environment = "Sandbox"
	EnvironmentXcode        Environment = "Xcode"
	EnvironmentLocalTesting Environment = "LocalTesting"
)

func (e Environment) known() bool {
	switch e {
	case EnvironmentProduction, EnvironmentSandbox, EnvironmentXcode, EnvironmentLocalTesting:
		return true
	}
	return false
}

// String returns the claim spelling.
func (e Environment) String() string { return string(e) }
