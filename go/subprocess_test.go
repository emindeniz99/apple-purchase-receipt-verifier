package applereceipt_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Two properties can only be tested in a fresh process, because the
// setting they depend on is read once, before any test runs:
// GODEBUG=fips140, and the OS trust store's location. Both tests below
// re-execute this test binary with the environment they need.

const subprocessMarker = "APPLERECEIPT_SUBPROCESS"

func inSubprocess() bool { return os.Getenv(subprocessMarker) == "1" }

// runSelf re-runs one test in a child process with extra environment,
// and returns its combined output.
func runSelf(t *testing.T, testName string, env ...string) (string, error) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("cannot locate the test binary: %v", err)
	}
	cmd := exec.Command(executable, "-test.run=^"+testName+"$", "-test.v")
	cmd.Env = append(os.Environ(), append([]string{subprocessMarker + "=1"}, env...)...)
	// The child walks up from its working directory to find fixtures/.
	cmd.Dir, err = os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func requireChildPassed(t *testing.T, output string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("the child process failed: %v\n%s", err, output)
	}
	if !strings.Contains(output, "PASS") {
		t.Fatalf("the child process did not report PASS:\n%s", output)
	}
}
