package wasm

import (
	"strings"
	"testing"
)

func TestEmbeddedModuleMatchesItsHashFile(t *testing.T) {
	// init already panics on a mismatch; this is the same check, named.
	if err := Check(Module, sumFile); err != nil {
		t.Fatal(err)
	}
	if len(SHA256()) != 64 {
		t.Fatalf("SHA256() = %q", SHA256())
	}
}

func TestAModuleThatDiffersByOneByteIsRefused(t *testing.T) {
	changed := append([]byte(nil), Module...)
	changed[len(changed)/2] ^= 1
	err := Check(changed, sumFile)
	if err == nil || !strings.Contains(err.Error(), SHA256()) {
		t.Fatalf("a changed module passed the check, or the refusal does not name the recorded hash: %v", err)
	}
}

func TestAHashFileThatIsNotOneSHA256LineIsRefused(t *testing.T) {
	good := SHA256()
	for name, file := range map[string]string{
		"empty":        "",
		"no file name": good + "\n",
		"another file": good + "  other.wasm\n",
		"short hash":   good[:63] + "  aprv.wasm\n",
		"uppercase":    strings.ToUpper(good) + "  aprv.wasm\n",
		"not hex":      strings.Repeat("g", 64) + "  aprv.wasm\n",
		"two lines":    good + "  aprv.wasm\n" + good + "  aprv.wasm\n",
	} {
		if err := Check(Module, file); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, file := range map[string]string{
		"sha256sum text mode":   good + "  aprv.wasm\n",
		"sha256sum binary mode": good + " *aprv.wasm\n",
		"CRLF":                  good + "  aprv.wasm\r\n",
	} {
		if err := Check(Module, file); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
