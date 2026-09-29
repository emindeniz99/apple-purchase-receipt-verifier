package host

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixture bytes for the ABI tests, taken from the same fixtures/cases.json
// every host runs, so nothing here is a second copy of test data.

type sharedFixtures struct {
	// g5 is the genuine sandbox receipt as a receipt-data string.
	g5 string
	// jws is a StoreKit 2 JWS signed under the test root, and jwsConfig the
	// init configuration that pins that root.
	jws       string
	jwsConfig []byte
}

func findFixturesDir(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		candidate := filepath.Join(dir, "fixtures")
		if _, err := os.Stat(filepath.Join(candidate, "cases.json")); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no fixtures/cases.json above the working directory")
		}
		dir = parent
	}
}

func loadFixtures(t testing.TB) sharedFixtures {
	t.Helper()
	dir := findFixturesDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Fixtures map[string]struct{ Path, Codec string } `json:"fixtures"`
		Cases    []struct {
			ID     string                   `json:"id"`
			Input  struct{ Fixture string } `json:"input"`
			Config struct {
				TrustedRoots struct{ Fixtures []string } `json:"trustedRoots"`
			} `json:"config"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	bytesOf := func(id string) []byte {
		entry, ok := doc.Fixtures[id]
		if !ok {
			t.Fatalf("no fixture %q", id)
		}
		b, err := os.ReadFile(filepath.Join(dir, entry.Path))
		if err != nil {
			t.Fatal(err)
		}
		switch entry.Codec {
		case "base64":
			out, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(b)), ""))
			if err != nil {
				t.Fatal(err)
			}
			return out
		case "utf8":
			return []byte(strings.TrimSpace(string(b)))
		}
		return b
	}
	var out sharedFixtures
	for _, c := range doc.Cases {
		switch c.ID {
		case "receipt/verify-genuine-sandbox-g5-against-apple-roots":
			out.g5 = string(bytesOf(c.Input.Fixture))
			if doc.Fixtures[c.Input.Fixture].Codec != "text" {
				out.g5 = base64.StdEncoding.EncodeToString([]byte(out.g5))
			}
		case "transaction/verify-shared-sandbox":
			out.jws = string(bytesOf(c.Input.Fixture))
			var roots []string
			for _, id := range c.Config.TrustedRoots.Fixtures {
				roots = append(roots, base64.StdEncoding.EncodeToString(bytesOf(id)))
			}
			out.jwsConfig, _ = json.Marshal(map[string][]string{"roots": roots})
		}
	}
	if out.g5 == "" || out.jws == "" || out.jwsConfig == nil {
		t.Fatal("the fixtures the ABI tests use are not in cases.json")
	}
	return out
}
