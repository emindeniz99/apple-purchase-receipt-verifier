// Command gencerts refreshes go/roots/certs from the repo-root certs/
// directory.
//
// The go:embed directive cannot reach outside the module directory, so
// the Go module keeps a copy of the pinned Apple roots. This program is what
// `go generate ./...` runs, and CI runs it followed by
// `git diff --exit-code`: a certs/ change that forgets the copy fails the
// build rather than shipping stale trust anchors.
package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gencerts:", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := moduleDir()
	if err != nil {
		return err
	}
	src := filepath.Join(root, "..", "certs")
	dst := filepath.Join(root, "roots", "certs")

	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("reading %s: %w", src, err)
	}
	wanted := map[string]bool{}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cer") {
			continue
		}
		names = append(names, entry.Name())
		wanted[entry.Name()] = true
	}
	sort.Strings(names)
	if len(names) == 0 {
		return fmt.Errorf("no .cer files in %s", src)
	}

	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, name := range names {
		der, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			return err
		}
		// Copy only what parses as a certificate: a truncated or
		// PEM-wrapped file must fail here, not at the first verification
		// in production.
		if _, err := x509.ParseCertificate(der); err != nil {
			return fmt.Errorf("%s is not DER certificate bytes: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), der, 0o644); err != nil {
			return err
		}
		fmt.Println("wrote roots/certs/" + name)
	}

	// Remove a root that was deleted upstream, so the embedded set can
	// shrink as well as grow.
	existing, err := os.ReadDir(dst)
	if err != nil {
		return err
	}
	for _, entry := range existing {
		if !entry.IsDir() && !wanted[entry.Name()] {
			if err := os.Remove(filepath.Join(dst, entry.Name())); err != nil {
				return err
			}
			fmt.Println("removed roots/certs/" + entry.Name())
		}
	}
	return nil
}

// moduleDir finds the directory holding go.mod, walking up from the
// working directory so the generator works from anywhere in the module.
func moduleDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found above %s", dir)
		}
		dir = parent
	}
}
