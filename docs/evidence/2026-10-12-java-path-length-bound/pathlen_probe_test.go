package applereceipt

// Runs the receipts PathLengthShapesProbeTest wrote to $SCRATCH/pathlen-exp
// through the core (the Go wrapper over the committed aprv.wasm), and
// counts per shape how often the core's verdict (ok or refused) matches
// Java's.

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestPathLengthProbe(t *testing.T) {
	dir := filepath.Join(os.Getenv("SCRATCH"), "pathlen-exp")
	files, _ := filepath.Glob(filepath.Join(dir, "*.b64"))
	sort.Strings(files)
	tally := map[string]map[string]int{}
	agree := map[string][2]int{}
	for _, f := range files {
		tag := strings.TrimSuffix(filepath.Base(f), ".b64")
		shape := tag[:strings.LastIndex(tag, "-")]
		b64, _ := os.ReadFile(f)
		rootDer, _ := os.ReadFile(filepath.Join(dir, tag+".root.der"))
		javaOut, _ := os.ReadFile(filepath.Join(dir, tag+".java.txt"))
		root, err := x509.ParseCertificate(rootDer)
		if err != nil {
			t.Fatal(err)
		}
		v, err := NewVerifier(NewConfig(ConfigOptions{
			Roots: []*x509.Certificate{root},
			Clock: func() int64 { return time.Now().UnixMilli() },
		}))
		if err != nil {
			t.Fatal(err)
		}
		_, verr := v.VerifyReceipt(strings.TrimSpace(string(b64)))
		out := "ok"
		if verr != nil {
			out = verr.Error()
		}
		if tally[shape] == nil {
			tally[shape] = map[string]int{}
		}
		tally[shape][out]++
		a := agree[shape]
		if (string(javaOut) == "ok") == (verr == nil) {
			a[0]++
		} else {
			a[1]++
		}
		agree[shape] = a
	}
	shapes := make([]string, 0, len(tally))
	for s := range tally {
		shapes = append(shapes, s)
	}
	sort.Strings(shapes)
	for _, s := range shapes {
		fmt.Printf("CORE %s -> %v (verdict as Java's: %d, not: %d)\n", s, tally[s], agree[s][0], agree[s][1])
	}
}
