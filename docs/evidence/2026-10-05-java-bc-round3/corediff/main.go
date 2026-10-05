package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"strings"

	aprv "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

type rootList []string

func (r *rootList) String() string     { return strings.Join(*r, ",") }
func (r *rootList) Set(v string) error { *r = append(*r, v); return nil }

func main() {
	kind := flag.String("kind", "receipt", "receipt|jws")
	now := flag.Int64("now", 0, "clock ms (0 = system)")
	var roots rootList
	flag.Var(&roots, "root", "root DER file")
	flag.Parse()
	opts := aprv.ConfigOptions{}
	if len(roots) > 0 {
		opts.Roots = []*x509.Certificate{}
		for _, f := range roots {
			b, err := os.ReadFile(f)
			if err != nil {
				panic(err)
			}
			c, err := x509.ParseCertificate(b)
			if err != nil {
				panic(err)
			}
			opts.Roots = append(opts.Roots, c)
		}
	}
	if *now != 0 {
		n := *now
		opts.Clock = func() int64 { return n }
	}
	v, err := aprv.NewVerifier(aprv.NewConfig(opts))
	if err != nil {
		panic(err)
	}
	for _, f := range flag.Args() {
		b, err := os.ReadFile(f)
		if err != nil {
			panic(err)
		}
		s := strings.TrimSpace(string(b))
		var e error
		if *kind == "endpoint" {
			out := v.VerifyReceiptEndpoint(aprv.EnvironmentSandbox, "{\"receipt-data\":\""+s+"\"}")
			fmt.Printf("%s: %s\n", f, out)
			continue
		}
		if *kind == "receipt" {
			_, e = v.VerifyReceipt(s)
		} else {
			_, e = v.VerifySignedData(s)
		}
		if e == nil {
			fmt.Printf("%s: ok\n", f)
		} else {
			r, _ := aprv.ReasonOf(e)
			fmt.Printf("%s: %s\n", f, r)
		}
	}
}
