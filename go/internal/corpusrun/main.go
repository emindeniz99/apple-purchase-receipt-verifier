// Command corpusrun runs a calls file through the package's host layer, the
// same pool and canonical-ABI call the Verifier uses, and prints one answer
// row per call. It is how the corpus (1,179 rows plus 5,000 mutants) is
// compared with the reference rows of ABI v1's Node run: its output goes to
// the round-13 classifier unchanged.
//
//	corpusrun [-module aprv.wasm] CALLS.jsonl > ROWS.jsonl
//
// CALLS.jsonl is one row per line in the format of
// docs/evidence/2026-09-29-canonical-abi-final/py/calls_bytes.py:
//
//	{"id", "fn": "verify-receipt" | "verify-signed-data" | "verify-receipt-endpoint",
//	 "env": 0 | 1, "config": "" | "{\"roots\":[...]}", "now": null | ms, "b64": "<the input bytes>"}
//
// or {"id", "map"} for a row that makes no call, which is copied through.
// A row's answer is {"id","out"}, or {"id","trap"} when the call failed
// inside the module: the pool discards that instance and the next row
// gets a fresh one. A configuration that init refuses is the row's answer
// (out: init's {"ok":false,...}). Without -module the embedded aprv.wasm is
// run; with it, that file instead, so a release build can be checked before
// it is copied into the package.
//
// The wall clock stands in for a row with no pinned clock, as the other
// hosts' runners do; the classifier masks request_date on those rows.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/host"
)

type row struct {
	ID     string          `json:"id"`
	Map    json.RawMessage `json:"map,omitempty"`
	Fn     string          `json:"fn"`
	Env    uint32          `json:"env"`
	Config string          `json:"config"`
	Now    *uint64         `json:"now"`
	B64    string          `json:"b64"`
}

func main() {
	modulePath := flag.String("module", "", "run this aprv.wasm instead of the embedded one")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: corpusrun [-module aprv.wasm] CALLS.jsonl > ROWS.jsonl")
		os.Exit(2)
	}
	if err := run(*modulePath, flag.Arg(0)); err != nil {
		fmt.Fprintln(os.Stderr, "corpusrun:", err)
		os.Exit(1)
	}
}

func run(modulePath, callsPath string) error {
	var module []byte
	if modulePath != "" {
		var err error
		if module, err = os.ReadFile(modulePath); err != nil {
			return err
		}
	}
	newPool := func(config string) (*host.Pool, error) {
		if module != nil {
			return host.NewPoolFromModule(module, []byte(config))
		}
		return host.NewPool([]byte(config))
	}

	calls, err := os.Open(callsPath)
	if err != nil {
		return err
	}
	defer calls.Close()
	scanner := bufio.NewScanner(calls)
	scanner.Buffer(make([]byte, 1<<20), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	pools := map[string]*host.Pool{}
	refused := map[string]string{} // config -> init's answer
	rows, traps := 0, 0
	for scanner.Scan() {
		var r row
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			return fmt.Errorf("row %d: %w", rows+1, err)
		}
		rows++
		answer := map[string]any{"id": r.ID}
		if r.Map != nil {
			answer["map"] = r.Map
		} else {
			input, err := base64.StdEncoding.DecodeString(r.B64)
			if err != nil {
				return fmt.Errorf("%s: %w", r.ID, err)
			}
			pool, initAnswer, err := poolFor(pools, refused, r.Config, newPool)
			switch {
			case err != nil:
				return fmt.Errorf("%s: %w", r.ID, err)
			case pool == nil:
				answer["out"] = initAnswer // init refused the config: that is the row's answer
			default:
				now := uint64(time.Now().UnixMilli())
				if r.Now != nil {
					now = *r.Now
				}
				var s string
				var err error
				switch r.Fn {
				case "verify-receipt":
					s, err = pool.VerifyReceipt(now, string(input))
				case "verify-signed-data":
					s, err = pool.VerifySignedData(now, string(input))
				case "verify-receipt-endpoint":
					s, err = pool.VerifyReceiptEndpoint(r.Env, now, string(input))
				default:
					return fmt.Errorf("%s: unknown fn %q", r.ID, r.Fn)
				}
				if err != nil {
					traps++
					answer["trap"] = err.Error()
				} else {
					answer["out"] = s
				}
			}
		}
		b, err := json.Marshal(answer)
		if err != nil {
			return err
		}
		out.Write(b)
		out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "{\"host\":\"the package (wazero, pooled)\",\"rows\":%d,\"traps\":%d,\"pools\":%d}\n", rows, traps, len(pools))
	return nil
}

// poolFor returns the pool for a configuration, making it on first use. A
// configuration init refuses returns a nil pool and init's answer.
func poolFor(pools map[string]*host.Pool, refused map[string]string, config string,
	newPool func(string) (*host.Pool, error)) (*host.Pool, string, error) {
	if pool := pools[config]; pool != nil {
		return pool, "", nil
	}
	if answer, ok := refused[config]; ok {
		return nil, answer, nil
	}
	pool, err := newPool(config)
	var refusal *host.InitRefusedError
	switch {
	case errors.As(err, &refusal):
		refused[config] = refusal.Answer
		return nil, refusal.Answer, nil
	case err != nil:
		return nil, "", err
	}
	pools[config] = pool
	return pool, "", nil
}
