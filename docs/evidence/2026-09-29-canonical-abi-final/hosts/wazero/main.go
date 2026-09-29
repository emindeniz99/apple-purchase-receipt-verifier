// Spike only (2026-09-29, round 13). A Go host (wazero) that calls the
// canonical-ABI aprv module's core exports by hand: no component runtime,
// no generated bindings. The lines between the "canonical ABI" markers are
// everything a host needs: one generic lowering helper for the four calls
// and the one import. scripts/count.sh counts them.
//
//	aprv-wazero calls MODULE CALLS.jsonl   rows in the Node runner's format (stdout)
//	aprv-wazero tests MODULE CASES.jsonl   the ABI tests, misuse cases, isolation
//	aprv-wazero bench V1.wasm,CABI.wasm CASES.jsonl   start-up and per-call timing
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

var ctx = context.Background()

const iface = "aprv:verifier/verify@1.0.0#"

// --- canonical ABI (hand-written) begin ---

// Guest is one instance of the module.
type Guest struct {
	m       api.Module
	realloc api.Function
}

// hostModule provides the one import, random-get: func(len: u32) -> list<u8>.
// Lowered: (len, retptr); the list lives in guest memory from cabi_realloc.
func hostModule(r wazero.Runtime) error {
	_, err := r.NewHostModuleBuilder("aprv:verifier/host@1.0.0").NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, n, retptr uint32) {
			res, err := m.ExportedFunction("cabi_realloc").Call(ctx, 0, 0, 1, uint64(n))
			if err != nil {
				panic(err)
			}
			buf := make([]byte, n)
			rand.Read(buf)
			buf = testHook(buf) // test hook (tests.go), not part of the protocol
			m.Memory().Write(uint32(res[0]), buf)
			m.Memory().WriteUint32Le(retptr, uint32(res[0]))
			m.Memory().WriteUint32Le(retptr+4, uint32(len(buf)))
		}).Export("random-get").Instantiate(ctx)
	return err
}

// sigs: each export's WIT parameters, in order: 'w' u32, 'd' u64, 'b' list<u8>.
var sigs = map[string]string{"init": "b", "verify-receipt": "db", "verify-signed-data": "db", "verify-receipt-endpoint": "wdb"}

// lower turns WIT values into core arguments, checked against fn's
// signature: u32 (uint32) and u64 (uint64) pass as scalars; list<u8>
// (string or []byte) becomes a guest buffer from cabi_realloc (the guest
// takes ownership) passed as (ptr, len). A wrong count or Go type is an error.
func (g *Guest) lower(fn string, args []any) ([]uint64, error) {
	sig, ok := sigs[fn]
	if !ok || len(sig) != len(args) {
		return nil, fmt.Errorf("%s: unknown export or wrong argument count", fn)
	}
	wrong := func(i int, a any) error {
		return fmt.Errorf("%s: argument %d is %T, the WIT type is %c", fn, i, a, sig[i])
	}
	var out []uint64
	for i, a := range args {
		var b []byte
		switch v := a.(type) {
		case uint32:
			if sig[i] != 'w' {
				return nil, wrong(i, a)
			}
			out = append(out, api.EncodeU32(v))
			continue
		case uint64:
			if sig[i] != 'd' {
				return nil, wrong(i, a)
			}
			out = append(out, v)
			continue
		case string:
			b = []byte(v)
		case []byte:
			b = v
		default:
			return nil, wrong(i, a)
		}
		if sig[i] != 'b' {
			return nil, wrong(i, a)
		}
		res, err := g.realloc.Call(ctx, 0, 0, 1, uint64(len(b)))
		if err != nil {
			return nil, err
		}
		if !g.m.Memory().Write(uint32(res[0]), b) {
			return nil, fmt.Errorf("%s: argument %d: cabi_realloc returned an out-of-range buffer", fn, i)
		}
		out = append(out, res[0], uint64(len(b)))
	}
	return out, nil
}

// Call runs one export whose result is a string: lower the arguments,
// call, read (ptr, len) from the return area, copy the result out, then
// call the post-return function, which frees it.
func (g *Guest) Call(fn string, args ...any) (string, error) {
	core, err := g.lower(fn, args)
	if err != nil {
		return "", err
	}
	ret, err := g.m.ExportedFunction(iface+fn).Call(ctx, core...)
	if err != nil {
		return "", err
	}
	rp := uint32(ret[0])
	ptr, _ := g.m.Memory().ReadUint32Le(rp)
	n, _ := g.m.Memory().ReadUint32Le(rp + 4)
	b, ok := g.m.Memory().Read(ptr, n)
	if !ok {
		return "", fmt.Errorf("%s: result (%d, %d) is out of range", fn, ptr, n)
	}
	out := string(b) // copies
	_, err = g.m.ExportedFunction("cabi_post_"+iface+fn).Call(ctx, uint64(rp))
	return out, err
}

// --- canonical ABI (hand-written) end ---

// The typed calls (thin, over Call).
func (g *Guest) Init(config []byte) (string, error) { return g.Call("init", config) }
func (g *Guest) VerifyReceipt(now uint64, b64 []byte) (string, error) {
	return g.Call("verify-receipt", now, b64)
}
func (g *Guest) VerifySignedData(now uint64, jws []byte) (string, error) {
	return g.Call("verify-signed-data", now, jws)
}
func (g *Guest) VerifyReceiptEndpoint(env uint32, now uint64, req []byte) (string, error) {
	return g.Call("verify-receipt-endpoint", env, now, req)
}

type Host struct {
	r        wazero.Runtime
	compiled wazero.CompiledModule
}

func NewHost(path string) *Host {
	r := wazero.NewRuntime(ctx)
	if err := hostModule(r); err != nil {
		panic(err)
	}
	wasm, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	c, err := r.CompileModule(ctx, wasm)
	if err != nil {
		panic(err)
	}
	return &Host{r, c}
}

func (h *Host) New() (*Guest, error) {
	m, err := h.r.InstantiateModule(ctx, h.compiled, wazero.NewModuleConfig().WithName("").WithStartFunctions())
	if err != nil {
		return nil, err
	}
	return &Guest{m: m, realloc: m.ExportedFunction("cabi_realloc")}, nil
}

func nowMs() uint64 { return uint64(time.Now().UnixMilli()) }

type row struct {
	ID     string          `json:"id"`
	Map    json.RawMessage `json:"map,omitempty"`
	Fn     string          `json:"fn"`
	Env    uint32          `json:"env"`
	Config string          `json:"config"`
	Now    *uint64         `json:"now"`
	B64    string          `json:"b64"`
}

func (r row) input() []byte {
	b, err := base64.StdEncoding.DecodeString(r.B64)
	if err != nil {
		panic(err)
	}
	return b
}

func (g *Guest) run(r row) (string, error) {
	now := nowMs()
	if r.Now != nil {
		now = *r.Now
	}
	switch r.Fn {
	case "verify-receipt":
		return g.VerifyReceipt(now, r.input())
	case "verify-signed-data":
		return g.VerifySignedData(now, r.input())
	default:
		return g.VerifyReceiptEndpoint(r.Env, now, r.input())
	}
}

func calls(h *Host, path string) {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	inst := map[string]*Guest{}
	rows, traps := 0, 0
	for sc.Scan() {
		var r row
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			panic(err)
		}
		rows++
		var o map[string]any
		if r.Map != nil {
			o = map[string]any{"id": r.ID, "map": r.Map}
		} else {
			g := inst[r.Config]
			initAnswer := ""
			if g == nil {
				if g, err = h.New(); err != nil {
					panic(err)
				}
				if initAnswer, err = g.Init([]byte(r.Config)); err != nil {
					panic(err)
				}
				if initAnswer == `{"ok":true}` {
					inst[r.Config] = g
				}
			}
			if initAnswer != "" && initAnswer != `{"ok":true}` {
				o = map[string]any{"id": r.ID, "out": initAnswer} // init refused the config: that is the row's answer
			} else if s, err := g.run(r); err != nil {
				traps++
				g.m.Close(ctx)
				delete(inst, r.Config) // a trap discards the instance
				o = map[string]any{"id": r.ID, "trap": err.Error()}
			} else {
				o = map[string]any{"id": r.ID, "out": s}
			}
		}
		b, _ := json.Marshal(o)
		out.Write(b)
		out.WriteByte('\n')
	}
	fmt.Fprintf(os.Stderr, "{\"host\":\"wazero %s\",\"rows\":%d,\"traps\":%d,\"instances_left\":%d}\n", "v1.12.0", rows, traps, len(inst))
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: aprv-wazero calls|tests|bench MODULE FILE.jsonl")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "calls":
		calls(NewHost(os.Args[2]), os.Args[3])
	case "tests":
		os.Exit(tests(NewHost(os.Args[2]), os.Args[3]))
	case "bench":
		bench(os.Args[2], os.Args[3])
	}
}

// helpers for tests.go and bench.go
func mustRow(path, id string) row {
	f, _ := os.ReadFile(path)
	for _, l := range strings.Split(string(f), "\n") {
		var r row
		if json.Unmarshal([]byte(l), &r) == nil && r.ID == id {
			return r
		}
	}
	panic("no row " + id)
}

func testHook(b []byte) []byte {
	randomCalls++
	if badRandom && len(b) > 0 {
		return b[:len(b)-1]
	}
	return b
}
