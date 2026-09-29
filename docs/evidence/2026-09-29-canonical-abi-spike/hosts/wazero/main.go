// Spike only (2026-09-29, round 12). A Go host (wazero) that calls the
// canonical-ABI aprv module's core exports by hand: no component runtime,
// no generated bindings. The lines between the "canonical ABI" markers are
// everything a host needs for the string->string calls and the one import;
// scripts/count.sh counts them.
//
//	aprv-wazero calls MODULE CALLS.jsonl   rows in the Node runner's format (stdout)
//	aprv-wazero tests MODULE CASES.jsonl   the adapted ABI tests + isolation checks
//	aprv-wazero bench MODULE CASES.jsonl   start-up and per-call timing
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
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

// Call runs one export whose last parameter is a string and whose result is
// a string: copy the argument into a guest buffer (the guest takes
// ownership), call, read (ptr, len) from the return area, copy the result
// out, then call the post-return function, which frees it.
func (g *Guest) Call(fn string, scalars []uint64, arg string) (string, error) {
	res, err := g.realloc.Call(ctx, 0, 0, 1, uint64(len(arg)))
	if err != nil {
		return "", err
	}
	p := uint32(res[0])
	g.m.Memory().WriteString(p, arg)
	ret, err := g.m.ExportedFunction(iface+fn).Call(ctx, append(scalars, uint64(p), uint64(len(arg)))...)
	if err != nil {
		return "", err
	}
	rp := uint32(ret[0])
	ptr, _ := g.m.Memory().ReadUint32Le(rp)
	n, _ := g.m.Memory().ReadUint32Le(rp + 4)
	b, _ := g.m.Memory().Read(ptr, n)
	out := string(b) // copies
	_, err = g.m.ExportedFunction("cabi_post_"+iface+fn).Call(ctx, uint64(rp))
	return out, err
}

// --- canonical ABI (hand-written) end ---

// The typed calls (thin, over Call).
func (g *Guest) Init(config string) (string, error) { return g.Call("init", nil, config) }
func (g *Guest) VerifyReceipt(now uint64, b64 string) (string, error) {
	return g.Call("verify-receipt", []uint64{now}, b64)
}
func (g *Guest) VerifySignedData(now uint64, jws string) (string, error) {
	return g.Call("verify-signed-data", []uint64{now}, jws)
}
func (g *Guest) VerifyReceiptEndpoint(env uint32, now uint64, req string) (string, error) {
	return g.Call("verify-receipt-endpoint", []uint64{uint64(env), now}, req)
}

type Host struct {
	r        wazero.Runtime
	compiled wazero.CompiledModule
}

func NewHost(path string) (*Host, time.Duration, time.Duration) {
	t0 := time.Now()
	r := wazero.NewRuntime(ctx)
	if err := hostModule(r); err != nil {
		panic(err)
	}
	wasm, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	t1 := time.Now()
	c, err := r.CompileModule(ctx, wasm)
	if err != nil {
		panic(err)
	}
	return &Host{r, c}, t1.Sub(t0), time.Since(t1)
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
	Text   string          `json:"text"`
}

func (g *Guest) run(r row) (string, error) {
	now := nowMs()
	if r.Now != nil {
		now = *r.Now
	}
	switch r.Fn {
	case "verify-receipt":
		return g.VerifyReceipt(now, r.Text)
	case "verify-signed-data":
		return g.VerifySignedData(now, r.Text)
	default:
		return g.VerifyReceiptEndpoint(r.Env, now, r.Text)
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
				if initAnswer, err = g.Init(r.Config); err != nil {
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
		h, _, _ := NewHost(os.Args[2])
		calls(h, os.Args[3])
	case "tests":
		h, _, _ := NewHost(os.Args[2])
		os.Exit(tests(h, os.Args[3]))
	case "bench":
		bench(os.Args[2], os.Args[3])
	}
}

// helpers for tests.go
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

func u32le(b []byte, i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }

func testHook(b []byte) []byte {
	randomCalls++
	if badRandom && len(b) > 0 {
		return b[:len(b)-1]
	}
	return b
}
