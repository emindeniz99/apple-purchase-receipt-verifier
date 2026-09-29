// Spike only (2026-09-29, round 12). Start-up and per-call timing on
// wazero, the canonical-ABI module against the ABI v1 module (b14e14b2),
// in one process, interleaved: RUNS rounds of { new runtime + compile,
// instantiate, init (cabi only), first g5, second g5 } for each, then a
// steady loop of g5 and of the shared-sandbox JWS per module.
//
//	aprv-wazero bench V1.wasm,CABI.wasm CASES.jsonl
package main

import (
	b64pkg "encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// ABI v1, by hand: aprv_alloc / aprv_call / aprv_result_ptr,len,free, and the two aprv.* imports.
type v1 struct{ m api.Module }

func (g v1) call(op int32, in []byte) string {
	f := func(n string, a ...uint64) uint64 {
		r, err := g.m.ExportedFunction(n).Call(ctx, a...)
		if err != nil {
			panic(err)
		}
		if len(r) > 0 {
			return r[0]
		}
		return 0
	}
	p := f("aprv_alloc", uint64(len(in)))
	g.m.Memory().Write(uint32(p), in)
	h := f("aprv_call", 1, uint64(op), p, uint64(len(in)))
	rp, rn := f("aprv_result_ptr", h), f("aprv_result_len", h)
	b, _ := g.m.Memory().Read(uint32(rp), uint32(rn))
	out := string(b)
	f("aprv_result_free", h)
	f("aprv_dealloc", p, uint64(len(in)))
	return out
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[len(s)/2]
}

func bench(mods, cases string) {
	paths := strings.Split(mods, ",")
	g5 := mustRow(cases, "receipt/verify-genuine-sandbox-g5-against-apple-roots")
	jws := mustRow(cases, "transaction/verify-shared-sandbox")
	// ABI v1's op 258 input: the same JWS with its test anchors, in ABI v1's envelope.
	var roots struct{ Roots []string }
	json.Unmarshal([]byte(jws.Config), &roots)
	env := []byte("APRVT1")
	env = binary.LittleEndian.AppendUint32(env, uint32(len(roots.Roots)))
	for _, r := range roots.Roots {
		der := mustB64(r)
		env = binary.LittleEndian.AppendUint32(env, uint32(len(der)))
		env = append(env, der...)
	}
	env = binary.LittleEndian.AppendUint64(env, 1<<63)
	env = append(env, jws.Text...)
	type sample struct{ compile, inst, init, first, second float64 }
	res := map[string][]sample{}
	for round := 0; round < 7; round++ {
		for i, path := range paths {
			wasm, _ := os.ReadFile(path)
			var s sample
			if i == 0 {
				t := time.Now()
				r := wazero.NewRuntime(ctx)
				r.NewHostModuleBuilder("aprv").
					NewFunctionBuilder().WithFunc(func() float64 { return float64(time.Now().UnixMilli()) }).Export("clock_now_ms").
					NewFunctionBuilder().WithFunc(func(p, n uint32) uint32 { return 0 }).Export("random_get").
					Instantiate(ctx)
				c, err := r.CompileModule(ctx, wasm)
				if err != nil {
					panic(err)
				}
				s.compile = ms(time.Since(t))
				t = time.Now()
				m, err := r.InstantiateModule(ctx, c, wazero.NewModuleConfig().WithName("").WithStartFunctions("_initialize"))
				if err != nil {
					panic(err)
				}
				s.inst = ms(time.Since(t))
				g := v1{m}
				t = time.Now()
				o := g.call(1, []byte(g5.Text))
				s.first = ms(time.Since(t))
				t = time.Now()
				g.call(1, []byte(g5.Text))
				s.second = ms(time.Since(t))
				if !strings.Contains(o, `"verified":true`) {
					panic(o)
				}
				r.Close(ctx)
			} else {
				t := time.Now()
				h, _, _ := NewHost(path)
				s.compile = ms(time.Since(t))
				t = time.Now()
				g, err := h.New()
				if err != nil {
					panic(err)
				}
				s.inst = ms(time.Since(t))
				t = time.Now()
				g.Init("")
				s.init = ms(time.Since(t))
				t = time.Now()
				o, _ := g.VerifyReceipt(nowMs(), g5.Text)
				s.first = ms(time.Since(t))
				t = time.Now()
				g.VerifyReceipt(nowMs(), g5.Text)
				s.second = ms(time.Since(t))
				if !strings.Contains(o, `"verified":true`) {
					panic(o)
				}
				h.r.Close(ctx)
			}
			res[path] = append(res[path], s)
		}
	}
	for i, path := range paths {
		var c, in, it, f, se []float64
		for _, s := range res[path] {
			c = append(c, s.compile)
			in = append(in, s.inst)
			it = append(it, s.init)
			f = append(f, s.first)
			se = append(se, s.second)
		}
		name := []string{"ABI v1", "canonical ABI"}[i]
		fmt.Printf("{\"module\":%q,\"rounds\":7,\"runtime_and_compile_ms\":%.1f,\"instantiate_ms\":%.2f,\"init_ms\":%.2f,\"first_g5_ms\":%.2f,\"second_g5_ms\":%.2f,\"to_first_result_ms\":%.1f}\n",
			name, median(c), median(in), median(it), median(f), median(se), median(c)+median(in)+median(it)+median(f))
	}
	// steady state, same process
	for i, path := range paths {
		name := []string{"ABI v1", "canonical ABI"}[i]
		for _, op := range []string{"g5", "jws"} {
			var run func() string
			if i == 0 {
				wasm, _ := os.ReadFile(path)
				r := wazero.NewRuntime(ctx)
				r.NewHostModuleBuilder("aprv").
					NewFunctionBuilder().WithFunc(func() float64 { return float64(time.Now().UnixMilli()) }).Export("clock_now_ms").
					NewFunctionBuilder().WithFunc(func(p, n uint32) uint32 { return 0 }).Export("random_get").
					Instantiate(ctx)
				c, _ := r.CompileModule(ctx, wasm)
				m, _ := r.InstantiateModule(ctx, c, wazero.NewModuleConfig().WithName("").WithStartFunctions("_initialize"))
				g := v1{m}
				if op == "g5" {
					run = func() string { return g.call(1, []byte(g5.Text)) }
				} else {
					run = func() string { return g.call(258, env) }
				}
			} else {
				h, _, _ := NewHost(path)
				g, _ := h.New()
				if op == "g5" {
					g.Init("")
					run = func() string { s, _ := g.VerifyReceipt(nowMs(), g5.Text); return s }
				} else {
					g.Init(jws.Config)
					run = func() string { s, _ := g.VerifySignedData(nowMs(), jws.Text); return s }
				}
			}
			for k := 0; k < 20; k++ {
				run()
			}
			n, t := 0, time.Now()
			for n < 30 || time.Since(t) < 3*time.Second {
				if o := run(); !strings.Contains(o, `"verified":true`) {
					panic(o)
				}
				n++
			}
			fmt.Printf("{\"module\":%q,\"op\":%q,\"calls\":%d,\"per_s\":%.1f}\n", name, op, n, float64(n)/time.Since(t).Seconds())
		}
	}
}

func mustB64(s string) []byte {
	b, err := b64.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var b64 = b64pkg.StdEncoding
