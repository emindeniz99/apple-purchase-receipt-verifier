// Runs a request corpus through the C ABI inside a wasm module under
// wazero (pure Go, no cgo), the same way run_rust.py runs it through the
// native .so and wasm/run.mjs runs it under Node. Rows: {"id","code","json"}.
//
//	go run . <module.wasm> <requests.jsonl> > rows.jsonl
//	go run . <module.wasm> <requests.jsonl> --bench <row id> <n>
//
// WASI gets no preopened directories, no environment and no arguments; the
// wall clock is the host's (WithSysWalltime). A trap is row code "TRAP" and
// the next row gets a fresh instance.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

var envBits = map[string]uint64{"Production": 1, "Sandbox": 2, "Xcode": 4, "LocalTesting": 8}

type request struct {
	ID      string  `json:"id"`
	Kind    string  `json:"kind"`
	Options string  `json:"options"`
	Input   string  `json:"input"`
	Op      int     `json:"op"`
	Base64  bool    `json:"base64"`
	GUIDHex *string `json:"guidHex"`
}

type options struct {
	BundleID             *string  `json:"bundleId"`
	AcceptedEnvironments []string `json:"acceptedEnvironments"`
	AppAppleID           *uint64  `json:"appAppleId"`
	Roots                []string `json:"roots"`
	Environment          *string  `json:"environment"`
	NowMillis            *int64   `json:"nowMillis"`
}

type row struct {
	ID   string  `json:"id"`
	Code any     `json:"code"`
	JSON *string `json:"json"`
	Trap string  `json:"trap,omitempty"`
}

type host struct {
	ctx      context.Context
	rt       wazero.Runtime
	compiled wazero.CompiledModule
	mod      api.Module
	handles  map[string]uint64
	pending  [][2]uint64
	n        int
}

func (h *host) instantiate() {
	if h.mod != nil {
		h.mod.Close(h.ctx)
	}
	h.n++
	cfg := wazero.NewModuleConfig().WithName(fmt.Sprintf("aprv%d", h.n)).
		WithStartFunctions("_initialize").WithSysWalltime().WithSysNanotime()
	mod, err := h.rt.InstantiateModule(h.ctx, h.compiled, cfg)
	if err != nil {
		panic(err)
	}
	h.mod, h.handles, h.pending = mod, map[string]uint64{}, nil
}

func (h *host) call(name string, args ...uint64) uint64 {
	f := h.mod.ExportedFunction(name)
	if f == nil {
		panic("missing export " + name)
	}
	r, err := f.Call(h.ctx, args...)
	if err != nil {
		panic(trap{err})
	}
	if len(r) == 0 {
		return 0
	}
	return r[0]
}

type trap struct{ err error }

func (h *host) alloc(n int) uint64 {
	if n < 1 {
		n = 1
	}
	p := h.call("aprv_alloc", uint64(n))
	h.pending = append(h.pending, [2]uint64{p, uint64(n)})
	return p
}

func (h *host) release() {
	for _, a := range h.pending {
		h.call("aprv_dealloc", a[0], a[1])
	}
	h.pending = nil
}

func (h *host) put(b []byte, nul bool) uint64 {
	n := len(b)
	if nul {
		n++
	}
	p := h.alloc(n)
	h.mod.Memory().Write(uint32(p), b)
	if nul {
		h.mod.Memory().WriteByte(uint32(p)+uint32(len(b)), 0)
	}
	return p
}

func (h *host) take(p uint32) *string {
	s := ""
	if p != 0 {
		var b []byte
		for i := p; ; i++ {
			c, ok := h.mod.Memory().ReadByte(i)
			if !ok || c == 0 {
				break
			}
			b = append(b, c)
		}
		s = strings.ToValidUTF8(string(b), "�")
		h.call("aprv_string_free", uint64(p))
	}
	return &s
}

func (h *host) u32(p uint64) uint32 {
	v, _ := h.mod.Memory().ReadUint32Le(uint32(p))
	return v
}

func (h *host) handle(r request, o options) uint64 {
	key := r.Kind + "\x00" + r.Options
	if v, ok := h.handles[key]; ok {
		return v
	}
	var ders, lens, count uint64
	if o.Roots != nil {
		count = uint64(len(o.Roots))
		ders, lens = h.alloc(4*len(o.Roots)), h.alloc(4*len(o.Roots))
		for i, s := range o.Roots {
			b, _ := base64.StdEncoding.DecodeString(s)
			h.mod.Memory().WriteUint32Le(uint32(ders)+uint32(4*i), uint32(h.put(b, false)))
			h.mod.Memory().WriteUint32Le(uint32(lens)+uint32(4*i), uint32(len(b)))
		}
	}
	bundle := ""
	if o.BundleID != nil {
		bundle = *o.BundleID
	}
	if r.Kind == "jws" && bundle == "" {
		bundle = "conformance.unset.bundle.id"
	}
	var v uint64
	switch r.Kind {
	case "receipt":
		if o.BundleID != nil {
			bp := h.put([]byte(bundle), true)
			if o.Roots == nil {
				v = h.call("aprv_verifier_new_receipt", bp)
			} else {
				v = h.call("aprv_verifier_new_receipt_with_roots", bp, ders, lens, count)
			}
		}
	case "jws":
		var mask, app uint64
		for _, e := range o.AcceptedEnvironments {
			mask |= envBits[e]
		}
		if o.AppAppleID != nil {
			app = *o.AppAppleID
		}
		bp := h.put([]byte(bundle), true)
		if o.Roots == nil {
			v = h.call("aprv_verifier_new_jws", bp, mask, app)
		} else {
			v = h.call("aprv_verifier_new_jws_with_roots", bp, mask, app, ders, lens, count)
		}
	default:
		var env, clock uint64
		if o.Environment != nil {
			env = envBits[*o.Environment]
		}
		if o.NowMillis != nil {
			clock = h.alloc(8)
			h.mod.Memory().WriteUint64Le(uint32(clock), uint64(*o.NowMillis))
		}
		v = h.call("aprv_endpoint_new_with_roots_and_clock", env, ders, lens, count, clock)
	}
	h.handles[key] = v
	return v
}

func hasNul(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

func (h *host) run(r request) row {
	var o options
	if err := json.Unmarshal([]byte(r.Options), &o); err != nil {
		panic(err)
	}
	data, _ := base64.StdEncoding.DecodeString(r.Input)
	hd := h.handle(r, o)
	if hd == 0 {
		return row{ID: r.ID, Code: "CTOR_REFUSED"}
	}
	if r.Kind == "endpoint" {
		if hasNul(data) {
			return row{ID: r.ID, Code: "NUL_IN_BODY"}
		}
		out := h.alloc(4)
		h.mod.Memory().WriteUint32Le(uint32(out), 0)
		st := int32(uint32(h.call("aprv_verify_receipt_endpoint_json", hd, h.put(data, true), out)))
		var code any
		if st != 0 {
			code = st
		}
		return row{ID: r.ID, Code: code, JSON: h.take(h.u32(out))}
	}
	res := h.alloc(8)
	h.mod.Memory().WriteUint64Le(uint32(res), 0)
	if r.Kind == "jws" {
		if hasNul(data) {
			return row{ID: r.ID, Code: "NUL_IN_INPUT"}
		}
		name := []string{"aprv_verify_transaction", "aprv_verify_app_transaction", "aprv_verify_raw"}[r.Op]
		h.call(name, hd, h.put(data, true), res)
	} else {
		var guid []byte
		if r.GUIDHex != nil {
			guid, _ = hex.DecodeString(*r.GUIDHex)
		}
		switch {
		case r.Base64 && hasNul(data):
			return row{ID: r.ID, Code: "NUL_IN_INPUT"}
		case r.Base64 && guid != nil:
			h.call("aprv_verify_receipt_base64_with_device_guid", hd, h.put(data, true), h.put(guid, false), uint64(len(guid)), res)
		case r.Base64:
			h.call("aprv_verify_receipt_base64", hd, h.put(data, true), res)
		case guid != nil:
			h.call("aprv_verify_receipt_der_with_device_guid", hd, h.put(data, false), uint64(len(data)), h.put(guid, false), uint64(len(guid)), res)
		default:
			h.call("aprv_verify_receipt_der", hd, h.put(data, false), uint64(len(data)), res)
		}
	}
	st, _ := h.mod.Memory().ReadUint32Le(uint32(res))
	return row{ID: r.ID, Code: int32(st), JSON: h.take(h.u32(res + 4))}
}

func (h *host) safe(r request) (out row) {
	defer func() {
		if p := recover(); p != nil {
			t, ok := p.(trap)
			if !ok {
				panic(p)
			}
			msg := strings.SplitN(t.err.Error(), "\n", 2)[0]
			h.instantiate()
			out = row{ID: r.ID, Code: "TRAP", Trap: msg}
		}
	}()
	out = h.run(r)
	h.release()
	return out
}

func main() {
	ctx := context.Background()
	wasm, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)
	compiled, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		panic(err)
	}
	for _, imp := range compiled.ImportedFunctions() {
		m, n, _ := imp.Import()
		if m != "wasi_snapshot_preview1" {
			fmt.Fprintf(os.Stderr, "unresolvable import %s.%s\n", m, n)
			os.Exit(3)
		}
	}
	h := &host{ctx: ctx, rt: rt, compiled: compiled}
	h.instantiate()
	raw, err := os.ReadFile(os.Args[2])
	if err != nil {
		panic(err)
	}
	var reqs []request
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r request
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			panic(err)
		}
		reqs = append(reqs, r)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if len(os.Args) > 5 && os.Args[3] == "--bench" {
		n, _ := strconv.Atoi(os.Args[5])
		for _, r := range reqs {
			if r.ID != os.Args[4] {
				continue
			}
			first := h.safe(r)
			for i := 0; i < 200 && i < n; i++ {
				h.safe(r)
			}
			t := time.Now()
			for i := 0; i < n; i++ {
				h.run(r)
				h.release()
			}
			us := float64(time.Since(t).Microseconds()) / float64(n)
			fmt.Printf(`{"id":%q,"code":%v,"n":%d,"mean_us":%.1f,"memory_bytes":%d}`+"\n",
				r.ID, first.Code, n, us, h.mod.Memory().Size())
		}
		return
	}
	for _, r := range reqs {
		enc.Encode(h.safe(r))
	}
}
