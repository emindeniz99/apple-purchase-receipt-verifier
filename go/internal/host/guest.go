package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"runtime"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// live counts instances not yet closed, for the test that shows an
// abandoned pool gives its instances back.
var live atomic.Int64

// Guest is one instance of the module, after a successful init. It serves
// one call at a time: the return area is one static slot in guest memory.
// Once a call fails inside the guest the Guest is dead and answers nothing:
// wazero keeps running a trapped instance, and this package must not.
type Guest struct {
	m       api.Module
	realloc api.Function
	dead    bool
}

// newGuest instantiates the module and runs init with config, the JSON of
// ARCHITECTURE.md §4 (empty means the built-in Apple roots).
func (mod *module) newGuest(config []byte) (*Guest, error) {
	m, err := mod.rt.InstantiateModule(ctx, mod.compiled,
		wazero.NewModuleConfig().WithName("").WithStartFunctions())
	if err != nil {
		return nil, fmt.Errorf("instantiating aprv.wasm: %w", err)
	}
	g := &Guest{m: m, realloc: m.ExportedFunction("cabi_realloc")}
	live.Add(1)
	// wazero lists every instance it makes, so a Guest that is merely
	// dropped would stay in memory for the life of the process. The
	// finalizer closes it once nothing refers to the Guest.
	runtime.SetFinalizer(g, (*Guest).close)

	answer, err := g.Call("init", config)
	if err != nil {
		return nil, err
	}
	var reply struct {
		OK      *bool  `json:"ok"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(answer), &reply); err != nil || reply.OK == nil {
		g.close()
		return nil, &ResultError{Fn: "init", Detail: "the answer is not {\"ok\":...}"}
	}
	if !*reply.OK {
		g.close()
		return nil, &InitRefusedError{Message: reply.Message, Answer: answer}
	}
	return g, nil
}

// close discards the instance and everything in it.
func (g *Guest) close() {
	if g.m == nil {
		return
	}
	runtime.SetFinalizer(g, nil)
	_ = g.m.Close(ctx)
	g.m = nil
	g.dead = true
	live.Add(-1)
}

// memorySize is the instance's linear memory in bytes.
func (g *Guest) memorySize() uint32 { return g.m.Memory().Size() }

// maxInput is the most bytes of any input that is copied into linear memory:
// one more than the largest cap the core has (3,145,728 for a receipt or an
// endpoint body). An input over a cap is over it however long it is, so the
// core answers TOO_LARGE (21002 at the endpoint) to the cut input exactly as it
// would to the whole one, and a hostile caller cannot make this package copy
// hundreds of megabytes into the module first.
const maxInput = 3_145_729

// lower turns WIT values into core arguments for fn: a u32 (uint32) and a
// u64 (uint64) pass as scalars; a list<u8> (string or []byte) is copied
// into a guest buffer from cabi_realloc, which the guest then owns, and
// passes as (ptr, len). A wrong count or Go type is refused before
// anything is allocated.
func (g *Guest) lower(fn string, args []any) ([]uint64, error) {
	sig, ok := sigs[fn]
	if !ok || len(sig) != len(args) {
		return nil, usagef("%s: unknown export or wrong argument count", fn)
	}
	for i, a := range args {
		ok := false
		switch a.(type) {
		case uint32:
			ok = sig[i] == 'w'
		case uint64:
			ok = sig[i] == 'd'
		case string, []byte:
			ok = sig[i] == 'b'
		}
		if !ok {
			return nil, usagef("%s: argument %d is %T, the WIT type is %c", fn, i, a, sig[i])
		}
	}
	mem := g.m.Memory()
	out := make([]uint64, 0, 4)
	for i, a := range args {
		var n int
		var write func(ptr uint32) bool
		switch v := a.(type) {
		case uint32:
			out = append(out, api.EncodeU32(v))
			continue
		case uint64:
			out = append(out, v)
			continue
		case string:
			if len(v) > maxInput {
				v = v[:maxInput]
			}
			n, write = len(v), func(ptr uint32) bool { return mem.WriteString(ptr, v) }
		case []byte:
			if len(v) > maxInput {
				v = v[:maxInput]
			}
			n, write = len(v), func(ptr uint32) bool { return mem.Write(ptr, v) }
		}
		res, err := g.realloc.Call(ctx, 0, 0, 1, uint64(n))
		if err != nil {
			return nil, err
		}
		ptr := api.DecodeU32(res[0])
		if !write(ptr) {
			return nil, &ResultError{Fn: fn, Detail: fmt.Sprintf("cabi_realloc returned a buffer outside memory for argument %d", i)}
		}
		out = append(out, api.EncodeU32(ptr), uint64(n))
	}
	return out, nil
}

// Call runs one export whose result is a string: lower the arguments,
// call, read (ptr, len) from the return area, copy the result out, then
// call the post-return function, which frees it. No guest pointer leaves
// this method, and the post-return is called exactly once: a second call
// would not trap on wazero and would corrupt the guest's heap.
//
// A failure inside the guest (a trap, or an answer outside memory) kills
// the Guest. The error is a *TrapError or *ResultError; a usage error
// happens before the guest is touched and leaves it alive.
func (g *Guest) Call(fn string, args ...any) (string, error) {
	if g.dead {
		return "", &TrapError{Fn: fn, Err: errors.New("the instance was discarded after an earlier failure")}
	}
	core, err := g.lower(fn, args)
	if err != nil {
		return "", g.fail(fn, err)
	}
	ret, err := g.m.ExportedFunction(verifyIface+fn).Call(ctx, core...)
	if err != nil {
		return "", g.fail(fn, err)
	}
	mem := g.m.Memory()
	// An i32 result: the upper half of the uint64 is not defined.
	rp := api.DecodeU32(ret[0])
	ptr, ok1 := mem.ReadUint32Le(rp)
	n, ok2 := mem.ReadUint32Le(rp + 4)
	if rp > math.MaxUint32-8 || !ok1 || !ok2 {
		return "", g.fail(fn, &ResultError{Fn: fn, Detail: "the return area is outside memory"})
	}
	b, ok := mem.Read(ptr, n)
	if !ok {
		return "", g.fail(fn, &ResultError{Fn: fn, Detail: fmt.Sprintf("the result (%d, %d) is outside memory", ptr, n)})
	}
	out := string(b) // copies
	if _, err := g.m.ExportedFunction("cabi_post_"+verifyIface+fn).Call(ctx, api.EncodeU32(rp)); err != nil {
		return "", g.fail(fn, err)
	}
	return out, nil
}

// fail classifies err and, unless it is a usage error, discards the Guest.
func (g *Guest) fail(fn string, err error) error {
	var usage *usageError
	if errors.As(err, &usage) {
		return err
	}
	g.close()
	var result *ResultError
	if errors.As(err, &result) {
		return err
	}
	return &TrapError{Fn: fn, Err: err}
}
