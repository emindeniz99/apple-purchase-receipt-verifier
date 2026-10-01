// Package host runs aprv.wasm under wazero. It holds no verification
// logic: it compiles the module once, creates instances, hands each
// instance its trust anchors through init, moves bytes in and JSON out
// through the canonical ABI, and throws an instance away when it traps.
//
// The ABI is aprv:verifier@0.1.0 (docs/rust-core/ARCHITECTURE.md §4). wazero
// has no Component Model, so the four exports are called by hand: the
// package name in the export names is the ABI version, and a module of
// another version finds no export here and is refused at create.
package host

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/wasm"
)

const (
	verifyIface = "aprv:verifier/verify@0.1.0#"
	hostIface   = "aprv:verifier/host@0.1.0"

	// memoryLimitPages is 256 MiB of linear memory per instance, the limit
	// aprv-server sets. A guest that tries to grow past it gets -1 from
	// memory.grow and traps.
	memoryLimitPages = 4096

	// maxRandomRequest bounds one random-get. OpenSSL asks for a few dozen
	// bytes; a module asking for more is not the module we built.
	maxRandomRequest = 1 << 20
)

// ctx is the context of every call: the public API has none.
var ctx = context.Background()

// randReader is where random-get's bytes come from; a test swaps it.
var randReader io.Reader = rand.Reader

// sigs is each export's WIT parameters, in order: 'w' u32, 'd' u64,
// 'b' list<u8>. Each export answers one string through a return area.
var sigs = map[string]string{
	"init":                    "b",
	"verify-receipt":          "db",
	"verify-signed-data":      "db",
	"verify-receipt-endpoint": "wdb",
}

// module is one compiled aprv.wasm and the runtime it lives in.
type module struct {
	rt       wazero.Runtime
	compiled wazero.CompiledModule
}

// loaded is the process's one compiled module: the compile takes about a
// second, and every Verifier shares the result. The compilation cache stays
// off, so nothing compiled is ever read back from disk.
var loaded = sync.OnceValues(func() (*module, error) { return compile(wasm.Module) })

// newRuntime is a runtime with the memory limit and the one import.
func newRuntime() (wazero.Runtime, error) {
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithMemoryLimitPages(memoryLimitPages))
	if err := instantiateHost(rt); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	return rt, nil
}

func compile(bytes []byte) (*module, error) {
	rt, err := newRuntime()
	if err != nil {
		return nil, err
	}
	compiled, err := rt.CompileModule(ctx, bytes)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("compiling aprv.wasm: %w", err)
	}
	if err := checkABI(compiled); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	return &module{rt: rt, compiled: compiled}, nil
}

// instantiateHost provides the module's one import,
// random-get: func(len: u32) -> list<u8>. Lowered it is (len, retptr): the
// list is written into guest memory obtained from cabi_realloc and its
// (ptr, len) into the return area. Anything else the module imports is not
// resolvable, so instantiation refuses it.
func instantiateHost(rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder(hostIface).NewFunctionBuilder().
		WithFunc(randomGet).Export("random-get").Instantiate(ctx)
	return err
}

// randomGet runs inside a guest call. A panic here is turned into a
// runtime error by wazero, which the call reports as a trap.
func randomGet(ctx context.Context, m api.Module, n, retptr uint32) {
	if n > maxRandomRequest {
		panic(fmt.Sprintf("random-get asked for %d bytes", n))
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(randReader, buf); err != nil {
		panic(err)
	}
	res, err := m.ExportedFunction("cabi_realloc").Call(ctx, 0, 0, 1, uint64(n))
	if err != nil {
		panic(err)
	}
	ptr := api.DecodeU32(res[0])
	mem := m.Memory()
	if !mem.Write(ptr, buf) || !mem.WriteUint32Le(retptr, ptr) || !mem.WriteUint32Le(retptr+4, n) {
		panic("random-get: cabi_realloc or the return area is outside guest memory")
	}
}

// coreParams flattens a WIT signature into core Wasm parameter types.
func coreParams(sig string) []api.ValueType {
	var out []api.ValueType
	for _, c := range sig {
		switch c {
		case 'w':
			out = append(out, api.ValueTypeI32)
		case 'd':
			out = append(out, api.ValueTypeI64)
		default: // 'b': (ptr, len)
			out = append(out, api.ValueTypeI32, api.ValueTypeI32)
		}
	}
	return out
}

func sameTypes(a, b []api.ValueType) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// checkABI refuses a module this package would misread: it must import only
// random-get, and export the four @0.1.0 operations with their
// post-return functions, cabi_realloc and its memory, all with the
// core signatures the canonical ABI gives them. The refusal names the
// version this package binds and the exports the module has.
func checkABI(c wazero.CompiledModule) error {
	for _, def := range c.ImportedFunctions() {
		mod, name, _ := def.Import()
		if mod != hostIface || name != "random-get" ||
			!sameTypes(def.ParamTypes(), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}) || len(def.ResultTypes()) != 0 {
			return &ABIError{Detail: fmt.Sprintf(
				"aprv.wasm imports %s %s; this package binds aprv:verifier@0.1.0, whose module imports only %s random-get",
				mod, name, hostIface)}
		}
	}
	if len(c.ImportedMemories()) != 0 {
		return &ABIError{Detail: "aprv.wasm imports a memory; this package binds aprv:verifier@0.1.0, whose module defines its own"}
	}

	have := c.ExportedFunctions()
	var names []string
	for name := range have {
		names = append(names, name)
	}
	sort.Strings(names)
	missing := func(name string) error {
		return &ABIError{Detail: fmt.Sprintf(
			"aprv.wasm does not export %q, or exports it with another signature: this package binds aprv:verifier@0.1.0; the module exports [%s]",
			name, strings.Join(names, ", "))}
	}
	want := func(name string, params []api.ValueType, results []api.ValueType) error {
		def, ok := have[name]
		if !ok || !sameTypes(def.ParamTypes(), params) || !sameTypes(def.ResultTypes(), results) {
			return missing(name)
		}
		return nil
	}
	i32 := api.ValueTypeI32
	if err := want("cabi_realloc", []api.ValueType{i32, i32, i32, i32}, []api.ValueType{i32}); err != nil {
		return err
	}
	for op, sig := range sigs {
		if err := want(verifyIface+op, coreParams(sig), []api.ValueType{i32}); err != nil {
			return err
		}
		if err := want("cabi_post_"+verifyIface+op, []api.ValueType{i32}, nil); err != nil {
			return err
		}
	}
	if _, ok := c.ExportedMemories()["memory"]; !ok {
		return &ABIError{Detail: fmt.Sprintf(
			"aprv.wasm does not export its memory: this package binds aprv:verifier@0.1.0; the module exports [%s]",
			strings.Join(names, ", "))}
	}
	return nil
}
