// Calls the real aprv.wasm (ABI 0.2.0) by hand on wazero, as the Go
// package does, with env 0, 1, 2, 255 and 2^32-1, and prints a value or
// the trap's error text. The endpoint is given the sandbox G5 receipt:
// status 0 means sandbox, 21007 production.
//
//	go run . <aprv.wasm> <repo>
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const iface = "aprv:verifier/verify@0.2.0#"

func main() {
	ctx := context.Background()
	wasm, err := os.ReadFile(os.Args[1])
	check(err)
	g5, err := os.ReadFile(os.Args[2] + "/fixtures/public-receipts/receipt-sandbox-g5.b64")
	check(err)
	body, _ := json.Marshal(map[string]string{"receipt-data": strings.TrimSpace(string(g5))})
	rt := wazero.NewRuntime(ctx)
	_, err = rt.NewHostModuleBuilder("aprv:verifier/host@0.2.0").NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, n, retptr uint32) {
			res, err := m.ExportedFunction("cabi_realloc").Call(ctx, 0, 0, 1, uint64(n))
			check(err)
			buf := make([]byte, n)
			_, _ = rand.Read(buf)
			m.Memory().Write(uint32(res[0]), buf)
			m.Memory().WriteUint32Le(retptr, uint32(res[0]))
			m.Memory().WriteUint32Le(retptr+4, n)
		}).Export("random-get").Instantiate(ctx)
	check(err)
	compiled, err := rt.CompileModule(ctx, wasm)
	check(err)
	fmt.Printf("module: %d bytes\n", len(wasm))
	for _, env := range []uint32{0, 1, 2, 255, 0xFFFFFFFF} {
		m, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("").WithStartFunctions())
		check(err)
		_, err = call(ctx, m, "init", nil, []byte("{}"))
		check(err)
		out, err := call(ctx, m, "verify-receipt-endpoint", []uint64{uint64(env), 1793577600000}, body)
		if err != nil {
			fmt.Printf("endpoint env %d: trap: %v\n", env, err)
		} else {
			var v struct{ Status int }
			_ = json.Unmarshal([]byte(out), &v)
			fmt.Printf("endpoint env %d: value status %d\n", env, v.Status)
		}
		_ = m.Close(ctx)
	}
}

func call(ctx context.Context, m api.Module, op string, scalars []uint64, data []byte) (string, error) {
	res, err := m.ExportedFunction("cabi_realloc").Call(ctx, 0, 0, 1, uint64(len(data)))
	check(err)
	m.Memory().Write(uint32(res[0]), data)
	args := append(scalars, res[0], uint64(len(data)))
	ret, err := m.ExportedFunction(iface+op).Call(ctx, args...)
	if err != nil {
		return "", err
	}
	area, _ := m.Memory().Read(uint32(ret[0]), 8)
	ptr, n := binary.LittleEndian.Uint32(area), binary.LittleEndian.Uint32(area[4:])
	out, _ := m.Memory().Read(ptr, n)
	s := string(out)
	_, err = m.ExportedFunction("cabi_post_"+iface+op).Call(ctx, ret[0])
	return s, err
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
