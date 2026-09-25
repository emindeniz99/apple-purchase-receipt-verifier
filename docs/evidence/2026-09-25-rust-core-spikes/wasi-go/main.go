package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed aprv_wasi.wasm
var wasm []byte

func main() {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)
	t0 := time.Now()
	compiled, err := rt.CompileModule(ctx, wasm)
	if err != nil { panic(err) }
	mod, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithStartFunctions("_initialize").WithSysWalltime())
	if err != nil { panic(err) }
	fmt.Println("compile+instantiate", time.Since(t0))
	alloc, free, verify := mod.ExportedFunction("aprv_alloc"), mod.ExportedFunction("aprv_dealloc"), mod.ExportedFunction("aprv_verify_receipt_b64")
	put := func(s string) (uint64, uint64) {
		r, _ := alloc.Call(ctx, uint64(len(s)))
		mod.Memory().Write(uint32(r[0]), []byte(s))
		return r[0], uint64(len(s))
	}
	raw, _ := os.ReadFile("../../../../fixtures/public-receipts/receipt-sandbox-g5.b64")
	b64 := strings.Join(strings.Fields(string(raw)), "")
	call := func(bid string) string {
		bp, bl := put(bid)
		rp, rl := put(b64)
		res, err := verify.Call(ctx, bp, bl, rp, rl)
		if err != nil { return "TRAP: " + err.Error() }
		p, l := uint32(res[0]>>32), uint32(res[0])
		b, _ := mod.Memory().Read(p, l)
		s := string(b)
		free.Call(ctx, uint64(p), uint64(l)); free.Call(ctx, bp, bl); free.Call(ctx, rp, rl)
		return s
	}
	fmt.Println(call("dev.bonzer.weeka.app"))
	fmt.Println(call("com.other.app"))
	n := 200
	t := time.Now()
	for i := 0; i < n; i++ { call("dev.bonzer.weeka.app") }
	fmt.Printf("wazero genuine g5 %d us/op\n", time.Since(t).Microseconds()/int64(n))
}
