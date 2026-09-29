// Spike only (2026-09-29, round 13). The round-13 ABI tests on the core
// exports, called by hand: the interface's contract, the misuse cases a
// hand-rolled host can commit (the verdicts the coordinator asked for, and
// what actually happens), trap isolation and memory. "RECORD" lines report
// behaviour with no pass/fail expectation (no trap is expected there, per
// round 12).
package main

import (
	"fmt"
	"strings"
	"time"
)

var failed = 0
var badRandom = false
var randomCalls = 0

func check(name string, ok bool, detail string) {
	s := "PASS"
	if !ok {
		s = "FAIL"
		failed++
	}
	fmt.Printf("%s %s: %s\n", s, name, detail)
}

func record(name, detail string) { fmt.Printf("RECORD %s: %s\n", name, detail) }

func show(s string, err error) string {
	if err != nil {
		m := err.Error()
		if i := strings.Index(m, "\n"); i > 0 {
			m = m[:i]
		}
		return "TRAP/ERROR " + m
	}
	if len(s) > 100 {
		s = s[:100] + "..."
	}
	return s
}

// raw calls an export with explicit core arguments and no post-return: for misuse cases.
func (g *Guest) raw(fn string, args ...uint64) (uint32, error) {
	r, err := g.m.ExportedFunction(iface+fn).Call(ctx, args...)
	if err != nil {
		return 0, err
	}
	return uint32(r[0]), nil
}

func (g *Guest) readRet(rp uint32) string {
	ptr, _ := g.m.Memory().ReadUint32Le(rp)
	n, _ := g.m.Memory().ReadUint32Le(rp + 4)
	b, _ := g.m.Memory().Read(ptr, n)
	return string(b)
}

func (g *Guest) alloc(b []byte) uint32 {
	r, _ := g.realloc.Call(ctx, 0, 0, 1, uint64(len(b)))
	g.m.Memory().Write(uint32(r[0]), b)
	return uint32(r[0])
}

func tests(h *Host, cases string) int {
	g5 := mustRow(cases, "receipt/verify-genuine-sandbox-g5-against-apple-roots").input()
	jwsRow := mustRow(cases, "transaction/verify-shared-sandbox")
	jws, jwsConfig := jwsRow.input(), []byte(jwsRow.Config)
	fresh := func(config []byte) *Guest {
		g, err := h.New()
		if err != nil {
			panic(err)
		}
		if s, err := g.Init(config); err != nil || s != `{"ok":true}` {
			panic(fmt.Sprint("init: ", s, err))
		}
		return g
	}
	g5ok := func(g *Guest) bool {
		s, err := g.VerifyReceipt(nowMs(), g5)
		return err == nil && strings.Contains(s, `"verified":true`)
	}
	req := []byte(`{"receipt-data":"` + string(g5) + `"}`)
	afterTrap := func() string { return fmt.Sprintf("a fresh instance verifies g5: %v", g5ok(fresh(nil))) }

	// --- the interface's contract
	g, _ := h.New()
	s, err := g.Init(nil)
	check("init(empty) answers {\"ok\":true}", err == nil && s == `{"ok":true}`, show(s, err))
	g, _ = h.New()
	s, err = g.VerifyReceipt(nowMs(), g5)
	check("verify before init traps", err != nil, show(s, err)+"; "+afterTrap())
	g = fresh(nil)
	s, err = g.Init(nil)
	check("a second init traps", err != nil, show(s, err)+"; "+afterTrap())
	g, _ = h.New()
	s, err = g.Init([]byte("{not json"))
	s2, err2 := g.Init(nil)
	check("a config that is not JSON is {\"ok\":false}, and init can be retried", err == nil && strings.Contains(s, `"ok":false`) && s2 == `{"ok":true}` && err2 == nil && g5ok(g), show(s, err))
	g, _ = h.New()
	s, err = g.Init([]byte{'{', 0xff, '}'})
	check("a config that is not UTF-8 is {\"ok\":false}", err == nil && strings.Contains(s, `"ok":false`), show(s, err))
	g = fresh(nil)
	s, err = g.VerifyReceipt(nowMs(), g5)
	check("verify-receipt(genuine g5) verifies", err == nil && strings.Contains(s, `"bundleId":"dev.bonzer.weeka.app"`), show(s, err))
	gj := fresh(jwsConfig)
	s, err = gj.VerifySignedData(nowMs(), jws)
	check("verify-signed-data(shared-sandbox JWS, init with its test roots) verifies with payloadJson", err == nil && strings.Contains(s, `"verified":true`) && strings.Contains(s, `"payloadJson":`), show(s, err))
	s, err = g.VerifyReceiptEndpoint(1, nowMs(), req)
	check("verify-receipt-endpoint(env 1 = sandbox, g5) answers status 0", err == nil && strings.Contains(s, `"status":0`), show(s, err))
	s, err = g.VerifyReceiptEndpoint(0, nowMs(), req)
	check("verify-receipt-endpoint(env 0 = production, sandbox g5) answers status 21007", err == nil && strings.Contains(s, `"status":21007`), show(s, err))
	s, err = g.VerifyReceipt(nowMs(), nil)
	check("empty input is a verification failure value", err == nil && strings.Contains(s, `"INVALID_RECEIPT_FORMAT"`), show(s, err))
	s, err = g.VerifySignedData(nowMs(), []byte{'e', 'y', 0xff, 0xfe, '.', 'x'})
	check("a JWS that is not UTF-8 reaches the guest and is a value (ABI v1's answer)", err == nil && strings.Contains(s, `"jws is not valid UTF-8"`), show(s, err))
	s, err = g.VerifyReceipt(nowMs(), []byte{0xc3, 0x28})
	check("a receipt that is not UTF-8 is a value", err == nil && strings.Contains(s, `"INVALID_RECEIPT_FORMAT"`), show(s, err))
	s, err = g.Call("verify-receipt", uint32(5), g5)
	check("the lowering helper refuses a u32 where the WIT says u64 (loud host error, no call)", err != nil && strings.Contains(err.Error(), "the WIT type is d"), show(s, err))
	s, err = g.Call("verify-receipt-endpoint", uint64(1), nowMs(), req)
	check("the lowering helper refuses a u64 where the WIT says u32", err != nil && strings.Contains(err.Error(), "the WIT type is w"), show(s, err))
	s, err = g.Call("verify-receipt", nowMs(), 42)
	check("the lowering helper refuses an int where the WIT says list<u8>", err != nil && strings.Contains(err.Error(), "the WIT type is b"), show(s, err))
	s, err = g.Call("verify-receipt", nowMs())
	check("the lowering helper refuses a wrong argument count", err != nil, show(s, err))
	check("  ... and the instance still verifies g5", g5ok(g), "")

	// --- env
	for _, env := range []uint32{2, 255, 0xFFFFFFFF} {
		g = fresh(nil)
		s, err = g.VerifyReceiptEndpoint(env, nowMs(), req)
		check(fmt.Sprintf("endpoint with env %d traps", env), err != nil, show(s, err))
	}

	// --- what a hand-rolled host can get wrong with pointers
	g = fresh(nil)
	size := g.m.Memory().Size()
	_, err = g.raw("verify-receipt", nowMs(), uint64(size-4), 16)
	check("argument range past the end of memory traps", err != nil, show("", err)+"; "+afterTrap())
	g = fresh(nil)
	_, err = g.raw("verify-receipt", nowMs(), 0xFFFFFFF0, 0x20)
	check("argument range that overflows u32 traps", err != nil, show("", err)+"; "+afterTrap())
	g = fresh(nil)
	rp, err := g.raw("verify-receipt", nowMs(), 1024, 10)
	res := ""
	if err == nil {
		res = g.readRet(rp)
	}
	record("argument pointer not from cabi_realloc (the guest frees it)", show(res, err)+fmt.Sprintf("; the instance verifies g5 afterwards: %v", g5ok(g)))
	g = fresh(nil)
	p := g.alloc(g5)
	rp, _ = g.raw("verify-receipt", nowMs(), uint64(p), uint64(len(g5)))
	_, e1 := g.m.ExportedFunction("cabi_post_"+iface+"verify-receipt").Call(ctx, uint64(rp))
	_, e2 := g.m.ExportedFunction("cabi_post_"+iface+"verify-receipt").Call(ctx, uint64(rp))
	ok1, ok2 := g5ok(g), g5ok(g)
	record("double post-return on one result", fmt.Sprintf("first: %s; second: %s; the instance verifies g5 twice afterwards: %v %v", show("ok", e1), show("no trap", e2), ok1, ok2))
	g = fresh(nil)
	foreign := g.alloc([]byte("12345678")) // a real heap block, never returned by an export
	_, e3 := g.m.ExportedFunction("cabi_post_"+iface+"verify-receipt").Call(ctx, uint64(foreign))
	record("post-return with a foreign pointer (a heap block no export returned)", show("no trap", e3)+fmt.Sprintf("; the instance verifies g5 afterwards: %v", g5ok(g)))
	g = fresh(nil)
	_, e4 := g.m.ExportedFunction("cabi_post_"+iface+"verify-receipt").Call(ctx, 0)
	record("post-return with a null return pointer", show("no trap", e4))
	g = fresh(nil)
	p = g.alloc(g5)
	rpA, _ := g.raw("verify-receipt", nowMs(), uint64(p), uint64(len(g5)))
	p = g.alloc([]byte("x"))
	rpB, _ := g.raw("verify-receipt", nowMs(), uint64(p), 1)
	record("the return area is one static slot", fmt.Sprintf("retptr %d and %d; the first result now reads %q", rpA, rpB, show(g.readRet(rpA), nil)))

	// --- the import
	badRandom = true
	randomCalls = 0
	g = fresh(jwsConfig)
	s, err = g.VerifySignedData(nowMs(), jws)
	badRandom = false
	check("random-get answering the wrong length traps (if random-get is called at all)", err != nil || randomCalls == 0, fmt.Sprintf("random-get calls: %d; %s", randomCalls, show(s, err)))

	// --- isolation and memory
	a, b := fresh(nil), fresh(nil)
	before := g5ok(b)
	_, errA := a.VerifyReceiptEndpoint(2, nowMs(), req)
	check("isolation: a trap (env 2) in one instance leaves another verifying", errA != nil && before && g5ok(b) && g5ok(b), show("", errA))
	sA2, errA2 := a.VerifyReceipt(nowMs(), g5)
	record("the trapped instance itself, called again (a host should discard it)", show(sA2, errA2))
	g = fresh(nil)
	for i := 0; i < 200; i++ {
		g.VerifyReceipt(nowMs(), g5)
	}
	m1 := g.m.Memory().Size()
	t := time.Now()
	for i := 0; i < 2000; i++ {
		g.VerifyReceipt(nowMs(), g5)
	}
	check("no growth of linear memory over 2,000 more calls (with post-return)", m1 == g.m.Memory().Size(), fmt.Sprintf("%d -> %d bytes; %.2f ms/call", m1, g.m.Memory().Size(), float64(time.Since(t).Microseconds())/2000/1000))
	fmt.Printf("summary: %d failed\n", failed)
	return failed
}
