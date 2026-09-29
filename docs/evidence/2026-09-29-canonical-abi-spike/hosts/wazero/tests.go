// Spike only (2026-09-29, round 12). ABI v1's tests, adapted to the
// canonical-ABI module and run by hand on its core exports, plus the misuse
// a hand-rolled host can commit that a component runtime would prevent
// (bad pointers, invalid UTF-8, an out-of-range enum, post-return misuse).
// Each misuse case reports what actually happened; `want` says what a safe
// module should do, and the case passes only if it does.
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

func show(s string, err error) string {
	if err != nil {
		m := err.Error()
		if i := strings.Index(m, "\n"); i > 0 {
			m = m[:i]
		}
		return "TRAP " + m
	}
	if len(s) > 90 {
		s = s[:90] + "..."
	}
	return s
}

// raw calls an export with explicit (ptr, len) and no post-return: for misuse cases.
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
	g5 := mustRow(cases, "receipt/verify-genuine-sandbox-g5-against-apple-roots")
	jws := mustRow(cases, "transaction/verify-shared-sandbox")
	fresh := func(config string) *Guest {
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
		s, err := g.VerifyReceipt(nowMs(), g5.Text)
		return err == nil && strings.Contains(s, `"verified":true`)
	}
	afterTrap := func() string { return fmt.Sprintf("fresh instance verifies g5: %v", g5ok(fresh(""))) }

	// --- the interface's contract
	g, _ := h.New()
	s, err := g.Init("")
	check("init(\"\") answers {\"ok\":true}", err == nil && s == `{"ok":true}`, show(s, err))
	g, _ = h.New()
	s, err = g.VerifyReceipt(nowMs(), g5.Text)
	check("verify before init traps", err != nil, show(s, err)+"; "+afterTrap())
	g = fresh("")
	s, err = g.Init("")
	check("a second init traps", err != nil, show(s, err)+"; "+afterTrap())
	g, _ = h.New()
	s, err = g.Init("{not json")
	s2, err2 := g.Init("")
	check("a config that is not JSON is {\"ok\":false}, and init can be retried", err == nil && strings.HasPrefix(s, `{"message":`) && strings.Contains(s, `"ok":false`) && s2 == `{"ok":true}` && err2 == nil && g5ok(g), show(s, err))
	g, _ = h.New()
	s, err = g.Init(`{"roots":["not base64!"]}`)
	check("a root that is not base64 is {\"ok\":false}", err == nil && strings.Contains(s, `"ok":false`), show(s, err))
	g = fresh("")
	s, err = g.VerifyReceipt(nowMs(), g5.Text)
	check("verify-receipt(genuine g5) verifies", err == nil && strings.Contains(s, `"bundleId":"dev.bonzer.weeka.app"`), show(s, err))
	gj := fresh(jws.Config)
	s, err = gj.VerifySignedData(nowMs(), jws.Text)
	check("verify-signed-data(shared-sandbox JWS, init with its test roots) verifies with payloadJson", err == nil && strings.Contains(s, `"verified":true`) && strings.Contains(s, `"payloadJson":`), show(s, err))
	s, err = g.VerifyReceiptEndpoint(1, nowMs(), `{"receipt-data":"`+g5.Text+`"}`)
	check("verify-receipt-endpoint(sandbox, g5) answers status 0", err == nil && strings.Contains(s, `"status":0`), show(s, err))
	s, err = g.VerifyReceipt(nowMs(), "")
	check("empty input is a verification failure value", err == nil && strings.Contains(s, `"INVALID_RECEIPT_FORMAT"`), show(s, err))
	s, err = g.VerifySignedData(nowMs(), "��.")
	check("a JWS that is not a JWS is a value", err == nil && strings.Contains(s, `"verified":false`), show(s, err))

	// --- what a hand-rolled host can get wrong (the component runtime prevents all of these)
	for _, env := range []uint64{2, 255, 0xFFFFFFFF} {
		g = fresh("")
		p := g.alloc([]byte(`{"receipt-data":"` + g5.Text + `"}`))
		rp, err := g.raw("verify-receipt-endpoint", env, nowMs(), uint64(p), uint64(len(g5.Text)+19))
		res := ""
		if err == nil {
			res = g.readRet(rp)
		}
		check(fmt.Sprintf("misuse: endpoint with enum value %d traps (want: trap)", env), err != nil, show(res, err))
	}
	g = fresh("")
	p := g.alloc([]byte{'e', 'y', 0xff, 0xfe, '.', 'x'})
	rp, err := g.raw("verify-signed-data", nowMs(), uint64(p), 6)
	res := ""
	if err == nil {
		res = g.readRet(rp)
	}
	check("misuse: a string argument that is not UTF-8 traps (want: trap)", err != nil, show(res, err))
	g = fresh("")
	size := g.m.Memory().Size()
	rp, err = g.raw("verify-receipt", nowMs(), uint64(size-4), 16)
	check("misuse: argument range past the end of memory traps (want: trap)", err != nil, show("", err)+"; "+afterTrap())
	g = fresh("")
	rp, err = g.raw("verify-receipt", nowMs(), 0xFFFFFFF0, 0x20)
	check("misuse: argument range that overflows u32 traps (want: trap)", err != nil, show("", err)+"; "+afterTrap())
	g = fresh("")
	rp, err = g.raw("verify-receipt", nowMs(), 1024, 10)
	res = ""
	if err == nil {
		res = g.readRet(rp)
	}
	check("misuse: argument pointer not from cabi_realloc (the guest frees it) traps (want: trap)", err != nil, show(res, err))
	if err == nil {
		check("  ... and the instance still verifies g5 afterwards", g5ok(g), "")
	}
	g = fresh("")
	p = g.alloc([]byte(g5.Text))
	rp, err = g.raw("verify-receipt", nowMs(), uint64(p), uint64(len(g5.Text)))
	_, e1 := g.m.ExportedFunction("cabi_post_"+iface+"verify-receipt").Call(ctx, uint64(rp))
	_, e2 := g.m.ExportedFunction("cabi_post_"+iface+"verify-receipt").Call(ctx, uint64(rp))
	check("misuse: post-return twice on the same result traps (want: trap)", e1 == nil && e2 != nil, fmt.Sprintf("first: %v; second: %s", e1, show("", e2)))
	if e2 == nil {
		ok := g5ok(g)
		ok2 := g5ok(g)
		check("  ... and the instance still verifies g5 twice afterwards", ok && ok2, fmt.Sprintf("%v %v", ok, ok2))
	}
	g = fresh("")
	_, e3 := g.m.ExportedFunction("cabi_post_"+iface+"verify-receipt").Call(ctx, 0)
	check("misuse: post-return with a return pointer that was never returned traps (want: trap)", e3 != nil, show("", e3))
	if e3 == nil {
		check("  ... and the instance still verifies g5 afterwards", g5ok(g), "")
	}
	g = fresh("")
	before := g.m.Memory().Size()
	for i := 0; i < 300; i++ {
		p = g.alloc([]byte(g5.Text))
		g.raw("verify-receipt", nowMs(), uint64(p), uint64(len(g5.Text)))
	}
	check("misuse: 300 calls with no post-return leak the results (memory before/after, bytes)", true, fmt.Sprintf("%d -> %d", before, g.m.Memory().Size()))
	g = fresh("")
	p = g.alloc([]byte(g5.Text))
	rpA, _ := g.raw("verify-receipt", nowMs(), uint64(p), uint64(len(g5.Text)))
	p = g.alloc([]byte("x"))
	rpB, _ := g.raw("verify-receipt", nowMs(), uint64(p), 1)
	check("the return area is one static slot: a second call before post-return overwrites the first result's (ptr, len)", rpA == rpB, fmt.Sprintf("retptr %d and %d; first result now reads %q", rpA, rpB, show(g.readRet(rpA), nil)))

	// --- the import
	badRandom = true
	randomCalls = 0
	g = fresh(jws.Config)
	s, err = g.VerifySignedData(nowMs(), jws.Text)
	badRandom = false
	check("random-get answering the wrong length traps (want: trap, if random-get is called at all)", err != nil || randomCalls == 0, fmt.Sprintf("random-get calls: %d; %s", randomCalls, show(s, err)))

	// --- isolation and memory
	a, b := fresh(""), fresh("")
	before1 := g5ok(b)
	pa := a.alloc([]byte("x"))
	_, errA := a.raw("verify-receipt", nowMs(), uint64(a.m.Memory().Size()-2), 8)
	_ = pa
	check("isolation: a trap in one instance leaves another untouched", errA != nil && before1 && g5ok(b), show("", errA))
	g = fresh("")
	for i := 0; i < 200; i++ {
		g.VerifyReceipt(nowMs(), g5.Text)
	}
	m1 := g.m.Memory().Size()
	t := time.Now()
	for i := 0; i < 2000; i++ {
		g.VerifyReceipt(nowMs(), g5.Text)
	}
	check("no growth of linear memory over 2,000 more calls (with post-return)", m1 == g.m.Memory().Size(), fmt.Sprintf("%d -> %d bytes; %.2f ms/call", m1, g.m.Memory().Size(), float64(time.Since(t).Microseconds())/2000/1000))
	fmt.Printf("summary: %d failed\n", failed)
	return failed
}
