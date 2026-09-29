package host

// The ABI tests of the canonical-ABI final round (docs/evidence/
// 2026-09-29-canonical-abi-final/hosts/wazero/tests.go) that apply to a
// wrapper, run against the embedded module. They assert what the ABI
// guarantees and nothing about the wire's payload shapes, so they hold for
// every module of the ABI.

import (
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
)

const now uint64 = 1_722_945_600_000 // 2024-08-06T12:00:00Z

func testModule(t testing.TB) *module {
	t.Helper()
	mod, err := loaded()
	if err != nil {
		t.Fatalf("loading the embedded module: %v", err)
	}
	return mod
}

// bareGuest is an instance before init, which no Pool ever hands out.
func bareGuest(t testing.TB) *Guest {
	t.Helper()
	mod := testModule(t)
	m, err := mod.rt.InstantiateModule(ctx, mod.compiled, wazero.NewModuleConfig().WithName("").WithStartFunctions())
	if err != nil {
		t.Fatal(err)
	}
	live.Add(1)
	g := &Guest{m: m, realloc: m.ExportedFunction("cabi_realloc")}
	t.Cleanup(g.close)
	return g
}

func freshGuest(t testing.TB, config []byte) *Guest {
	t.Helper()
	g, err := testModule(t).newGuest(config)
	if err != nil {
		t.Fatalf("new instance: %v", err)
	}
	t.Cleanup(g.close)
	return g
}

func isTrap(err error) bool {
	var trap *TrapError
	return errors.As(err, &trap)
}

func verified(answer string) bool { return strings.Contains(answer, `"verified":true`) }

func TestInitAnswers(t *testing.T) {
	g := bareGuest(t)
	answer, err := g.Call("init", []byte(nil))
	if err != nil || answer != `{"ok":true}` {
		t.Fatalf("init(empty) = %q, %v; want {\"ok\":true}", answer, err)
	}
}

func TestVerifyBeforeInitTraps(t *testing.T) {
	fx := loadFixtures(t)
	g := bareGuest(t)
	_, err := g.Call("verify-receipt", now, fx.g5)
	if !isTrap(err) {
		t.Fatalf("verify before init: %v, want a trap", err)
	}
	// The trapped instance answers nothing more, though wazero would let it.
	if _, err := g.Call("init", []byte(nil)); !isTrap(err) {
		t.Fatalf("a discarded instance answered: %v", err)
	}
}

func TestSecondInitTraps(t *testing.T) {
	g := freshGuest(t, nil)
	if _, err := g.Call("init", []byte(nil)); !isTrap(err) {
		t.Fatalf("second init: %v, want a trap", err)
	}
}

func TestRefusedConfigCanBeRetriedOnTheInstance(t *testing.T) {
	// The ABI allows init to be retried after {"ok":false}; the wrapper
	// itself discards such an instance, which TestNewPoolRefusesABadRoot shows.
	for name, config := range map[string][]byte{
		"not JSON":                      []byte("{not json"),
		"not UTF-8":                     {'{', 0xff, '}'},
		"a root that is not base64 DER": []byte(`{"roots":["AAAA"]}`),
	} {
		t.Run(name, func(t *testing.T) {
			g := bareGuest(t)
			answer, err := g.Call("init", config)
			if err != nil || !strings.Contains(answer, `"ok":false`) {
				t.Fatalf("init(%q) = %q, %v; want {\"ok\":false,...}", config, answer, err)
			}
			if answer, err := g.Call("init", []byte(nil)); err != nil || answer != `{"ok":true}` {
				t.Fatalf("init after a refusal = %q, %v", answer, err)
			}
		})
	}
}

func TestOperations(t *testing.T) {
	fx := loadFixtures(t)
	g := freshGuest(t, nil)
	answer, err := g.Call("verify-receipt", now, fx.g5)
	if err != nil || !verified(answer) {
		t.Errorf("the genuine sandbox receipt: %q, %v", answer, err)
	}
	gj := freshGuest(t, fx.jwsConfig)
	answer, err = gj.Call("verify-signed-data", now, fx.jws)
	if err != nil || !verified(answer) {
		t.Errorf("the shared sandbox JWS under its test root: %q, %v", answer, err)
	}
	req := `{"receipt-data":"` + fx.g5 + `"}`
	answer, err = g.Call("verify-receipt-endpoint", uint32(1), now, req)
	if err != nil || !strings.Contains(answer, `"status":0`) {
		t.Errorf("endpoint, sandbox: %q, %v; want status 0", answer, err)
	}
	answer, err = g.Call("verify-receipt-endpoint", uint32(0), now, req)
	if err != nil || !strings.Contains(answer, `"status":21007`) {
		t.Errorf("endpoint, production, sandbox receipt: %q, %v; want status 21007", answer, err)
	}
}

func TestBadInputIsAValueNotATrap(t *testing.T) {
	g := freshGuest(t, nil)
	for name, call := range map[string]func() (string, error){
		"empty receipt":     func() (string, error) { return g.Call("verify-receipt", now, []byte(nil)) },
		"receipt not UTF-8": func() (string, error) { return g.Call("verify-receipt", now, []byte{0xc3, 0x28}) },
		"JWS not UTF-8": func() (string, error) {
			return g.Call("verify-signed-data", now, []byte{'e', 'y', 0xff, 0xfe, '.', 'x'})
		},
		"endpoint not UTF-8":  func() (string, error) { return g.Call("verify-receipt-endpoint", uint32(0), now, []byte{0xff, 0xfe}) },
		"endpoint empty body": func() (string, error) { return g.Call("verify-receipt-endpoint", uint32(1), now, "") },
	} {
		answer, err := call()
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if verified(answer) || answer == "" {
			t.Errorf("%s: answered %q", name, answer)
		}
	}
	fx := loadFixtures(t)
	if answer, err := g.Call("verify-receipt", now, fx.g5); err != nil || !verified(answer) {
		t.Errorf("the instance stopped verifying after bad input: %q, %v", answer, err)
	}
}

func TestLoweringRefusesWrongArguments(t *testing.T) {
	fx := loadFixtures(t)
	g := freshGuest(t, nil)
	for name, call := range map[string]func() (string, error){
		"u32 where the WIT says u64":  func() (string, error) { return g.Call("verify-receipt", uint32(5), fx.g5) },
		"u64 where the WIT says u32":  func() (string, error) { return g.Call("verify-receipt-endpoint", uint64(1), now, "{}") },
		"int where the WIT says list": func() (string, error) { return g.Call("verify-receipt", now, 42) },
		"a wrong argument count":      func() (string, error) { return g.Call("verify-receipt", now) },
		"an unknown export":           func() (string, error) { return g.Call("verify-everything", now, "") },
	} {
		if _, err := call(); err == nil || isTrap(err) {
			t.Errorf("%s: %v, want a host error and no call", name, err)
		}
	}
	// Nothing was called, so nothing was discarded.
	if answer, err := g.Call("verify-receipt", now, fx.g5); err != nil || !verified(answer) {
		t.Errorf("the instance stopped verifying after refused calls: %q, %v", answer, err)
	}
}

func TestEnvOtherThanZeroOrOneTraps(t *testing.T) {
	fx := loadFixtures(t)
	req := `{"receipt-data":"` + fx.g5 + `"}`
	for _, env := range []uint32{2, 255, 0xFFFFFFFF} {
		g := freshGuest(t, nil)
		if _, err := g.Call("verify-receipt-endpoint", env, now, req); !isTrap(err) {
			t.Errorf("env %d: %v, want a trap", env, err)
		}
	}
}

func TestArgumentRangesOutsideMemoryDoNotBreakOtherInstances(t *testing.T) {
	// What a hand-rolled host could get wrong; the wrapper cannot, since it
	// always allocates the input from cabi_realloc. Called raw, past the
	// wrapper's own lowering. A range that overflows u32 must trap. A range
	// that runs past the end of memory traps on a module that reads all of
	// it, and is a plain answer on one that stops at the first bad byte (the
	// release module does); either way no other instance is affected.
	g := freshGuest(t, nil)
	_, err := g.m.ExportedFunction(verifyIface+"verify-receipt").Call(ctx, now, uint64(g.memorySize())-4, 16)
	t.Logf("a range past the end of memory: trap=%v", err != nil)
	g = freshGuest(t, nil)
	if _, err := g.m.ExportedFunction(verifyIface+"verify-receipt").Call(ctx, now, 0xFFFFFFF0, 0x20); err == nil {
		t.Error("a range that overflows u32 did not trap")
	}
	fx := loadFixtures(t)
	fresh := freshGuest(t, nil)
	if answer, err := fresh.Call("verify-receipt", now, fx.g5); err != nil || !verified(answer) {
		t.Errorf("a fresh instance failed afterwards: %q, %v", answer, err)
	}
}

type countingReader struct {
	calls atomic.Int64
	fail  bool
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.calls.Add(1)
	if r.fail {
		return 0, errors.New("the entropy source failed")
	}
	for i := range p {
		p[i] = byte(i*7 + 1)
	}
	return len(p), nil
}

func TestRandomGetFailureTraps(t *testing.T) {
	// A random-get that cannot answer must stop the call: the guest never
	// runs on bytes the host did not supply.
	fx := loadFixtures(t)
	reader := &countingReader{fail: true}
	saved := randReader
	randReader = reader
	t.Cleanup(func() { randReader = saved })
	g := freshGuest(t, fx.jwsConfig)
	_, err := g.Call("verify-signed-data", now, fx.jws)
	if reader.calls.Load() == 0 {
		t.Skip("this module did not call random-get for the JWS")
	}
	if !isTrap(err) {
		t.Fatalf("random-get failed and the call answered: %v", err)
	}
}

func TestTrapInOneInstanceLeavesAnotherVerifying(t *testing.T) {
	fx := loadFixtures(t)
	req := `{"receipt-data":"` + fx.g5 + `"}`
	a, b := freshGuest(t, nil), freshGuest(t, nil)
	if answer, err := b.Call("verify-receipt", now, fx.g5); err != nil || !verified(answer) {
		t.Fatalf("b before the trap: %q, %v", answer, err)
	}
	if _, err := a.Call("verify-receipt-endpoint", uint32(2), now, req); !isTrap(err) {
		t.Fatalf("a: %v, want a trap", err)
	}
	for i := 0; i < 2; i++ {
		if answer, err := b.Call("verify-receipt", now, fx.g5); err != nil || !verified(answer) {
			t.Fatalf("b after the trap: %q, %v", answer, err)
		}
	}
	if _, err := a.Call("verify-receipt", now, fx.g5); !isTrap(err) {
		t.Fatalf("the trapped instance answered: %v", err)
	}
}

func TestLinearMemoryDoesNotGrowAcrossCalls(t *testing.T) {
	// Post-return frees every result; a missing or doubled free would show
	// as growth over thousands of calls.
	calls := 2000
	switch {
	case raceEnabled:
		calls = 200
	case testing.Short():
		calls = 100
	}
	fx := loadFixtures(t)
	g := freshGuest(t, nil)
	for i := 0; i < 20; i++ {
		g.Call("verify-receipt", now, fx.g5)
	}
	before := g.memorySize()
	start := time.Now()
	for i := 0; i < calls; i++ {
		if _, err := g.Call("verify-receipt", now, fx.g5); err != nil {
			t.Fatal(err)
		}
	}
	if after := g.memorySize(); after != before {
		t.Fatalf("linear memory grew from %d to %d bytes over %d calls", before, after, calls)
	}
	t.Logf("%d bytes before and after %d calls, %.2f ms per call", before, calls, float64(time.Since(start).Microseconds())/float64(calls)/1000)
}

func TestNewPoolRefusesABadRoot(t *testing.T) {
	_, err := newPool(testModule(t), []byte(`{"roots":["AAAA"]}`))
	var refused *InitRefusedError
	if !errors.As(err, &refused) || refused.Message == "" {
		t.Fatalf("a root that is not a certificate: %v, want *InitRefusedError with a message", err)
	}
}

func TestPoolDiscardsATrappedInstanceAndKeepsAnswering(t *testing.T) {
	fx := loadFixtures(t)
	p, err := newPool(testModule(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := p.VerifyReceiptEndpoint(2, now, `{"receipt-data":"`+fx.g5+`"}`); !isTrap(err) {
			t.Fatalf("env 2: %v, want a trap", err)
		}
		if answer, err := p.VerifyReceipt(now, fx.g5); err != nil || !verified(answer) {
			t.Fatalf("after the trap: %q, %v", answer, err)
		}
	}
}

func TestPoolIsSafeForConcurrentUse(t *testing.T) {
	fx := loadFixtures(t)
	p, err := newPool(testModule(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	workers, each := 8, 6
	if raceEnabled || testing.Short() {
		each = 3
	}
	var wg sync.WaitGroup
	failures := make(chan string, workers*each)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				var answer string
				var err error
				if (w+i)%3 == 0 {
					// Traps mixed in: they must not disturb the others.
					_, err = p.VerifyReceiptEndpoint(2, now, "{}")
					if !isTrap(err) {
						failures <- "no trap for env 2"
					}
					continue
				}
				answer, err = p.VerifyReceipt(now, fx.g5)
				if err != nil || !verified(answer) {
					failures <- answer
				}
			}
		}(w)
	}
	wg.Wait()
	close(failures)
	for f := range failures {
		t.Errorf("a concurrent call failed: %s", f)
	}
}

func TestAbandonedPoolReleasesItsInstances(t *testing.T) {
	// wazero keeps every instance it makes; the finalizer on each Guest is
	// what lets a dropped Verifier give its instances back.
	fx := loadFixtures(t)
	before := settle()
	func() {
		p, err := newPool(testModule(t), nil)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.VerifyReceipt(now, fx.g5)
			}()
		}
		wg.Wait()
		if live.Load() <= before {
			t.Fatalf("the pool made no instance")
		}
	}()
	for i := 0; i < 100; i++ {
		collect()
		if live.Load() <= before {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%d instances are still live %d collections after the pool was dropped", live.Load()-before, 100)
}

func TestOversizedInstanceIsNotKept(t *testing.T) {
	fx := loadFixtures(t)
	p, err := newPool(testModule(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	saved := maxPooledMemory
	maxPooledMemory = 1
	t.Cleanup(func() { maxPooledMemory = saved })
	before := live.Load()
	for i := 0; i < 3; i++ {
		if answer, err := p.VerifyReceipt(now, fx.g5); err != nil || !verified(answer) {
			t.Fatalf("%q, %v", answer, err)
		}
	}
	// Each call closed its instance synchronously; only what was pooled
	// before the limit changed can remain.
	if live.Load() > before {
		t.Fatalf("live instances grew from %d to %d", before, live.Load())
	}
}

// --- modules this package must refuse, and the memory limit -----------------

// Each is a few bytes of WebAssembly assembled from the WAT beside it.
var (
	// (module (memory (export "memory") 1)
	//   (func (export "aprv:verifier/verify@0.9.0#init") ...) (func (export "cabi_realloc") ...))
	wrongVersion = mustHex("0061736d01000000010f0260027f7f017f60047f7f7f7f017f03030200010503010001073b03066d656d6f727902001f617072763a76657269666965722f76657269667940302e392e3023696e697400000c636162695f7265616c6c6f6300010a0b02040041000b040041000b")
	// (module (import "wasi_snapshot_preview1" "fd_write" (func ...)) (memory (export "memory") 1))
	extraImport = mustHex("0061736d0100000001090160047f7f7f7f017f02230116776173695f736e617073686f745f70726576696577310866645f777269746500000503010001070a01066d656d6f72790200")
	// (module (memory (export "memory") 1) (func (export "grow") (param i32) (result i32) local.get 0 memory.grow))
	grower = mustHex("0061736d0100000001060160017f017f030201000503010001071102066d656d6f727902000467726f7700000a08010600200040000b")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestABIMismatchIsRefusedAtCreate(t *testing.T) {
	_, err := compile(wrongVersion)
	var abi *ABIError
	if !errors.As(err, &abi) {
		t.Fatalf("a module of another ABI version: %v, want *ABIError", err)
	}
	for _, want := range []string{"aprv:verifier@1.0.0", "aprv:verifier/verify@0.9.0#init", "cabi_realloc"} {
		if !strings.Contains(abi.Detail, want) {
			t.Errorf("the refusal does not name %q: %s", want, abi.Detail)
		}
	}
}

func TestAnyImportBeyondRandomGetIsRefused(t *testing.T) {
	_, err := compile(extraImport)
	var abi *ABIError
	if !errors.As(err, &abi) || !strings.Contains(abi.Detail, "fd_write") {
		t.Fatalf("a module importing fd_write: %v, want *ABIError naming it", err)
	}
	// Second line of defence: the runtime has no other module to resolve it.
	rt, err := newRuntime()
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	compiled, err := rt.CompileModule(ctx, extraImport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("")); err == nil {
		t.Fatal("the runtime resolved a WASI import nobody provided")
	}
}

func TestMemoryLimit(t *testing.T) {
	// A hostile module growing memory: the limit is 256 MiB, and a grow
	// past it answers -1 instead of taking the machine's memory.
	rt, err := newRuntime()
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	compiled, err := rt.CompileModule(ctx, grower)
	if err != nil {
		t.Fatal(err)
	}
	m, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		t.Fatal(err)
	}
	grow := func(pages uint64) int32 {
		res, err := m.ExportedFunction("grow").Call(ctx, pages)
		if err != nil {
			t.Fatal(err)
		}
		return int32(uint32(res[0]))
	}
	if got := grow(memoryLimitPages - 1); got != 1 {
		t.Errorf("growing to the limit answered %d, want the old size of 1 page", got)
	}
	if got := grow(1); got != -1 {
		t.Errorf("growing past the limit answered %d, want -1", got)
	}
	if got := grow(65535); got != -1 {
		t.Errorf("a 4 GiB grow answered %d, want -1", got)
	}
}
