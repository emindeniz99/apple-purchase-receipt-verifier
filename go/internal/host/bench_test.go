package host

import "testing"

// Steady-state cost of one call through the pool, sequential and parallel,
// with the answer left as text: what the module and the ABI cost, without
// the wrapper's JSON reading. NewPool's cost is the first-call compile.
//
//	go test -run '^$' -bench . -benchtime 3s ./internal/host

func benchPool(b *testing.B, config []byte) *Pool {
	b.Helper()
	p, err := newPool(testModule(b), config)
	if err != nil {
		b.Fatal(err)
	}
	return p
}

func BenchmarkReceiptG5(b *testing.B) {
	fx := loadFixtures(b)
	p := benchPool(b, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.VerifyReceipt(now, fx.g5); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignedData(b *testing.B) {
	fx := loadFixtures(b)
	p := benchPool(b, fx.jwsConfig)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.VerifySignedData(now, fx.jws); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReceiptG5Parallel(b *testing.B) {
	fx := loadFixtures(b)
	p := benchPool(b, nil)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := p.VerifyReceipt(now, fx.g5); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkSignedDataParallel(b *testing.B) {
	fx := loadFixtures(b)
	p := benchPool(b, fx.jwsConfig)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := p.VerifySignedData(now, fx.jws); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkNewInstance(b *testing.B) {
	testModule(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g, err := testModule(b).newGuest(nil)
		if err != nil {
			b.Fatal(err)
		}
		g.close()
	}
}
