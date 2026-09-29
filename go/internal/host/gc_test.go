package host

import (
	"runtime"
	"time"
)

// collect runs the collector twice: a sync.Pool gives up an item after two
// cycles, and a finalizer runs after the cycle that finds its object.
func collect() {
	runtime.GC()
	runtime.GC()
}

// settle collects until the live-instance count stops changing, so a
// measurement starts without other tests' garbage in it.
func settle() int64 {
	stable := 0
	prev := live.Load()
	for i := 0; i < 100 && stable < 3; i++ {
		collect()
		time.Sleep(20 * time.Millisecond)
		if now := live.Load(); now == prev {
			stable++
		} else {
			prev, stable = now, 0
		}
	}
	return prev
}
