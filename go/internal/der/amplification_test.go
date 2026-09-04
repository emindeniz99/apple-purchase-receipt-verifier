package der

import (
	"runtime"
	"testing"
)

// wrapIndefinite puts `levels` indefinite-length constructed OCTET STRING
// headers around payload. Each level adds exactly four bytes of input.
func wrapIndefinite(payload []byte, levels int) []byte {
	out := payload
	for i := 0; i < levels; i++ {
		wrapped := make([]byte, 0, len(out)+4)
		wrapped = append(wrapped, TagOctetStringConstructed, 0x80)
		wrapped = append(wrapped, out...)
		wrapped = append(wrapped, 0x00, 0x00)
		out = wrapped
	}
	return out
}

func primitiveOctetString(n int) []byte {
	head := []byte{TagOctetString, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	return append(head, make([]byte, n)...)
}

// TestIndefiniteContentsAliasTheInput is the structural half of the
// bound below: the children of an indefinite-length value are contiguous
// in the input, so its Contents are a sub-slice like every other node's,
// not a fresh concatenation. A copy here is quadratic in nesting depth,
// which is exactly the amplification the byte budget forbids.
func TestIndefiniteContentsAliasTheInput(t *testing.T) {
	input := wrapIndefinite(primitiveOctetString(8), 1)
	node, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(node.Contents) == 0 {
		t.Fatal("indefinite node has no contents")
	}
	if uintptrOf(&node.Contents[0]) != uintptrOf(&input[2]) {
		t.Fatal("indefinite-length Contents were copied instead of sliced; " +
			"the copy is O(depth x input) and is not covered by maxNodes")
	}
}

// TestParseAllocationIsLinearInInput pins the DoS property the package
// documents. maxNodes caps the node COUNT and MaxDepth caps recursion,
// but neither caps the number of BYTES a parse materializes: with a
// per-level concatenation, nesting an indefinite-length value 30 deep
// multiplies the cost by 30 while adding 120 bytes of input.
//
// The assertion is on the ratio, not on a wall-clock number, so it is
// stable across machines.
func TestParseAllocationIsLinearInInput(t *testing.T) {
	const payload = 60_000
	for _, levels := range []int{1, 10, 25, 30} {
		blob := wrapIndefinite(primitiveOctetString(payload), levels)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		node, err := Parse(blob)
		if err != nil {
			t.Fatalf("levels=%d: %v", levels, err)
		}
		value := OctetValue(node)
		runtime.ReadMemStats(&after)
		if len(value) != payload {
			t.Fatalf("levels=%d: OctetValue returned %d bytes, want %d", levels, len(value), payload)
		}
		allocated := after.TotalAlloc - before.TotalAlloc
		ratio := float64(allocated) / float64(len(blob))
		t.Logf("levels=%2d input=%d allocated=%d ratio=%.1fx", levels, len(blob), allocated, ratio)
		// One OctetValue copy of the whole payload, plus tree overhead,
		// is under 4x. A per-level copy reaches depth-times that.
		if ratio > 4 {
			t.Errorf("levels=%d: parsing allocated %.1fx the input (%d bytes from %d); "+
				"nesting must not multiply the cost", levels, ratio, allocated, len(blob))
		}
	}
}

// TestOctetValueIsSinglePass is the other half: a constructed OCTET
// STRING tree must be flattened in one walk, not re-concatenated at
// every level on the way up.
func TestOctetValueIsSinglePass(t *testing.T) {
	const payload = 200_000
	blob := wrapIndefinite(primitiveOctetString(payload), 28)
	node, err := Parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	value := OctetValue(node)
	runtime.ReadMemStats(&after)
	if len(value) != payload {
		t.Fatalf("OctetValue returned %d bytes, want %d", len(value), payload)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("28 levels, %d byte payload: OctetValue allocated %d bytes", payload, allocated)
	// The answer itself is `payload` bytes; a single pass allocates it
	// once. Re-concatenating per level allocates ~28x that.
	if allocated > 3*payload {
		t.Errorf("OctetValue allocated %d bytes to produce %d; it is re-copying per level",
			allocated, payload)
	}
}
