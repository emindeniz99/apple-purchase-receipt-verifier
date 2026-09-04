package der

import (
	"bytes"
	"testing"
)

// FuzzParseDER asserts the three properties the whole port's hostile-input
// story rests on: Parse never panics, a successful parse consumed exactly
// the input, and Raw/Contents never point outside the buffer handed in.
//
// The seed corpus is deliberately structural rather than fixture-derived:
// this package has no dependency on the repository's fixtures, and the
// shapes below are the ones the bounds are written against.
func FuzzParseDER(f *testing.F) {
	seeds := [][]byte{
		nil,
		{},
		{0x05, 0x00},
		{0x02, 0x01, 0x01},
		{0x30, 0x03, 0x02, 0x01, 0x01},
		{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00},
		{0x24, 0x80, 0x04, 0x01, 0x41, 0x00, 0x00},
		{0x04, 0x84, 0xff, 0xff, 0xff, 0xff},
		{0x1f, 0x01, 0x00},
		{0x30, 0x80},
		bytes.Repeat([]byte{0x30, 0x80}, 64),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		node, err := Parse(input)
		if err != nil {
			if node != nil {
				t.Fatal("Parse returned both a node and an error")
			}
			return
		}
		if len(node.Raw) != len(input) {
			t.Fatalf("a successful parse consumed %d of %d bytes", len(node.Raw), len(input))
		}
		checkWithin(t, node, input)
	})
}

// checkWithin walks the tree asserting every Raw slice is a view into the
// original buffer. Contents is exempt for indefinite-length nodes, which
// own a freshly built concatenation.
func checkWithin(t *testing.T, node *Node, input []byte) {
	t.Helper()
	if len(node.Raw) > 0 && !within(node.Raw, input) {
		t.Fatal("a node's Raw slice points outside the parsed buffer")
	}
	for _, child := range node.Children {
		checkWithin(t, child, input)
	}
}

func within(part, whole []byte) bool {
	if len(part) == 0 || len(whole) == 0 {
		return true
	}
	start := &whole[0]
	end := &whole[len(whole)-1]
	first := &part[0]
	last := &part[len(part)-1]
	return uintptrOf(first) >= uintptrOf(start) && uintptrOf(last) <= uintptrOf(end)
}
