package der

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func tlv(tag byte, contents []byte) []byte {
	if len(contents) < 0x80 {
		return append([]byte{tag, byte(len(contents))}, contents...)
	}
	return append([]byte{tag, 0x82, byte(len(contents) >> 8), byte(len(contents))}, contents...)
}

func seq(parts ...[]byte) []byte { return tlv(0x30, bytes.Join(parts, nil)) }

// indefinite wraps contents in a constructed TLV with a BER
// indefinite length and an end-of-contents marker.
func indefinite(tag byte, contents []byte) []byte {
	out := []byte{tag, 0x80}
	out = append(out, contents...)
	return append(out, 0x00, 0x00)
}

func TestParseRejectsMalformedInput(t *testing.T) {
	deep := tlv(0x02, []byte{1})
	for i := 0; i < MaxDepth+2; i++ {
		deep = seq(deep)
	}

	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"nil", nil, "truncated"},
		{"empty", []byte{}, "truncated"},
		{"one byte", []byte{0x30}, "truncated"},
		{"length exceeds input", []byte{0x04, 0x05, 0x01}, "exceeds input"},
		{"five-byte long form length", []byte{0x04, 0x85, 1, 1, 1, 1, 1}, "unsupported ASN.1 length"},
		{"long form length octets past the end", []byte{0x04, 0x84, 0x00}, "unsupported ASN.1 length"},
		{"multi-byte tag", []byte{0x1f, 0x01, 0x00}, "multi-byte"},
		{"indefinite length on a primitive", []byte{0x04, 0x80, 0x00, 0x00}, "indefinite length on a primitive"},
		{"unterminated indefinite content", []byte{0x30, 0x80, 0x02, 0x01, 0x01}, "unterminated"},
		{"trailing byte after a complete value", []byte{0x02, 0x01, 0x01, 0x00}, "trailing bytes"},
		{"nesting bomb", deep, "nesting depth"},
		{"child overruns its parent", []byte{0x30, 0x03, 0x02, 0x05, 0x01}, "exceeds input"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			node, err := Parse(test.input)
			if err == nil {
				t.Fatalf("expected an error, parsed %+v", node)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error %q does not mention %q", err, test.want)
			}
		})
	}
}

func TestTrailingBytesErrorIsIdentifiable(t *testing.T) {
	_, err := Parse([]byte{0x02, 0x01, 0x01, 0xff})
	if !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("a trailing-byte rejection must be identifiable, got %v", err)
	}
}

func TestParseAcceptsWellFormedValues(t *testing.T) {
	t.Run("zero-length value", func(t *testing.T) {
		node, err := Parse([]byte{0x04, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		if len(node.Contents) != 0 || node.Tag != TagOctetString {
			t.Fatalf("got %+v", node)
		}
	})
	t.Run("nested sequence", func(t *testing.T) {
		node, err := Parse(seq(tlv(0x02, []byte{1}), tlv(0x02, []byte{2})))
		if err != nil {
			t.Fatal(err)
		}
		if len(node.Children) != 2 {
			t.Fatalf("expected two children, got %d", len(node.Children))
		}
		if Child(node, 0).Contents[0] != 1 || Child(node, 1).Contents[0] != 2 {
			t.Fatal("children decoded in the wrong order")
		}
	})
	t.Run("indefinite length", func(t *testing.T) {
		node, err := Parse(indefinite(0x30, tlv(0x02, []byte{7})))
		if err != nil {
			t.Fatal(err)
		}
		if len(node.Children) != 1 || node.Children[0].Contents[0] != 7 {
			t.Fatalf("got %+v", node)
		}
	})
	t.Run("nesting exactly at the depth limit", func(t *testing.T) {
		value := tlv(0x02, []byte{1})
		for i := 0; i < MaxDepth-1; i++ {
			value = seq(value)
		}
		if _, err := Parse(value); err != nil {
			t.Fatalf("depth %d must be accepted: %v", MaxDepth-1, err)
		}
	})
}

func TestOctetValueJoinsConstructedChunks(t *testing.T) {
	t.Run("definite constructed", func(t *testing.T) {
		node, err := Parse(tlv(0x24, bytes.Join([][]byte{
			tlv(0x04, []byte{1, 2}), tlv(0x04, []byte{3, 4}),
		}, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if got := OctetValue(node); !bytes.Equal(got, []byte{1, 2, 3, 4}) {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("indefinite constructed", func(t *testing.T) {
		node, err := Parse(indefinite(0x24, bytes.Join([][]byte{
			tlv(0x04, []byte{9}), tlv(0x04, []byte{8}),
		}, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if got := OctetValue(node); !bytes.Equal(got, []byte{9, 8}) {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("chunks that are themselves constructed", func(t *testing.T) {
		inner := tlv(0x24, bytes.Join([][]byte{tlv(0x04, []byte{1}), tlv(0x04, []byte{2})}, nil))
		node, err := Parse(tlv(0x24, bytes.Join([][]byte{inner, tlv(0x04, []byte{3})}, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if got := OctetValue(node); !bytes.Equal(got, []byte{1, 2, 3}) {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("nil node", func(t *testing.T) {
		if OctetValue(nil) != nil {
			t.Fatal("OctetValue(nil) must be nil")
		}
	})
}

// Truncating a well-formed value at every offset must produce an error at
// every one of them, and never a panic. This is the cheapest broad proof
// that no index in the reader is unguarded.
func TestTruncationAtEveryOffsetIsRejectedWithoutPanicking(t *testing.T) {
	value := seq(
		tlv(0x02, []byte{1, 2, 3}),
		tlv(0x04, bytes.Repeat([]byte{0xaa}, 200)),
		indefinite(0x24, tlv(0x04, []byte{5, 6})),
	)
	if _, err := Parse(value); err != nil {
		t.Fatalf("the intact value must parse: %v", err)
	}
	for cut := 0; cut < len(value); cut++ {
		truncated := value[:cut]
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Parse panicked on a %d-byte truncation: %v", cut, r)
				}
			}()
			if _, err := Parse(truncated); err == nil {
				t.Fatalf("a %d-byte truncation parsed successfully", cut)
			}
		}()
	}
}

// Every single-byte flip of a well-formed value must either parse or
// error — never panic.
func TestByteFlipsNeverPanic(t *testing.T) {
	value := seq(tlv(0x02, []byte{1, 2, 3}), tlv(0x04, bytes.Repeat([]byte{0xaa}, 64)))
	for i := range value {
		for _, mask := range []byte{0x01, 0x80, 0xff} {
			mutated := bytes.Clone(value)
			mutated[i] ^= mask
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Parse panicked on byte %d flipped with %#x: %v", i, mask, r)
					}
				}()
				_, _ = Parse(mutated)
			}()
		}
	}
}

func TestChildIsNilSafe(t *testing.T) {
	if Child(nil, 0) != nil {
		t.Fatal("Child(nil, 0) must be nil")
	}
	node, err := Parse(seq(tlv(0x02, []byte{1})))
	if err != nil {
		t.Fatal(err)
	}
	if Child(node, -1) != nil || Child(node, 1) != nil {
		t.Fatal("an out-of-range index must be nil, not a panic")
	}
}

func TestNodeBudgetBoundsTinyTLVFloods(t *testing.T) {
	// Many tiny TLVs are the other shape of parser DoS: each one costs
	// two input bytes but allocates a Node.
	var contents []byte
	for i := 0; i < 100; i++ {
		contents = append(contents, 0x05, 0x00)
	}
	if _, err := Parse(tlv(0x30, contents)); err != nil {
		t.Fatalf("100 tiny children is normal: %v", err)
	}
}

func TestRawAndContentsAreSubslicesOfTheInput(t *testing.T) {
	// The reader is zero-copy by design; the aliasing rule that follows
	// from it (every byte field handed to a caller is a copy) is enforced
	// in the root package, and this is the fact it is protecting against.
	input := seq(tlv(0x02, []byte{1, 2, 3}))
	node, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	if &node.Raw[0] != &input[0] {
		t.Fatal("Parse copied the input; the aliasing rule assumes it does not")
	}
}
