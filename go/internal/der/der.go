// Package der is a bounded BER/DER reader — just enough ASN.1 to walk
// CMS/PKCS#7 SignedData and Apple receipt payloads.
//
// It is hand-rolled on purpose. encoding/asn1 is DER-only and refuses the
// indefinite lengths that genuine Apple and Xcode receipts use (10 of the
// 11 receipt fixtures in this repository are indefinite-length BER), and
// golang.org/x/crypto/cryptobyte rejects the 0x80 length octet for the
// same reason. PLAN.md D8 already settled the same question for the Node
// port: a small audited reader beats a large dependency in a security
// library.
//
// Every input this package sees is attacker-controlled. It therefore:
//
//   - bounds nesting depth (recursion is the obvious DoS),
//   - bounds the total node count (many tiny TLVs are the other one),
//   - rejects multi-byte tags and long-form lengths above four octets,
//   - checks every computed offset against the input length and against
//     integer overflow before slicing,
//   - rejects trailing bytes after the outermost value, and
//   - never panics: Parse returns an error for every malformed input.
package der

import (
	"errors"
	"fmt"
)

// MaxDepth is the deepest nesting Parse will follow. Real receipts nest
// about six levels; 32 leaves room to spare while making a nesting bomb a
// rejection rather than a stack overflow.
const MaxDepth = 32

// maxNodes bounds the total TLVs one Parse may produce.
//
// Every node costs at least two input bytes but around a hundred bytes of
// parsed tree, so a megabyte of two-byte TLVs is a fifty-megabyte
// allocation. Measured, the genuine 79 KB legacy receipt with 187 in-app
// purchases parses to 271 nodes and the sandbox one to 277, so this sits
// roughly 370x above anything real while capping the amplification at a
// constant.
const maxNodes = 100_000

// ErrTrailingBytes is returned when a complete value is followed by more
// bytes. Rejecting the remainder rather than ignoring it is what stops a
// verified CMS blob from carrying an unverified tail (PLAN.md §2.3).
var ErrTrailingBytes = errors.New("trailing bytes after ASN.1 value")

// Common identifier octets.
const (
	TagInteger                byte = 0x02
	TagBitString              byte = 0x03
	TagOctetString            byte = 0x04
	TagOID                    byte = 0x06
	TagUTF8String             byte = 0x0c
	TagIA5String              byte = 0x16
	TagSequence               byte = 0x30
	TagSet                    byte = 0x31
	TagOctetStringConstructed byte = 0x24
	TagContext0               byte = 0xa0
	TagContext1               byte = 0xa1
	TagContext2               byte = 0xa2
	TagContext3               byte = 0xa3
)

// Node is one parsed TLV.
//
// Raw and Contents are always sub-slices of the buffer handed to Parse,
// indefinite-length nodes included: the children of an indefinite-length
// value are contiguous between its length octet and its end-of-contents
// marker, so its contents need no concatenation. Callers that hand a byte
// field to their own caller must copy it — see the aliasing rule in the
// root package.
type Node struct {
	Tag         byte
	Constructed bool
	Raw         []byte
	Contents    []byte
	Children    []*Node
}

type parser struct {
	buf   []byte
	nodes int
}

// Parse reads exactly one ASN.1 value from b and rejects anything left
// over.
func Parse(b []byte) (*Node, error) {
	p := &parser{buf: b}
	node, end, err := p.readNode(0, 0)
	if err != nil {
		return nil, err
	}
	if end != len(b) {
		return nil, fmt.Errorf("%w (%d)", ErrTrailingBytes, len(b)-end)
	}
	return node, nil
}

func (p *parser) readNode(off, depth int) (*Node, int, error) {
	if depth > MaxDepth {
		return nil, 0, fmt.Errorf("maximum ASN.1 nesting depth (%d) exceeded", MaxDepth)
	}
	p.nodes++
	if p.nodes > maxNodes {
		return nil, 0, fmt.Errorf("ASN.1 value has more than %d nodes", maxNodes)
	}
	if off < 0 || off+2 > len(p.buf) {
		return nil, 0, errors.New("truncated ASN.1 value")
	}
	tag := p.buf[off]
	if tag&0x1f == 0x1f {
		return nil, 0, errors.New("multi-byte ASN.1 tags are not supported")
	}
	constructed := tag&0x20 != 0
	pos := off + 1
	lenByte := p.buf[pos]
	pos++

	indefinite := false
	length := 0
	switch {
	case lenByte < 0x80:
		length = int(lenByte)
	case lenByte == 0x80:
		if !constructed {
			return nil, 0, errors.New("indefinite length on a primitive value")
		}
		indefinite = true
	default:
		n := int(lenByte & 0x7f)
		// Four octets caps a declared length at 2^32-1, which is far above
		// any receipt and keeps the accumulation below int64 overflow. The
		// bounds check happens before any length octet is read.
		if n > 4 || pos+n > len(p.buf) {
			return nil, 0, errors.New("unsupported ASN.1 length")
		}
		for i := 0; i < n; i++ {
			length = length<<8 | int(p.buf[pos+i])
		}
		pos += n
	}

	if !indefinite {
		end := pos + length
		// end < pos catches the overflow case on any word size; end >
		// len(buf) catches a length that claims more than we have.
		if end < pos || end > len(p.buf) {
			return nil, 0, errors.New("ASN.1 length exceeds input")
		}
		node := &Node{
			Tag:         tag,
			Constructed: constructed,
			Raw:         p.buf[off:end],
			Contents:    p.buf[pos:end],
		}
		if constructed {
			children, err := p.readChildren(pos, end, depth+1)
			if err != nil {
				return nil, 0, err
			}
			node.Children = children
		}
		return node, end, nil
	}

	// Indefinite (BER) length: children until an end-of-contents marker.
	//
	// The children run contiguously from here to the marker, so the
	// contents are the slice between the two — NOT a concatenation of the
	// children's Raw bytes. Building that concatenation would copy the
	// whole subtree once per level of nesting, which is O(MaxDepth x
	// input) and is capped by neither maxNodes (a node count) nor
	// MaxDepth (a multiplier on the copy, not a bound on it): 30 levels
	// of indefinite wrapping cost four bytes of input each and multiplied
	// the parse by 30.
	contentStart := pos
	var children []*Node
	for {
		if pos+2 > len(p.buf) {
			return nil, 0, errors.New("unterminated indefinite-length value")
		}
		if p.buf[pos] == 0x00 && p.buf[pos+1] == 0x00 {
			pos += 2
			break
		}
		child, next, err := p.readNode(pos, depth+1)
		if err != nil {
			return nil, 0, err
		}
		children = append(children, child)
		pos = next
	}
	return &Node{
		Tag:         tag,
		Constructed: true,
		Raw:         p.buf[off:pos],
		Contents:    p.buf[contentStart : pos-2],
		Children:    children,
	}, pos, nil
}

func (p *parser) readChildren(start, end, depth int) ([]*Node, error) {
	var children []*Node
	pos := start
	for pos < end {
		child, next, err := p.readNode(pos, depth)
		if err != nil {
			return nil, err
		}
		if next > end {
			return nil, errors.New("ASN.1 child overruns its parent")
		}
		children = append(children, child)
		pos = next
	}
	return children, nil
}

// IsOctetString reports whether n is an OCTET STRING in either the
// primitive or the BER constructed form.
func IsOctetString(n *Node) bool {
	return n != nil && (n.Tag == TagOctetString || n.Tag == TagOctetStringConstructed)
}

// OctetValue is the value of an OCTET STRING, joining the chunks of a BER
// constructed one. Depth is already bounded by Parse.
//
// The flattening is a single pass into one buffer sized in advance. The
// obvious recursive spelling — concatenate each child's OctetValue —
// re-copies the whole subtree at every level on the way up, so a
// 28-deep constructed OCTET STRING costs 28x its own size to read. That
// is attacker-controlled nesting and it is not bounded by the node cap.
func OctetValue(n *Node) []byte {
	if n == nil {
		return nil
	}
	if !n.Constructed {
		return n.Contents
	}
	out := make([]byte, 0, octetValueLen(n))
	return appendOctetValue(out, n)
}

// octetValueLen is the exact size of OctetValue's answer, so the buffer
// is allocated once and never grown.
func octetValueLen(n *Node) int {
	if !n.Constructed {
		return len(n.Contents)
	}
	total := 0
	for _, child := range n.Children {
		total += octetValueLen(child)
	}
	return total
}

func appendOctetValue(dst []byte, n *Node) []byte {
	if !n.Constructed {
		return append(dst, n.Contents...)
	}
	for _, child := range n.Children {
		dst = appendOctetValue(dst, child)
	}
	return dst
}

// Child returns the i-th child, or nil when there is none. Returning nil
// rather than panicking is what lets the CMS walk read a structure of an
// unexpected shape without an index check at every step.
func Child(n *Node, i int) *Node {
	if n == nil || i < 0 || i >= len(n.Children) {
		return nil
	}
	return n.Children[i]
}
