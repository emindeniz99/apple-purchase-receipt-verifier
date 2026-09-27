package applereceipt

import (
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
)

// jsonWriter builds a JSON object by hand.
//
// ReceiptPayload.ToJSON uses it for the canonical form every port
// produces byte for byte (docs/design/0.7-api.md, Canonical form):
// Go's encoding/json is not used for it, because its HTML-safe escaping
// (which turns "<", ">", "&", U+2028 and U+2029 into \u escapes) and its
// alphabetic key sorting both violate the canonical form, which orders
// keys by the design's table and escapes exactly as ECMAScript
// JSON.stringify does. VerifyReceiptEndpoint uses the same writer for
// Apple's response body, whose key order is not part of any contract but
// is deterministic for a caller comparing bytes across calls.
type jsonWriter struct {
	out   *strings.Builder
	first bool
}

func newJSONWriter(out *strings.Builder) *jsonWriter {
	out.WriteByte('{')
	return &jsonWriter{out: out, first: true}
}

func (w *jsonWriter) close() { w.out.WriteByte('}') }

func (w *jsonWriter) key(key string) {
	if !w.first {
		w.out.WriteByte(',')
	}
	w.first = false
	quoteJSONInto(w.out, key)
	w.out.WriteByte(':')
}

// str writes a string value, or null when value is nil.
func (w *jsonWriter) str(key string, value *string) {
	w.key(key)
	if value == nil {
		w.out.WriteString("null")
		return
	}
	quoteJSONInto(w.out, *value)
}

// num writes an int64 value as a JSON number, or null when value is nil.
func (w *jsonWriter) num(key string, value *int64) {
	w.key(key)
	if value == nil {
		w.out.WriteString("null")
		return
	}
	w.out.WriteString(strconv.FormatInt(*value, 10))
}

// id writes a 64-bit id as a JSON string, so a JavaScript reader does not
// round it, or null when value is nil.
func (w *jsonWriter) id(key string, value *int64) {
	w.key(key)
	if value == nil {
		w.out.WriteString("null")
		return
	}
	quoteJSONInto(w.out, strconv.FormatInt(*value, 10))
}

// boolean writes a bool value, or null when value is nil.
func (w *jsonWriter) boolean(key string, value *bool) {
	w.key(key)
	switch {
	case value == nil:
		w.out.WriteString("null")
	case *value:
		w.out.WriteString("true")
	default:
		w.out.WriteString("false")
	}
}

// bytesValue writes value as standard padded base64, or null when value
// is nil.
func (w *jsonWriter) bytesValue(key string, value []byte) {
	w.key(key)
	if value == nil {
		w.out.WriteString("null")
		return
	}
	quoteJSONInto(w.out, base64.StdEncoding.EncodeToString(value))
}

// array opens a JSON array under key; the caller writes its elements
// (each a raw JSON value, comma-separated by the caller) and closes it.
func (w *jsonWriter) arrayStart(key string) {
	w.key(key)
	w.out.WriteByte('[')
}

func (w *jsonWriter) arrayEnd() { w.out.WriteByte(']') }

// attributes writes UnknownAttributes: an object whose keys are the
// attribute types in ascending numeric order (as decimal strings) and
// whose values are arrays of standard base64 strings, in receipt order.
func (w *jsonWriter) attributes(key string, attrs UnknownAttributes) {
	w.key(key)
	w.out.WriteByte('{')
	keys := make([]int64, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for i, k := range keys {
		if i > 0 {
			w.out.WriteByte(',')
		}
		quoteJSONInto(w.out, strconv.FormatInt(k, 10))
		w.out.WriteByte(':')
		w.out.WriteByte('[')
		for j, value := range attrs[k] {
			if j > 0 {
				w.out.WriteByte(',')
			}
			quoteJSONInto(w.out, base64.StdEncoding.EncodeToString(value))
		}
		w.out.WriteByte(']')
	}
	w.out.WriteByte('}')
}

const hexDigits = "0123456789abcdef"

// quoteJSONInto writes value as a JSON string exactly as ECMAScript
// JSON.stringify escapes it: \" \\ and the short escapes \b \f \n \r \t,
// every other character from U+0000 to U+001F as \u00xx in lowercase hex,
// and nothing else: "/" is not escaped, and non-ASCII characters, U+2028
// and U+2029 included, are written raw.
func quoteJSONInto(out *strings.Builder, value string) {
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte(hexDigits[(r>>4)&0xf])
				out.WriteByte(hexDigits[r&0xf])
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}
