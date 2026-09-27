package applereceipt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

// decodeBase64 decodes receipt-data and x5c entries by the one rule both
// follow: non-empty standard base64 ([A-Za-z0-9+/]) with exactly the
// canonical '=' padding for its length, and nothing else. It is the rule
// Apple's verifyReceipt applies to receipt-data (measured 2026-09-23, see
// docs/evidence/2026-09-23-verifyreceipt-base64.md) and the one RFC 7515
// §4.1.6 gives an x5c entry. Unused low bits in the last data character
// are accepted, as Apple accepts them.
//
// base64.StdEncoding enforces the alphabet, the padding and the length,
// ignores the trailing bits, and does two things the rule does not: it
// skips CR and LF anywhere, and it decodes "" to nothing. isCanonicalBase64
// refuses both first. StdEncoding.Strict() is not used because it refuses
// the trailing bits Apple accepts.
//
// A rejected input decodes to nil, not an error, so every caller stays a
// single assignment: nil is empty is "not a certificate" / "not a CMS
// blob", the same downstream reasons a garbage decode already produced.
// Callers cap the string before calling (MaxReceiptBytes, MaxJWSBytes),
// so the decode is bounded by the cap.
func decodeBase64(text string) []byte {
	if !isCanonicalBase64(text) {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil
	}
	return decoded
}

// isCanonicalBase64 reports whether text is non-empty, a multiple of four
// long, and made of the standard alphabet followed by at most two '='.
// With the length check that leaves exactly the canonical padding.
func isCanonicalBase64(text string) bool {
	if len(text) == 0 || len(text)%4 != 0 {
		return false
	}
	end := len(text)
	for pad := 0; pad < 2 && text[end-1] == '='; pad++ {
		end--
	}
	for i := 0; i < end; i++ {
		c := text[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/') {
			return false
		}
	}
	return true
}

// decodeBase64URLStrict decodes one compact-JWS segment.
//
// Unlike decodeBase64 this one also FAILS on anything that is not canonical
// base64url: a character outside the alphabet, "=" padding (RFC 7515 §2
// requires the padding to be omitted), a wrong length, or non-zero bits
// in the final quantum. base64.RawURLEncoding.Strict() rejects all four
// on its own — "raw" means no padding accepted, and .Strict() adds the
// alphabet and trailing-bits checks — so this is a direct call, nothing
// is stripped first.
//
// Every port decodes segments this strictly, and the
// transaction/reject-signature-segment-* vectors in fixtures/cases.json
// hold them to it: junk appended to the signature segment, "=" padding
// on it, or flipped unused bits in its last character is
// INVALID_JWS_FORMAT. Strictness here can only turn an accept into a
// reject, never the reverse, and it means every byte of a JWS this port
// accepts is a byte the signature covers.
func decodeBase64URLStrict(segment string) ([]byte, error) {
	return base64.RawURLEncoding.Strict().DecodeString(segment)
}

// jsonBoundsExceeded reports whether b holds more than maxDepth arrays and
// objects open at once, a JSON object member NAME longer than
// maxNameLength characters, or a JSON number literal with more than
// maxNumberDigits digits: the three JSON bounds the design's Bounds
// table pins on the same shape of input (docs/design/0.7-api.md). It
// runs before the JSON is parsed, so a hostile document is refused in one
// linear pass rather than handed to encoding/json; a bound of 0 disables
// that one check. A request body's password value or a payload's
// productId, however long, is not a member name and is never bounded by
// maxNameLength.
//
// It does not validate: a closing bracket with no opener only lowers the
// depth count, and such input is not JSON, so the parse that follows
// rejects it. Telling a member name from a string VALUE needs only the
// shallow structural state a streaming scanner already tracks: whether
// the innermost open container is an object or an array, and whether the
// next string is in "key position" (right after `{` or, inside an
// object, right after `,`), never whether the document is otherwise
// well-formed, which the parse that follows still decides.
func jsonBoundsExceeded(b []byte, maxDepth, maxNameLength, maxNumberDigits int) bool {
	depth := 0
	inString := false
	escaped := false
	nameLength := 0
	isKeyString := false
	expectKey := false
	// isObject[i] is whether the container opened at nesting level i+1 is
	// an object (true) or an array (false); only its top matters, to
	// decide whether a "," reopens key position.
	var isObject []bool
	inNumber := false
	numberDigits := 0

	for _, c := range b {
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
				if isKeyString && maxNameLength > 0 && nameLength > maxNameLength {
					return true
				}
			default:
				nameLength++
			}
			continue
		}
		if inNumber {
			switch {
			case c >= '0' && c <= '9':
				numberDigits++
				if maxNumberDigits > 0 && numberDigits > maxNumberDigits {
					return true
				}
				continue
			case c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E':
				continue
			default:
				inNumber = false
			}
		}
		switch c {
		case '"':
			inString = true
			nameLength = 0
			isKeyString = expectKey
			expectKey = false
		case '{':
			depth++
			if depth > maxDepth {
				return true
			}
			isObject = append(isObject, true)
			expectKey = true
		case '[':
			depth++
			if depth > maxDepth {
				return true
			}
			isObject = append(isObject, false)
			expectKey = false
		case '}', ']':
			depth--
			if len(isObject) > 0 {
				isObject = isObject[:len(isObject)-1]
			}
			expectKey = false
		case ',':
			if len(isObject) > 0 && isObject[len(isObject)-1] {
				expectKey = true
			}
		case ':':
			expectKey = false
		case '-':
			inNumber = true
			numberDigits = 0
		default:
			if c >= '0' && c <= '9' {
				inNumber = true
				numberDigits = 1
				if maxNumberDigits > 0 && numberDigits > maxNumberDigits {
					return true
				}
			}
		}
	}
	return false
}

// decodeJSONObject decodes exactly one JSON object from b, with only
// whitespace tolerated after it: a JWS header or payload with trailing
// content is not the object that was covered by the signature.
//
// Numbers stay as json.Number rather than float64, so a claim above 2^53
// survives round-tripping unchanged; integralMillis reads the ones this
// library uses. A duplicate member keeps the last one, as decoding into a
// Go map already does.
func decodeJSONObject(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing content after JSON value")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("not a JSON object")
	}
	return object, nil
}
