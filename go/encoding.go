package applereceipt

import (
	"encoding/base64"
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
// It is deliberately stricter than Java's MIME decoder and Node's
// Buffer.from(s, "base64url"), both of which skip characters they do not
// recognise and tolerate padding. The difference is observable in
// exactly one place: appending junk to a compact JWS, padding a segment,
// or flipping the unused bits of a segment's last character, leaves
// those ports' answer unchanged, and makes this one answer
// INVALID_JWS_FORMAT. Strictness here can only turn an accept into a
// reject, never the reverse, and it means every byte of a JWS this port
// accepts is a byte the signature covers.
func decodeBase64URLStrict(segment string) ([]byte, error) {
	return base64.RawURLEncoding.Strict().DecodeString(segment)
}

// jsonNestingExceeds reports whether b holds more than limit arrays and
// objects open at once, counting brackets outside string literals. It runs
// before the JSON is parsed, so a hostile document nested thousands deep
// is refused in one linear pass rather than handed to encoding/json.
//
// It does not validate: a closer with no opener only lowers the count,
// and such input is not JSON, so the parse that follows rejects it.
func jsonNestingExceeds(b []byte, limit int) bool {
	depth := 0
	inString := false
	escaped := false
	for _, c := range b {
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '[', '{':
			depth++
			if depth > limit {
				return true
			}
		case ']', '}':
			depth--
		}
	}
	return false
}
