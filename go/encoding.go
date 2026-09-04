package applereceipt

import (
	"encoding/base64"
)

// Base64 decoding for receipt-data and x5c entries, matching what
// Foundation's base64EncodedString(options:) can emit and rejecting
// everything else — the rule adjudicated for the receipt-base64 contract
// (fixtures/cases.json, "Receipt base64" paragraph):
//
//   - ACCEPT: the standard (+/) or the base64url (-_) alphabet, not both
//     in the same string; padding present or omitted; CR, LF, space and
//     tab anywhere, stripped before decoding.
//   - REJECT (yields no bytes): any character outside both alphabets;
//     both alphabets in one string; anything but whitespace after the
//     padding starts; padding whose length is not exactly what the
//     unpadded data requires (over- or under-padded); a stripped length
//     congruent to 1 mod 4; an empty or whitespace-only string.
//
// There is deliberately no canonical-trailing-bits check: an unpadded
// tail's unused low bits are simply dropped, same as before.
//
// A rejected input decodes to nil, not an error — decodeBase64 still
// never fails. That is what lets every caller (VerifyBase64, the
// verifyReceipt endpoint, and the JWS x5c decoder) stay a single
// assignment: nil is empty is "not a certificate" / "not a CMS blob",
// the same downstream reasons a garbage decode already produced.

var base64Values = func() [128]int8 {
	var table [128]int8
	for i := range table {
		table[i] = -1
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for i := 0; i < len(alphabet); i++ {
		table[alphabet[i]] = int8(i)
	}
	table['-'] = 62
	table['_'] = 63
	return table
}()

// decodeBase64 decodes standard or URL-safe base64, padded or not,
// tolerating CR/LF/space/tab anywhere, and rejecting (as nil) anything
// the doc comment above does not accept.
//
// It stops as soon as it has produced limit+1 bytes, for input it has
// not already rejected. That one extra byte is all a caller needs to
// answer "over the limit", because the full decode can only be longer —
// so the verdict is identical to decoding everything and measuring
// afterwards, and the memory and CPU are bounded by the limit instead of
// by the attacker's input. A rejection found before the ceiling — an
// out-of-alphabet character, a mixed alphabet, non-whitespace after
// padding — short-circuits even earlier, without scanning the rest of
// the string.
//
// This matters because the base64 entry points are the untrusted-network
// surface: VerifyReceiptEndpoint emulates Apple's public verifyReceipt
// host. Decoding first and checking the ceiling afterwards would let a
// 300 MB request body allocate 225 MB against a 1 MB ceiling. The
// ceiling counts DECODED bytes, so skipped characters — PEM line breaks,
// whitespace — still do not count against it.
//
// The empty/mod-4 checks need the whole string's length, so they run
// only once the loop finishes without an early per-character rejection
// or an early ceiling return; a ceiling return already carries its own
// verdict ("exceeds the limit") regardless of how the rest of the string
// would have checked out.
func decodeBase64(text string, limit int) []byte {
	if limit < 0 {
		limit = 0
	}
	// One past the limit is the most this can usefully produce. Clamping
	// the capacity this way also keeps len(text)*3/4 from overflowing the
	// slice length on a 32-bit build.
	capacity := len(text)/4*3 + 3
	if limit < capacity-1 {
		capacity = limit + 1
	}
	out := make([]byte, 0, capacity)
	accumulator := uint32(0)
	bits := 0
	coreLen := 0
	padLen := 0
	sawStd := false
	sawURL := false
	sawPad := false
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		}
		if sawPad {
			// Nothing but more padding — or whitespace, handled above —
			// may follow the first '='.
			if c != '=' {
				return nil
			}
			coreLen++
			padLen++
			continue
		}
		if c == '=' {
			sawPad = true
			coreLen++
			padLen++
			continue
		}
		if c >= 128 {
			return nil
		}
		value := base64Values[c]
		if value < 0 {
			return nil
		}
		switch c {
		case '+', '/':
			if sawURL {
				return nil
			}
			sawStd = true
		case '-', '_':
			if sawStd {
				return nil
			}
			sawURL = true
		}
		coreLen++
		accumulator = accumulator<<6 | uint32(value)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(accumulator>>uint(bits)))
			if len(out) > limit {
				return out
			}
		}
	}
	// The impossible-length test is on the DATA, not the padded string:
	// "A===" is a multiple of four in total and still encodes no whole byte.
	dataLen := coreLen - padLen
	if dataLen == 0 || dataLen%4 == 1 {
		return nil
	}
	// Padding, if present, must be the exact amount needed to round the
	// unpadded data up to a multiple of 4 — no more, no less. An unpadded
	// string (padLen == 0) is still accepted.
	if padLen != 0 && padLen != (4-dataLen%4)%4 {
		return nil
	}
	return out
}

// decodeBase64URLStrict decodes one compact-JWS segment.
//
// Unlike decodeBase64 this one FAILS on anything that is not canonical
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
