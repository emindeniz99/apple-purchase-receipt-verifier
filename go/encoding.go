package applereceipt

import (
	"encoding/base64"
)

// Base64 decoding, deliberately lenient in exactly the way the other
// ports are.
//
// Java decodes with Base64.getMimeDecoder() and Node with
// Buffer.from(s, "base64"): both skip characters outside the alphabet
// (whitespace, PEM line breaks, padding) and both accept the standard and
// URL-safe alphabets. Go's encoding/base64 does none of that — it rejects
// a newline, and StdEncoding rejects a '-'. Using it directly would make
// the Go port reject inputs the other four accept, which is a divergence
// in the answer to the same bytes.
//
// So this is the same table-driven decoder node/src/bytes.ts uses,
// character for character. It never fails: bytes outside both alphabets
// are skipped and a trailing partial group is dropped. Garbage in
// therefore produces garbage bytes, which then fail as "not a
// certificate" / "not JSON" / "not a CMS blob" — the same reasons the
// other ports produce, from the same inputs.

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
// skipping anything outside both alphabets.
//
// It stops as soon as it has produced limit+1 bytes. That one extra byte
// is all a caller needs to answer "over the limit", because the full
// decode can only be longer — so the verdict is identical to decoding
// everything and measuring afterwards, and the memory and CPU are
// bounded by the limit instead of by the attacker's input.
//
// This matters because the base64 entry points are the untrusted-network
// surface: VerifyReceiptEndpoint emulates Apple's public verifyReceipt
// host. Decoding first and checking the ceiling afterwards would let a
// 300 MB request body allocate 225 MB against a 1 MB ceiling. The
// ceiling counts DECODED bytes, so skipped characters — PEM line breaks,
// whitespace — still do not count against it.
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
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c >= 128 {
			continue
		}
		value := base64Values[c]
		if value < 0 {
			continue
		}
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
