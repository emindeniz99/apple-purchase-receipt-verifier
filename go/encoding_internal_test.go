package applereceipt

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// decodeBase64 tries the standard library's decoder before its own
// tolerant one. That shortcut is safe only if it never changes an answer:
// every string the fast path accepts must be one the tolerant path
// accepts too, with the same bytes, and everything else must reach the
// tolerant path unchanged. If the fast path accepted a string the
// receipt-data contract rejects (a character after the padding, a wrong
// padding count), a malformed receipt would verify in Go alone and the
// ports would disagree.
//
// The standard decoder's behaviour is not frozen: the Python port found
// its "strict" decoder accepting over-padded strings on older versions.
// So this runs on every Go in the CI matrix rather than trusting one.

const (
	diffSeed       = 0x5EEDB64
	diffCases      = 20000
	diffIllegal    = "!#$%&*.,:;?@[]{}|~\"'\\\x00\x7f\x0b\x80\xff\xc3\xa9"
	diffWhitespace = "\r\n \t"
)

func TestDecodeBase64AgreesWithTheTolerantPathOnGeneratedInputs(t *testing.T) {
	random := rand.New(rand.NewSource(diffSeed))
	fastAccepted, tolerantOnlyAccepted, rejected, overLimit := 0, 0, 0, 0
	for i := 0; i < diffCases; i++ {
		input := generateBase64(random)
		// Mostly a roomy limit, sometimes one near the decoded size so the
		// ceiling guard in front of the fast path is exercised as well.
		limit := 1 << 20
		if random.Intn(4) == 0 {
			limit = random.Intn(len(input) + 1)
		}
		switch compareDecoders(t, input, limit) {
		case "fast":
			fastAccepted++
		case "tolerant":
			tolerantOnlyAccepted++
		case "over-limit":
			overLimit++
		default:
			rejected++
		}
	}
	t.Logf("fast path %d, tolerant only %d, over the limit %d, rejected %d",
		fastAccepted, tolerantOnlyAccepted, overLimit, rejected)
	// The comparison proves nothing unless every branch ran many times:
	// the fast path taken, the fallback accepting, and both rejecting.
	for name, count := range map[string]int{
		"fast path accepted": fastAccepted,
		"fallback accepted":  tolerantOnlyAccepted,
		"over the limit":     overLimit,
		"rejected by both":   rejected,
	} {
		if count < 500 {
			t.Errorf("%s only %d times", name, count)
		}
	}
}

func TestDecodeBase64AgreesWithTheTolerantPathOnHandPickedEdges(t *testing.T) {
	edges := []string{
		"", " ", "\r\n\t ", "\r\n", "\n\n\n\n",
		"=", "==", "===", "====",
		"A", "A=", "A==", "A===",
		"AA", "AA=", "AA==", "AA===",
		"AAA", "AAA=", "AAA==",
		"AAAA", "AAAA=", "AAAA==", "AAAA===", "AAAA====",
		"AA==A", "AA==\n", "AA=\n=", "AA=\r\n=", "AA== ", "AA==AA==", "AAAAA",
		"\nAA==", "A\nA==", "AA\n==", "AAAA\r\nAAAA",
		"-_", "+/", "+_", "-/", "AB-_", "AB+/", "AB+/\n",
		"AB\xc3\xa9=", "AB\x80", "AB\x00=",
		"QUJD", "QUJ", "QUI", "QQ", "QR", "QUK=", "QUJD\r\n", "QR==", "QUL=",
	}
	for _, edge := range edges {
		for _, limit := range []int{0, 1, 2, 3, 1 << 20} {
			compareDecoders(t, edge, limit)
		}
	}
}

// compareDecoders asserts that decodeBase64 and decodeBase64Tolerant give
// the same answer for input: equal bytes, or both nil. It reports which
// branch produced the answer.
func compareDecoders(t *testing.T, input string, limit int) string {
	t.Helper()
	want := decodeBase64Tolerant(input, limit)
	got := decodeBase64(input, limit)
	shown := strconv.Quote(input) + " limit " + strconv.Itoa(limit)
	switch {
	case want == nil && got != nil:
		t.Fatalf("decodeBase64 accepted what the tolerant path rejects: %s", shown)
	case want != nil && got == nil:
		t.Fatalf("decodeBase64 rejected what the tolerant path accepts: %s", shown)
	case !bytes.Equal(want, got):
		t.Fatalf("decodeBase64 and the tolerant path disagree on the bytes of %s", shown)
	}
	switch {
	case want == nil:
		return "rejected"
	case len(want) > limit:
		return "over-limit"
	case decodeBase64Fast(input, limit) != nil:
		return "fast"
	default:
		return "tolerant"
	}
}

func generateBase64(random *rand.Rand) string {
	raw := make([]byte, random.Intn(40))
	random.Read(raw)
	s := base64.StdEncoding.EncodeToString(raw)
	// About half the inputs stay canonical so the fast path is taken
	// often; the rest get one or more defects.
	if random.Intn(2) == 0 {
		return s
	}
	for m := 1 + random.Intn(3); m > 0; m-- {
		switch random.Intn(10) {
		case 0: // drop the padding
			s = strings.TrimRight(s, "=")
		case 1: // extra padding
			s += []string{"=", "=="}[random.Intn(2)]
		case 2: // base64url alphabet, whole string
			s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
		case 3: // one character of the other alphabet
			s = insertAt(random, s, pick(random, "+/-_"))
		case 4: // whitespace anywhere, before and after the padding included
			s = insertAt(random, s, pick(random, diffWhitespace))
		case 5: // an illegal byte, including non-ASCII and invalid UTF-8
			s = insertAt(random, s, pick(random, diffIllegal))
		case 6: // something after the padding
			s += "=" + string(rune('A'+random.Intn(26)))
		case 7: // data length congruent to 1 mod 4
			s = strings.TrimRight(s, "=")
			for len(s)%4 != 1 {
				s += "A"
			}
		case 8: // CR or LF only, which the standard decoder skips itself
			s = insertAt(random, s, pick(random, "\r\n"))
		default: // whitespace-only or empty
			if random.Intn(8) == 0 {
				s = ""
				for k := random.Intn(3); k > 0; k-- {
					s += pick(random, diffWhitespace)
				}
			} else {
				s += pick(random, diffWhitespace)
			}
		}
	}
	return s
}

func insertAt(random *rand.Rand, s, piece string) string {
	at := random.Intn(len(s) + 1)
	return s[:at] + piece + s[at:]
}

// pick returns one byte of set as a one-byte string, so a byte >= 0x80
// stays a lone byte (invalid UTF-8) instead of becoming a rune.
func pick(random *rand.Rand, set string) string {
	at := random.Intn(len(set))
	return set[at : at+1]
}
