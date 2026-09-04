package applereceipt

import "strconv"

// containPanic turns an unexpected panic inside a verification entry
// point into a *VerificationError.
//
// Containment is categorical, not a list of types. Two concrete reasons
// Go needs it:
//
//   - Under GODEBUG=fips140=only, crypto/sha1 panics rather than
//     erroring: "crypto/sha1: use of SHA-1 is not allowed in FIPS
//     140-only mode". Every genuine legacy Apple receipt is SHA-1
//     signed, so a library without this would abort its caller's process
//     for the crime of being deployed in FIPS mode. Answering
//     INVALID_SIGNATURE / INVALID_RECEIPT_FORMAT is the truth: we cannot
//     verify it here.
//   - A latent index bug in the hand-written parsers must surface as a
//     rejected receipt, not as a crashed request.
//
// The bounded parser in internal/der is the first line of defence and has
// its own tests; this is the net under it. A panic that reaches here is a
// bug — it is contained, not condoned.
func containPanic(reason Reason, err *error, clear func()) {
	if r := recover(); r != nil {
		if clear != nil {
			clear()
		}
		*err = newError(reason, "verification aborted: %v", r)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
