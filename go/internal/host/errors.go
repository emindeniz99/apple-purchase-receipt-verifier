package host

import (
	"fmt"
	"strings"
)

// The kinds of failure a call can end in. The root package turns every one
// of them into INTERNAL_ERROR and keeps the kind in the failure's cause,
// so a caller who looks can tell a trap from a bad answer.

// TrapError is a guest trap, or a runtime error while the guest ran (an
// out-of-bounds access, unreachable, a failing host function). The guest
// instance it happened in has been discarded.
type TrapError struct {
	Fn  string // the export, without its interface prefix
	Err error
}

func (e *TrapError) Error() string {
	return "the verification module trapped in " + e.Fn + ": " + firstLine(e.Err.Error())
}

func (e *TrapError) Unwrap() error { return e.Err }

// ResultError is an answer the wrapper cannot use: a return area or a
// string outside the guest's memory, or JSON that is not what the wire
// defines. Where the guest's memory is in doubt the instance has been
// discarded.
type ResultError struct {
	Fn     string
	Detail string
}

func (e *ResultError) Error() string {
	return "the verification module's answer to " + e.Fn + " is unusable: " + e.Detail
}

// InitRefusedError is init answering {"ok":false}: a trust anchor the core
// does not accept. It is caller misuse, reported at create.
type InitRefusedError struct {
	Message string
	Answer  string // the module's answer, verbatim
}

func (e *InitRefusedError) Error() string {
	return "the verification module refused the trust anchors: " + e.Message
}

// ABIError is a module this package cannot bind: a missing export, a wrong
// signature, or an import beyond random-get.
type ABIError struct{ Detail string }

func (e *ABIError) Error() string { return e.Detail }

// usageError is the call helper refusing its own arguments before any call
// into the guest. It cannot happen through the typed methods.
type usageError struct{ detail string }

func (e *usageError) Error() string { return e.detail }

func usagef(format string, args ...any) error {
	return &usageError{detail: fmt.Sprintf(format, args...)}
}

// firstLine drops the stack trace wazero appends to a trap.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
