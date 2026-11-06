package core

import (
	"errors"
	"fmt"
)

// UsageError marks a failure caused by how jb was asked, not by what it found: a
// negative window, a bad watcher name, a config the case does not allow. A caller can
// fix it by changing the request. The CLI exits 2 on it and the Go package reports it
// through jb.IsUsage. A case that is missing, a source that is down and a credential
// that is not set are not usage errors: the request was well formed.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// Usagef returns a *UsageError with a formatted message.
func Usagef(format string, a ...any) error {
	return &UsageError{Msg: fmt.Sprintf(format, a...)}
}

// IsUsage reports whether err is, or wraps, a *UsageError.
func IsUsage(err error) bool {
	var ue *UsageError
	return errors.As(err, &ue)
}
