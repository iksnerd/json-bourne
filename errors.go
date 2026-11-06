package jb

import "github.com/iksnerd/json-bourne/internal/core"

// UsageError is the error every function of this package returns, possibly wrapped,
// when the caller's request is at fault: a negative window, an invalid watcher name, a
// window shorter than the watch interval, a config the case does not allow. The CLI
// exits 2 on the same errors. A missing case, an unreachable source and an unset
// credential are not usage errors.
type UsageError = core.UsageError

// IsUsage reports whether err is, or wraps, a [UsageError]. Use it instead of reading
// the message.
func IsUsage(err error) bool { return core.IsUsage(err) }

// usagef returns a [UsageError] with the package's "jb: " prefix.
func usagef(format string, a ...any) error { return core.Usagef("jb: "+format, a...) }
