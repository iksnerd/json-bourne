package plugin

import (
	"regexp"
	"strings"
	"sync"
	"unicode"
)

// boundedTail keeps the last cap bytes written to it and never blocks the writer. It
// is the child's stderr: a plugin that floods it costs jb cap bytes, not memory.
type boundedTail struct {
	mu  sync.Mutex
	cap int
	buf []byte
}

func (b *boundedTail) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if len(p) >= b.cap {
		b.buf = append(b.buf[:0], p[len(p)-b.cap:]...)
		return n, nil
	}
	b.buf = append(b.buf, p...)
	if over := len(b.buf) - b.cap; over > 0 {
		b.buf = append(b.buf[:0], b.buf[over:]...)
	}
	return n, nil
}

func (b *boundedTail) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

var (
	reANSI   = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07`)
	reKeyVal = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|bearer)\b(\s*[=:]\s*|\s+)\S+`)
	reLongTk = regexp.MustCompile(`[A-Za-z0-9+/=_-]{32,}`)
)

// maxErrText bounds plugin-authored text that ends up in an error message.
const maxErrText = 400

// scrub makes plugin-authored text safe to put in an error: control characters and
// terminal escapes are removed, anything that looks like a credential (a key=value
// pair named like one, or a 32+ character token) is replaced, and the result is
// shortened. It is a heuristic: a plugin that wants to leak can encode around it. Its
// job is to stop the accident, and the real defence is that the child never receives a
// secret (see Host.childEnv).
func scrub(s string) string {
	s = reANSI.ReplaceAllString(s, "")
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	s = reKeyVal.ReplaceAllString(s, "$1=[redacted]")
	s = reLongTk.ReplaceAllString(s, "[redacted]")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxErrText {
		s = "..." + s[len(s)-maxErrText:]
	}
	return s
}
