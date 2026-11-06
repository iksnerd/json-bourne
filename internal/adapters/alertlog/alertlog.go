// Package alertlog delivers alerts to a terminal and to an append-only local file.
// It sends nothing over a network.
package alertlog

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Sink writes each alert as one line to Out and appends the same line to Path.
// Both must succeed for an alert to count as delivered.
type Sink struct {
	Out  io.Writer
	Path string // empty: no file

	mu sync.Mutex
}

var _ core.AlertSink = (*Sink)(nil)

// Line renders an alert as exactly one line. Fields come from detector output and
// log content, so control characters are escaped: an alert text containing a newline
// must not be able to forge a second log line.
func Line(a core.Alert) string {
	var b strings.Builder
	switch a.Kind {
	case core.AlertCycle:
		fmt.Fprintf(&b, "%s %s %s", a.At, strings.ToUpper(a.Kind), clean(a.Run))
		if a.Watcher != "" {
			fmt.Fprintf(&b, " [w:%s]", clean(a.Watcher))
		}
	default:
		fmt.Fprintf(&b, "%s ALERT [%s] [c:%s]", a.At, clean(a.Severity), clean(a.Tag))
		if a.Watcher != "" {
			fmt.Fprintf(&b, " [w:%s]", clean(a.Watcher))
		}
		if a.Detector != "" {
			fmt.Fprintf(&b, " %s:", clean(a.Detector))
		}
	}
	b.WriteString(" ")
	b.WriteString(clean(a.Text))
	return b.String()
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\r", "\\r", "\t", "\\t").Replace(s))
}

// Deliver writes the line to the file first, then to Out.
func (s *Sink) Deliver(_ context.Context, a core.Alert) error {
	line := Line(a) + "\n"
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Path != "" {
		f, err := os.OpenFile(s.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("alert log: %w", err)
		}
		_, werr := f.WriteString(line)
		if werr == nil {
			werr = f.Sync()
		}
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return fmt.Errorf("alert log %s: %w", s.Path, werr)
		}
	}
	if s.Out != nil {
		if _, err := io.WriteString(s.Out, line); err != nil {
			return fmt.Errorf("alert output: %w", err)
		}
	}
	return nil
}
