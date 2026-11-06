package alertlog

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

func alert(text string) core.Alert {
	return core.Alert{Kind: core.AlertFinding, Tag: "spray:192.0.2.7", Severity: "high", Detector: "authspike", Text: text, Run: "r", At: "2026-11-05T12:00:00Z"}
}

func TestDeliverWritesOneLineToBoth(t *testing.T) {
	var out bytes.Buffer
	p := filepath.Join(t.TempDir(), "watch.log")
	s := &Sink{Out: &out, Path: p}
	if err := s.Deliver(context.Background(), alert("192.0.2.7 failed 80%")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	want := "2026-11-05T12:00:00Z ALERT [high] [c:spray:192.0.2.7] authspike: 192.0.2.7 failed 80%\n"
	if string(b) != want || out.String() != want {
		t.Errorf("file %q\nout  %q", b, out.String())
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
}

func TestLogIsAppendOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "watch.log")
	if err := os.WriteFile(p, []byte("earlier line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"one", "two"} {
		if err := (&Sink{Path: p}).Deliver(context.Background(), alert(n)); err != nil { // a new sink: a restart
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 || lines[0] != "earlier line" {
		t.Errorf("log = %q", b)
	}
}

// Alert text comes from log content. It must not be able to add a line of its own.
func TestAlertTextCannotForgeALine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "watch.log")
	hostile := "ok\n2026-11-05T12:00:01Z ALERT [critical] [c:forged] forged\r\x1b[2Jtail more"
	a := alert(hostile)
	a.Tag = "t\nag"
	if err := (&Sink{Path: p}).Deliver(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if n := strings.Count(string(b), "\n"); n != 1 {
		t.Fatalf("%d lines written for one alert: %q", n, b)
	}
	if strings.Contains(string(b), "\x1b") || strings.Contains(string(b), " ") {
		t.Errorf("control characters survived: %q", b)
	}
}

func TestDeliveryFailuresAreErrors(t *testing.T) {
	bad := &Sink{Path: filepath.Join(t.TempDir(), "no-such-dir", "watch.log")}
	if err := bad.Deliver(context.Background(), alert("x")); err == nil {
		t.Error("unwritable log reported as delivered")
	}
	if err := (&Sink{Out: failWriter{}}).Deliver(context.Background(), alert("x")); err == nil {
		t.Error("failed output reported as delivered")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestCycleLine(t *testing.T) {
	l := Line(core.Alert{Kind: core.AlertCycle, Run: "r1", At: "2026-11-05T12:00:00Z", Text: "CYCLE QUIET: ok"})
	if l != "2026-11-05T12:00:00Z CYCLE r1 CYCLE QUIET: ok" {
		t.Errorf("line = %q", l)
	}
}

func TestLineNamesTheWatcherOnlyWhenThereIsOne(t *testing.T) {
	a := core.Alert{Kind: core.AlertFinding, Tag: "t", Severity: "high", Detector: "d", Text: "x", At: "2026-11-05T12:00:00Z"}
	if got, want := Line(a), "2026-11-05T12:00:00Z ALERT [high] [c:t] d: x"; got != want {
		t.Errorf("unnamed line = %q, want %q (unchanged)", got, want)
	}
	a.Watcher = "attack"
	if got, want := Line(a), "2026-11-05T12:00:00Z ALERT [high] [c:t] [w:attack] d: x"; got != want {
		t.Errorf("named line = %q, want %q", got, want)
	}
	c := core.Alert{Kind: core.AlertCycle, Run: "watch-attack-1", Text: "CYCLE QUIET", At: "2026-11-05T12:00:00Z", Watcher: "attack"}
	if got, want := Line(c), "2026-11-05T12:00:00Z CYCLE watch-attack-1 [w:attack] CYCLE QUIET"; got != want {
		t.Errorf("named cycle line = %q, want %q", got, want)
	}
	// A hostile name cannot forge a second line.
	a.Watcher = "x\n2026 ALERT"
	if strings.Contains(Line(a), "\n") {
		t.Error("a newline in the watcher name reached the log")
	}
}
