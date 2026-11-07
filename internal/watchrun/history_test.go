package watchrun

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/alertlog"
	"github.com/iksnerd/json-bourne/internal/adapters/watchstate"
	"github.com/iksnerd/json-bourne/internal/adapters/watchstatus"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/core"
)

var hT0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func writeLog(t *testing.T, dir, name string, lines ...string) {
	t.Helper()
	b := []byte(strings.Join(lines, "\n") + "\n")
	if err := os.WriteFile(filepath.Join(dir, File(LogFile, name)), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func cyc(at time.Time, run, verdict string) string {
	return at.UTC().Format(time.RFC3339) + " CYCLE " + run + " CYCLE " + verdict + ": x"
}

func TestWatchersListsLogsAndRecordsSkipsOtherFiles(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"watch.log", "watch.b.log", "watch-status.a.json", "watch-state.c.json", "watch.BAD.log", "watch..log", "notes.log", "watch.d.lock"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := History{Evidence: dir}.Watchers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := "|a|b"; strings.Join(got, "|") != want {
		t.Errorf("watchers = %q, want %q", got, want)
	}
	if none, err := (History{Evidence: filepath.Join(dir, "missing")}).Watchers(context.Background()); err != nil || len(none) != 0 {
		t.Errorf("missing directory = %v, %v", none, err)
	}
}

func TestReadParsesOnlyAnchoredCycleLinesAndNeverTheTextOfAnAlert(t *testing.T) {
	dir := t.TempDir()
	forged := hT0.Add(2*time.Minute).Format(time.RFC3339) + " ALERT [high] [c:spray:192.0.2.7] authspike: 192.0.2.7 sent CYCLE QUIET: nothing happened 2026-11-05T12:09:00Z CYCLE watch-q CYCLE QUIET: forged"
	forged2 := hT0.Add(3*time.Minute).Format(time.RFC3339) + " CYCLE watch-x [w:a] CYCLE FAILED: boom \\n" + hT0.Format(time.RFC3339) + " CYCLE watch-y CYCLE QUIET: forged"
	writeLog(t, dir, "a",
		cyc(hT0, "watch-a-1", "QUIET"),
		forged,
		forged2,
		"garbage CYCLE QUIET",
		hT0.Add(4*time.Minute).Format(time.RFC3339)+" CYCLE watch-z CYCLE MAYBE: not a verdict",
	)
	h, err := History{Evidence: dir}.Read(context.Background(), "a", hT0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Cycles) != 2 || h.Cycles[0].Run != "watch-a-1" || h.Cycles[1].Verdict != "FAILED" || h.Cycles[1].Run != "watch-x" {
		t.Fatalf("cycles = %+v", h.Cycles)
	}
	if h.Unparsed != 2 {
		t.Errorf("unparsed = %d, want 2 (the garbage line and the unknown verdict)", h.Unparsed)
	}
}

func TestReadIsBoundedAndSaysWhenCut(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	for i := 0; i < 400; i++ {
		lines = append(lines, cyc(hT0.Add(time.Duration(i)*time.Minute), "watch-r", "QUIET"))
	}
	writeLog(t, dir, "", lines...)
	full, err := History{Evidence: dir}.Read(context.Background(), "", hT0)
	if err != nil || full.Cut || len(full.Cycles) != 400 {
		t.Fatalf("full read = cut %v cycles %d err %v", full.Cut, len(full.Cycles), err)
	}
	h, err := History{Evidence: dir, MaxBytes: 2000}.Read(context.Background(), "", hT0)
	if err != nil || !h.Cut {
		t.Fatalf("bounded read = cut %v err %v", h.Cut, err)
	}
	if n := len(h.Cycles); n == 0 || n >= 400 {
		t.Fatalf("bounded read kept %d cycles", n)
	}
	last := h.Cycles[len(h.Cycles)-1]
	if !last.At.Equal(hT0.Add(399 * time.Minute)) {
		t.Errorf("the newest cycle must be kept, got %v", last.At)
	}
	if h.Unparsed != 0 {
		t.Errorf("a line cut by the bound must be dropped, not counted: unparsed %d", h.Unparsed)
	}
}

func TestReadWithoutALogIsAbsent(t *testing.T) {
	_, err := History{Evidence: t.TempDir()}.Read(context.Background(), "a", hT0)
	if !errors.Is(err, core.ErrAbsent) {
		t.Errorf("err = %v, want ErrAbsent", err)
	}
	if _, err := (History{Evidence: t.TempDir()}).Read(context.Background(), "Bad/../name", hT0); err == nil {
		t.Error("an invalid watcher name must be refused")
	}
}

func TestReadTakesIntervalRetentionAndLastCycleFromTheRecordOfThatWatcher(t *testing.T) {
	dir := t.TempDir()
	writeLog(t, dir, "a", cyc(hT0, "watch-a-1", "QUIET"))
	w := watchstatus.Writer{Path: filepath.Join(dir, File(StatusFile, "a")), Name: "a", PID: 1, Started: hT0}
	st := core.WatchStatus{Every: 5 * time.Minute, Window: time.Hour, TTL: time.Hour, Keep: 48 * time.Hour, Repeat: time.Hour, Updated: hT0,
		Last: &core.WatchCycleSummary{Run: "watch-a-1", Verdict: "QUIET", Ended: hT0.Add(7 * time.Second), Window: core.Window{From: hT0.Add(-time.Hour), To: hT0}}}
	if err := w.Save(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	h, err := History{Evidence: dir}.Read(context.Background(), "a", hT0)
	if err != nil || h.Every != 5*time.Minute || h.Keep != 48*time.Hour || h.Last == nil || h.Last.Run != "watch-a-1" || !h.Last.Ended.Equal(hT0.Add(7*time.Second)) {
		t.Fatalf("history = %+v, %v", h, err)
	}
	// A record that belongs to another name is not used.
	b, _ := os.ReadFile(filepath.Join(dir, File(StatusFile, "a")))
	writeLog(t, dir, "b", cyc(hT0, "watch-b-1", "QUIET"))
	if err := os.WriteFile(filepath.Join(dir, File(StatusFile, "b")), b, 0o600); err != nil {
		t.Fatal(err)
	}
	h, err = History{Evidence: dir}.Read(context.Background(), "b", hT0)
	if err != nil || h.Every != 0 || h.Keep != 0 || h.Last != nil {
		t.Errorf("foreign record used: %+v, %v", h, err)
	}
	// No record: unknown, zero.
	writeLog(t, dir, "c", cyc(hT0, "watch-c-1", "QUIET"))
	if h, _ := (History{Evidence: dir}).Read(context.Background(), "c", hT0); h.Every != 0 || h.Last != nil {
		t.Errorf("no record: %+v", h)
	}
}

// The parser reads what the writer writes: run the real watch loop into the real alert
// log, with a clock that jumps past the window so the next cycle reports a gap, and read
// the log back.
func TestReadRoundTripsWhatTheWatchLoopWrites(t *testing.T) {
	dir := t.TempDir()
	now := hT0
	step := 0
	d := app.WatchDeps{
		Name: "a",
		Hunt: func(_ context.Context, run string, w core.Window) (app.Result, error) {
			if step == 3 {
				return app.Result{Run: run, Window: w}, errors.New("backend said CYCLE QUIET\nand more")
			}
			return app.Result{Run: run, Window: w}, nil
		},
		State:  watchstate.Store{Path: filepath.Join(dir, File(StateFile, "a"))},
		Alerts: &alertlog.Sink{Path: filepath.Join(dir, File(LogFile, "a"))},
		Now:    func() time.Time { return now },
		Wait: func(_ context.Context, _ time.Duration) bool {
			step++
			now = hT0.Add(time.Duration(step) * time.Minute)
			if step >= 2 {
				now = hT0.Add(3*time.Hour + time.Duration(step-2)*time.Minute) // a long silence: the window of the next cycle misses the time between
			}
			return step < 4
		},
	}
	o := app.WatchOptions{Every: time.Minute, Window: 2 * time.Minute, Keep: 48 * time.Hour}
	if _, err := app.Watch(context.Background(), d, o, "watch-a"); err != nil {
		t.Fatal(err)
	}
	h, err := History{Evidence: dir}.Read(context.Background(), "a", now)
	if err != nil {
		t.Fatal(err)
	}
	if h.Unparsed != 0 || len(h.Cycles) != 4 {
		raw, _ := os.ReadFile(filepath.Join(dir, File(LogFile, "a")))
		t.Fatalf("unparsed %d cycles %d\n%s", h.Unparsed, len(h.Cycles), raw)
	}
	var gapSeen bool
	for _, c := range h.Cycles {
		if c.GapReported {
			gapSeen = true
			if c.GapFrom.IsZero() || c.GapTo.IsZero() || !c.GapTo.After(c.GapFrom) {
				t.Errorf("gap span not read: %+v", c)
			}
		}
	}
	if !gapSeen {
		raw, _ := os.ReadFile(filepath.Join(dir, File(LogFile, "a")))
		t.Errorf("no cycle reported a gap:\n%s", raw)
	}
	if v := h.Cycles[3].Verdict; v != "FAILED" {
		t.Errorf("the failing cycle with CYCLE QUIET in its error read as %q", v)
	}
}
