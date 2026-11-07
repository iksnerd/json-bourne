package webhook

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// The sink is a product of the cap, the failure latch and the spacing. Walk it across
// cycles: a cap summary that fails latches the cycle, the latch ends with the cycle, the
// spacing outlives it, and a failed request still counts as a send for the spacing.
func TestCapFailureLatchAndSpacingAcrossCycles(t *testing.T) {
	f := newFake(t)
	var fail atomic.Bool
	f.h = func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(503)
			return
		}
		io.WriteString(w, "ok")
	}
	var slept []time.Duration
	s := newSink(t, Config{URL: f.url(), MaxPerCycle: 1, MinSeverity: core.SevHigh, MinInterval: time.Hour,
		Sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }})
	ctx := context.Background()
	hb := func(run string) core.Alert {
		return core.Alert{Kind: core.AlertCycle, Severity: "info", Tag: "watch-cycle", Run: run}
	}
	// Cycle 1: one sent, two capped; the webhook then goes down, so the summary fails.
	if err := s.Deliver(ctx, finding("a", "high", "x", "r1")); err != nil {
		t.Fatal(err)
	}
	s.Deliver(ctx, finding("b", "high", "x", "r1"))
	s.Deliver(ctx, finding("c", "high", "x", "r1"))
	fail.Store(true)
	if err := s.Deliver(ctx, hb("r1")); err == nil {
		t.Fatal("a failed summary is reported as delivered")
	}
	// Still cycle 1: the latch holds, later alerts error without a request.
	n := f.n()
	if err := s.Deliver(ctx, finding("d", "high", "x", "r1")); err == nil || f.n() != n {
		t.Fatalf("latched cycle sent again: err=%v requests %d->%d", err, n, f.n())
	}
	// Cycle 2: the latch and the cap start over; the spacing does not (a wait happens).
	fail.Store(false)
	before := len(slept)
	if err := s.Deliver(ctx, finding("e", "high", "x", "r2")); err != nil {
		t.Fatalf("cycle 2 inherited cycle 1's failure: %v", err)
	}
	if len(slept) != before+1 {
		t.Errorf("no spacing wait before the first send of the next cycle: %v", slept)
	}
	if err := s.Deliver(ctx, hb("r2")); err != nil {
		t.Fatal(err)
	}
	// Alerts below the threshold are never counted as capped.
	for i := 0; i < 2; i++ {
		s.Deliver(ctx, core.Alert{Kind: core.AlertRecovered, Severity: "info", Tag: "watch-recovered", Run: "r3"})
	}
	n = f.n()
	if err := s.Deliver(ctx, hb("r3")); err != nil || f.n() != n {
		t.Fatalf("info alerts below the threshold produced a cap summary: err=%v", err)
	}
}
