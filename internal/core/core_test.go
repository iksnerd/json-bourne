package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestPreviousIsSameLengthAndAdjacent(t *testing.T) {
	to := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	w := Window{From: to.Add(-90 * time.Minute), To: to}
	p := w.Previous()
	if p.Duration() != w.Duration() {
		t.Fatalf("previous length %v, want %v", p.Duration(), w.Duration())
	}
	if !p.To.Equal(w.From) {
		t.Fatalf("previous ends %v, want %v", p.To, w.From)
	}
}

func TestLookupErrorsFindsEveryIndicatorInAJoinedError(t *testing.T) {
	a := &LookupError{Indicator: "192.0.2.1", Err: ErrRateLimited}
	b := &LookupError{Indicator: "192.0.2.2", Err: errors.New("boom")}
	joined := fmt.Errorf("feed: %w", errors.Join(a, fmt.Errorf("wrapped: %w", b)))
	got := LookupErrors(joined)
	if len(got) != 2 || got[0].Indicator != "192.0.2.1" || got[1].Indicator != "192.0.2.2" {
		t.Fatalf("LookupErrors = %+v", got)
	}
	if !errors.Is(a, ErrRateLimited) {
		t.Fatal("LookupError must unwrap to its cause")
	}
	if len(LookupErrors(errors.New("plain"))) != 0 || len(LookupErrors(nil)) != 0 {
		t.Fatal("a plain error carries no per-indicator failures")
	}
}

type stubSink struct {
	err   error
	calls int
}

func (s *stubSink) Deliver(context.Context, Alert) error { s.calls++; return s.err }

func TestFanOut(t *testing.T) {
	boom := errors.New("boom")
	t.Run("all ok", func(t *testing.T) {
		req, a, b := &stubSink{}, &stubSink{}, &stubSink{}
		if err := (FanOut{Required: req, Optional: []AlertSink{a, b}}).Deliver(context.Background(), Alert{}); err != nil || a.calls+b.calls != 2 {
			t.Fatal(err)
		}
	})
	t.Run("required fails: optionals are not tried", func(t *testing.T) {
		req, a := &stubSink{err: boom}, &stubSink{}
		err := FanOut{Required: req, Optional: []AlertSink{a}}.Deliver(context.Background(), Alert{})
		var oe *OptionalDeliveryError
		if !errors.Is(err, boom) || errors.As(err, &oe) || a.calls != 0 {
			t.Fatalf("err=%v calls=%d", err, a.calls)
		}
	})
	t.Run("an optional failure does not stop the others", func(t *testing.T) {
		req, bad, good := &stubSink{}, &stubSink{err: boom}, &stubSink{}
		err := FanOut{Required: req, Optional: []AlertSink{bad, good}}.Deliver(context.Background(), Alert{})
		var oe *OptionalDeliveryError
		if !errors.As(err, &oe) || !errors.Is(err, boom) || good.calls != 1 {
			t.Fatalf("err=%v goodcalls=%d", err, good.calls)
		}
	})
}
