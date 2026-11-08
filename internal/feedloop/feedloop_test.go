package feedloop

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

type recorder struct {
	asked  []string
	sleeps []time.Duration
}

func (r *recorder) one(_ context.Context, ind string, _ netip.Addr) (core.Reputation, error) {
	r.asked = append(r.asked, ind)
	return core.Reputation{Indicator: ind}, nil
}

func (r *recorder) sleep(_ context.Context, d time.Duration) error {
	r.sleeps = append(r.sleeps, d)
	return nil
}

// lookupErrs returns the joined errors as a map from indicator to message.
func lookupErrs(t *testing.T, err error) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err == nil {
		return out
	}
	j, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("not a joined error: %T", err)
	}
	for _, e := range j.Unwrap() {
		var le *core.LookupError
		if !errors.As(e, &le) {
			t.Fatalf("not a LookupError: %v", e)
		}
		out[le.Indicator] = le.Err.Error()
	}
	return out
}

func TestRunSuccessSleepsBetweenAsks(t *testing.T) {
	r := &recorder{}
	got, err := Run(context.Background(), Config{MaxLookups: 5, MinInterval: time.Second, Sleep: r.sleep}, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, r.one)
	if err != nil || len(got) != 3 {
		t.Fatalf("got %d answers, err %v", len(got), err)
	}
	if len(r.sleeps) != 2 {
		t.Errorf("sleeps = %v, want 2 (none before the first ask)", r.sleeps)
	}
}

func TestRunBadAddressIsNotSent(t *testing.T) {
	r := &recorder{}
	got, err := Run(context.Background(), Config{MaxLookups: 5}, []string{"example.com", "fe80::1%eth0", "192.0.2.1"}, r.one)
	if len(got) != 1 || len(r.asked) != 1 {
		t.Fatalf("answers %d, asked %v", len(got), r.asked)
	}
	m := lookupErrs(t, err)
	for _, ind := range []string{"example.com", "fe80::1%eth0"} {
		if !strings.Contains(m[ind], "not an IP address, not sent") || !strings.HasPrefix(m[ind], core.ErrFeedFailed.Error()) {
			t.Errorf("%s: %q", ind, m[ind])
		}
	}
}

func TestRunStopsAfterRateLimit(t *testing.T) {
	asked := 0
	one := func(_ context.Context, ind string, _ netip.Addr) (core.Reputation, error) {
		asked++
		return core.Reputation{}, fmt.Errorf("%w: HTTP 429", core.ErrRateLimited)
	}
	_, err := Run(context.Background(), Config{MaxLookups: 5}, []string{"192.0.2.1", "192.0.2.2"}, one)
	if asked != 1 {
		t.Errorf("asked %d, want 1", asked)
	}
	m := lookupErrs(t, err)
	if !strings.Contains(m["192.0.2.2"], "not asked after the feed refused a request") || !strings.HasPrefix(m["192.0.2.2"], core.ErrRateLimited.Error()) {
		t.Errorf("second: %q", m["192.0.2.2"])
	}
	if !errors.Is(err, core.ErrRateLimited) {
		t.Error("error does not wrap ErrRateLimited")
	}
}

func TestRunBudget(t *testing.T) {
	r := &recorder{}
	got, err := Run(context.Background(), Config{MaxLookups: 1}, []string{"192.0.2.1", "192.0.2.2"}, r.one)
	if len(got) != 1 || len(r.asked) != 1 {
		t.Fatalf("answers %d, asked %v", len(got), r.asked)
	}
	if !errors.Is(err, core.ErrBudgetExceeded) || !strings.Contains(err.Error(), "the per-run cap is 1 lookups") {
		t.Errorf("err = %v", err)
	}
}

func TestRunCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &recorder{}
	_, err := Run(ctx, Config{MaxLookups: 5}, []string{"192.0.2.1"}, r.one)
	if len(r.asked) != 0 {
		t.Errorf("asked %v after cancel", r.asked)
	}
	if !errors.Is(err, core.ErrFeedFailed) || !strings.Contains(err.Error(), "not asked: context canceled") {
		t.Errorf("err = %v", err)
	}
}

func TestRunSleepError(t *testing.T) {
	r := &recorder{}
	sleep := func(context.Context, time.Duration) error { return errors.New("wait broke") }
	got, err := Run(context.Background(), Config{MaxLookups: 5, MinInterval: time.Second, Sleep: sleep}, []string{"192.0.2.1", "192.0.2.2"}, r.one)
	if len(got) != 1 || len(r.asked) != 1 {
		t.Fatalf("answers %d, asked %v", len(got), r.asked)
	}
	if !errors.Is(err, core.ErrFeedFailed) || !strings.Contains(err.Error(), "not asked: wait broke") {
		t.Errorf("err = %v", err)
	}
}

func TestRunScrubsDetailOnly(t *testing.T) {
	scrub := func(s string) string { return strings.ReplaceAll(s, "example.com", "[redacted]") }
	one := func(context.Context, string, netip.Addr) (core.Reputation, error) {
		return core.Reputation{}, errors.New("answer from example.com")
	}
	_, err := Run(context.Background(), Config{MaxLookups: 5, Scrub: scrub}, []string{"example.com", "192.0.2.1"}, one)
	m := lookupErrs(t, err)
	if strings.Contains(m["example.com"], "example.com") {
		t.Errorf("detail not scrubbed: %q", m["example.com"])
	}
	// The one-function error is passed through untouched: the feed scrubs its own.
	if m["192.0.2.1"] != "answer from example.com" {
		t.Errorf("one error changed: %q", m["192.0.2.1"])
	}
}
