package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Drift delivery follows the same rules as the watch loop, over a disk-like store.

type flakySink struct {
	got    []core.Alert
	fail   bool
	optErr bool
}

func (f *flakySink) Deliver(_ context.Context, a core.Alert) error {
	if f.fail {
		return errors.New("sink down")
	}
	f.got = append(f.got, a)
	if f.optErr {
		return &core.OptionalDeliveryError{Err: errors.New("webhook 503")}
	}
	return nil
}

func TestSeqDriftDeliveryFollowsTheWatchRules(t *testing.T) {
	ds, sink := &diskState{}, &flakySink{}
	now := t0
	ttl := time.Hour
	f := core.Finding{Detector: DriftDetector, Tag: "estate_drift:ns:domain:example.com:abcd1234", Severity: core.SevActivity, Summary: "estate drift: x"}
	run := func(at time.Time) (DriftDelivery, error) {
		return DeliverDrift(context.Background(), ds, sink, at, ttl, "run", []core.Finding{f})
	}
	// Required sink down: not remembered, eligible again, error reported.
	sink.fail = true
	if r, err := run(now); err == nil || r.New != 0 {
		t.Fatalf("down sink: %+v %v", r, err)
	}
	if _, ok := ds.disk.Seen[f.Tag]; ok {
		t.Fatal("remembered an undelivered alert")
	}
	// Optional sink fails: delivered, remembered, error reported.
	sink.fail, sink.optErr = false, true
	if r, err := run(now.Add(time.Minute)); err == nil || r.New != 1 || r.OptionalFailed != 1 {
		t.Fatalf("optional failure: %+v %v", r, err)
	}
	sink.optErr = false
	if r, _ := run(now.Add(2 * time.Minute)); r.New != 0 || r.Suppressed != 1 {
		t.Fatalf("suppressed expected: %+v", r)
	}
	// Save failure after delivery: the alert repeats (at-least-once), and says so.
	ds.disk = core.WatchState{}
	ds.saveErr = errors.New("disk full")
	n := len(sink.got)
	if r, err := run(now.Add(3 * time.Minute)); err == nil || r.New != 1 || !strings.Contains(err.Error(), "repeat") {
		t.Fatalf("save failure: %+v %v", r, err)
	}
	ds.saveErr = nil
	if r, err := run(now.Add(4 * time.Minute)); err != nil || r.New != 1 || len(sink.got) != n+2 {
		t.Fatalf("documented repeat: %+v %v", r, err)
	}
	// Future-dated memory does not suppress; expiry re-delivers.
	ds.disk = core.WatchState{Seen: map[string]core.SeenTag{f.Tag: {At: now.Add(48 * time.Hour), Severity: core.SevCritical}}}
	if r, _ := run(now.Add(5 * time.Minute)); r.New != 1 {
		t.Fatalf("future-dated entry suppressed: %+v", r)
	}
	if r, _ := run(now.Add(5*time.Minute + ttl)); r.New != 1 {
		t.Fatalf("ttl expiry: %+v", r)
	}
}
