package duckdb

import (
	"context"
	"testing"
	"time"
)

func TestDashboardLastSeenIsTheNewestMatchSinceTheCutoff(t *testing.T) {
	d := dashFixture(t)
	ctx := context.Background()
	got, ok, err := d.LastSeen(ctx, "client_ip", "192.0.2.7", base.Add(-time.Hour))
	if err != nil || !ok || !got.Equal(base.Add(time.Second)) {
		t.Fatalf("LastSeen = %v %v %v, want the newest of two matches", got, ok, err)
	}
	// A match older than the cutoff is not a match: the answer is "none in the window".
	if _, ok, err := d.LastSeen(ctx, "client_ip", "192.0.2.7", base.Add(time.Minute)); ok || err != nil {
		t.Errorf("an event before the cutoff must not count: ok=%v err=%v", ok, err)
	}
	// An address that never appears is also not found, with no error.
	if _, ok, err := d.LastSeen(ctx, "client_ip", "198.51.100.1", base.Add(-time.Hour)); ok || err != nil {
		t.Errorf("unknown address: ok=%v err=%v", ok, err)
	}
	// The value and the field are bound, never text: a quote or a prefix matches nothing.
	if _, ok, _ := d.LastSeen(ctx, "client_ip", "192.0.2.7' OR '1'='1", base.Add(-time.Hour)); ok {
		t.Error("the value is not bound")
	}
	if _, ok, _ := d.LastSeen(ctx, "client_ip", "192.0.2", base.Add(-time.Hour)); ok {
		t.Error("the match must be exact")
	}
	if _, _, err := d.LastSeen(ctx, `client_ip"]`, "192.0.2.7", base.Add(-time.Hour)); err == nil {
		t.Error("a field that could break out of the JSON path must be refused")
	}
	if _, _, err := d.LastSeen(ctx, "client_ip", "", base); err == nil {
		t.Error("an empty value must be refused")
	}
}

func TestDashboardLastSeenStopsWhenTheContextEnds(t *testing.T) {
	d := dashFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok, err := d.LastSeen(ctx, "client_ip", "192.0.2.7", base.Add(-time.Hour)); err == nil || ok {
		t.Errorf("a cancelled context must be an error, not 'none': ok=%v err=%v", ok, err)
	}
}
