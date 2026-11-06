package jb

import (
	"strings"
	"testing"
	"time"
)

func TestPlan(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 500, time.UTC)

	w, run, err := plan(now, HuntOptions{Window: time.Hour})
	if err != nil || run != "hunt-20261002T120000Z" || w.Duration() != time.Hour || !w.To.Equal(now.Truncate(time.Second)) {
		t.Fatalf("live: %v %q %v", w, run, err)
	}

	until := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	w, run, err = plan(now, HuntOptions{Window: 2 * time.Hour, Until: until})
	if err != nil || run != "hunt-until-20261001T000000Z-w7200s" || !w.To.Equal(until) {
		t.Fatalf("past: %v %q %v", w, run, err)
	}

	for name, o := range map[string]HuntOptions{
		"future":     {Window: time.Hour, Until: now.Add(time.Hour).Truncate(time.Second)},
		"fractional": {Window: time.Hour, Until: until.Add(time.Nanosecond)},
		"too long":   {Window: MaxHistoricalWindow + time.Second, Until: until},
	} {
		if _, _, err := plan(now, o); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestHuntRefusesNilConfig(t *testing.T) {
	if _, err := Hunt(t.Context(), nil, HuntOptions{}); err == nil || !strings.Contains(err.Error(), "nil config") {
		t.Fatalf("got %v", err)
	}
}
