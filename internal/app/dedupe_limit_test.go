package app

import (
	"context"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// A shared scope holds every event of its sources in memory until all of them are read
// (the stored copy is chosen by the smallest source name). That buffer is bounded: past
// the limit the source fails, so the run is incomplete, instead of the process running
// out of memory on a large window.
func TestSharedScopeBufferIsBounded(t *testing.T) {
	old := sharedBufferLimit
	sharedBufferLimit = 2048
	defer func() { sharedBufferLimit = old }()

	big := strings.Repeat("x", 700)
	mk := func(name string) core.Source {
		var evs []core.Event
		for _, id := range []string{"d1", "d2", "d3", "d4", "d5", "d6"} {
			evs = append(evs, docAt(name, id, big+id, win().From))
		}
		return sourceOf(name, evs...)
	}
	m := newMem()
	res, err := Hunt(context.Background(), Deps{Sources: []core.Source{mk("a"), mk("b")}, Detectors: []core.Detector{fakeDetector{"d", fixed()}}, Sink: m, Reader: m, Concurrency: 1}, "r", win())
	if err != nil {
		t.Fatalf("a bounded buffer is a source failure, not a hunt error: %v", err)
	}
	if res.Complete() {
		t.Fatal("the buffer limit was hit but the hunt reports complete")
	}
	var msg string
	for _, s := range res.Sources {
		if s.Err != nil {
			msg += s.Err.Error()
		}
	}
	if !strings.Contains(msg, "shared-scope buffer limit") {
		t.Errorf("no source names the limit: %q", msg)
	}
}

// Under the limit nothing changes.
func TestSharedScopeBufferUnderTheLimitIsComplete(t *testing.T) {
	a := sourceOf("a", docAt("a", "d1", "r1", win().From))
	b := sourceOf("b", docAt("b", "d1", "r1", win().From))
	m := newMem()
	res, err := Hunt(context.Background(), Deps{Sources: []core.Source{a, b}, Detectors: []core.Detector{fakeDetector{"d", fixed()}}, Sink: m, Reader: m, Concurrency: 1}, "r", win())
	if err != nil || !res.Complete() {
		t.Fatalf("err=%v complete=%v", err, res.Complete())
	}
}
