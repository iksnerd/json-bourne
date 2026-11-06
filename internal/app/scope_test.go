package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// seen counts what a reader yields for a wide window, per source name.
func seen(t *testing.T, r core.EventReader) map[string]int {
	t.Helper()
	out := map[string]int{}
	wide := core.Window{From: t0.Add(-48 * time.Hour), To: t0.Add(48 * time.Hour)}
	for e, err := range r.Events(context.Background(), wide) {
		if err != nil {
			t.Fatal(err)
		}
		out[e.Source]++
	}
	return out
}

// recorder is a detector that records what it was handed.
type recorder struct {
	name      string
	cur, prev map[string]int
	t         *testing.T
}

func (r *recorder) Name() string { return r.name }
func (r *recorder) Detect(_ context.Context, cur, prev core.EventReader, _ core.Window) ([]core.Finding, error) {
	r.cur, r.prev = seen(r.t, cur), seen(r.t, prev)
	return nil, nil
}

// two sources, each with one event in the current window and one in the preceding one.
func twoSources() []core.Source { return []core.Source{okSource("ingress"), okSource("kc")} }

func TestScopedDetectorReadsOnlyItsSourcesInBothWindows(t *testing.T) {
	m := newMem()
	scoped := &recorder{name: "scoped", t: t}
	all := &recorder{name: "all", t: t}
	_, err := Hunt(context.Background(), Deps{
		Sources: twoSources(), Detectors: []core.Detector{scoped, all}, Sink: m, Reader: m,
		Scopes: map[string][]string{"scoped": {"kc"}},
	}, "r", win())
	if err != nil {
		t.Fatal(err)
	}
	if got := scoped.cur; len(got) != 1 || got["kc"] != 1 {
		t.Errorf("scoped current window = %v, want only kc's one event", got)
	}
	if got := scoped.prev; len(got) != 1 || got["kc"] != 1 {
		t.Errorf("scoped preceding window = %v, want only kc's one event (the baseline is scoped too)", got)
	}
	// Unscoped behaviour is unchanged.
	if all.cur["ingress"] != 1 || all.cur["kc"] != 1 || all.prev["ingress"] != 1 || all.prev["kc"] != 1 {
		t.Errorf("unscoped detector saw cur=%v prev=%v, want both sources in both windows", all.cur, all.prev)
	}
}

// Scoping selects on the source name, not on what a mapper put in Event.Source.
func TestScopeFollowsTheSourceNameNotTheMapperLabel(t *testing.T) {
	m := newMem()
	src := okSource("kc")
	for i := range src.events {
		src.events[i].Source = "label-chosen-by-a-mapper"
	}
	rec := &recorder{name: "d", t: t}
	_, err := Hunt(context.Background(), Deps{
		Sources: []core.Source{src, okSource("ingress")}, Detectors: []core.Detector{rec}, Sink: m, Reader: m,
		Scopes: map[string][]string{"d": {"kc"}},
	}, "r", win())
	if err != nil {
		t.Fatal(err)
	}
	if rec.cur["kc"] != 1 || len(rec.cur) != 1 {
		t.Errorf("cur = %v, want kc's event under its source name", rec.cur)
	}
}

func TestScopeIsValidated(t *testing.T) {
	m := newMem()
	for name, tc := range map[string]struct {
		scopes map[string][]string
		want   string
	}{
		"unknown source":   {map[string][]string{"d": {"nope"}}, `"nope"`},
		"empty scope":      {map[string][]string{"d": {}}, "empty source scope"},
		"unknown detector": {map[string][]string{"ghost": {"a"}}, `"ghost"`},
	} {
		_, err := Hunt(context.Background(), Deps{
			Sources: []core.Source{okSource("a")}, Detectors: []core.Detector{fakeDetector{"d", fixed()}},
			Sink: m, Reader: m, Scopes: tc.scopes,
		}, "r", win())
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want one naming %s", name, err, tc.want)
		}
	}
}

// activityRec is a recording detector that also reports activity.
type activityRec struct {
	recorder
	actCur, actPrev map[string]int
}

func (a *activityRec) Activity(_ context.Context, cur, prev core.EventReader, _ core.Window) (core.ActivityReport, error) {
	a.actCur, a.actPrev = seen(a.t, cur), seen(a.t, prev)
	return core.ActivityReport{Seen: 1}, nil
}

func TestActivityReadsThroughTheSameScope(t *testing.T) {
	m := newMem()
	d := &activityRec{recorder: recorder{name: "d", t: t}}
	_, err := Activity(context.Background(), Deps{
		Sources: twoSources(), Detectors: []core.Detector{d}, Sink: m, Reader: m,
		Scopes: map[string][]string{"d": {"ingress"}},
	}, "r", win())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.actCur) != 1 || d.actCur["ingress"] != 1 || len(d.actPrev) != 1 || d.actPrev["ingress"] != 1 {
		t.Errorf("Activity saw cur=%v prev=%v, want ingress only", d.actCur, d.actPrev)
	}
}
