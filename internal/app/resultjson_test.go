package app

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// The optional keys of `hunt` and `activity` --output json, the ones a CLI scenario does
// not always reach. They are the keys the commands printed before the encoding moved here
// (RFC 0013), taken from the tags of the types they used. Every key must stay.

func keysOf(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	var walk func(v any, p string)
	walk = func(v any, p string) {
		switch x := v.(type) {
		case map[string]any:
			if len(x) == 0 {
				set[p] = true
			}
			for k, e := range x {
				walk(e, p+"."+k)
			}
		case []any:
			if len(x) == 0 {
				set[p] = true
			}
			for _, e := range x {
				walk(e, p+"[]")
			}
		default:
			set[p] = true
		}
	}
	walk(doc, "")
	var out []string
	for k := range set {
		out = append(out, strings.TrimPrefix(k, "."))
	}
	sort.Strings(out)
	return out
}

func jwin(h int) core.Window {
	to := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	return core.Window{From: to.Add(-time.Duration(h) * time.Hour), To: to}
}

func TestHuntResultJSONOptionalKeys(t *testing.T) {
	r := Result{
		Run: "search-x", Window: jwin(1), Baseline: jwin(2), Until: jwin(1).To, Stored: true,
		Search:   []string{"t"},
		Disabled: []Disabled{{Kind: "source", Name: "s"}},
		Sources: []SourceResult{{Name: "a", Status: StatusOK, Events: 2, Unparsable: 1, Duplicates: 3, IndexAlive: true, IndexDocs: 9,
			Err: errors.New("e")}},
		Detectors: []DetectorResult{{Name: "d", Status: StatusError, Findings: 1, Err: errors.New("x")}},
		Findings: []core.Finding{{Detector: "d", Tag: "t", Severity: core.SevHigh, Summary: "s", Window: jwin(1), Baseline: jwin(2),
			Detail: map[string]any{"k": 1}}},
	}
	want := []string{
		"baseline[]", "complete", "detectors[].error", "detectors[].findings", "detectors[].name", "detectors[].status",
		"disabled[].kind", "disabled[].name", "findings[].baseline[]", "findings[].detail.k", "findings[].detector",
		"findings[].severity", "findings[].summary", "findings[].tag", "findings[].window[]", "run", "search.absent", "search.terms[]",
		"sources[].duplicates", "sources[].error", "sources[].events", "sources[].high_unparsable", "sources[].index_alive",
		"sources[].index_documents", "sources[].name", "sources[].outcome", "sources[].status", "sources[].unparsable",
		"sources[].unparsable_share", "stored", "until", "window[]",
	}
	sort.Strings(want)
	if got := keysOf(t, r); !reflect.DeepEqual(got, want) {
		t.Errorf("hunt keys:\n got %v\nwant %v", got, want)
	}
	if got := keysOf(t, &r); !reflect.DeepEqual(got, want) {
		t.Errorf("hunt keys through a pointer differ: %v", got)
	}
}

func TestHuntResultJSONEmptyListsAreArraysAndAbsentSearchIsComplete(t *testing.T) {
	var r Result
	b, _ := json.Marshal(r)
	for _, want := range []string{`"sources":[]`, `"detectors":[]`, `"findings":[]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s lacks %s", b, want)
		}
	}
	// A search that matched nothing in a live index is an answer: complete is true.
	r = Result{Window: jwin(1), Baseline: jwin(2), Search: []string{"t"},
		Sources: []SourceResult{{Name: "a", Status: StatusOK, IndexAlive: true, IndexDocs: 5}}}
	b, _ = json.Marshal(r)
	if !strings.Contains(string(b), `"complete":true`) || !strings.Contains(string(b), `"absent":true`) {
		t.Errorf("absent search: %s", b)
	}
}

func TestActivityResultJSONOptionalKeys(t *testing.T) {
	last := jwin(1).To.Add(-time.Minute)
	r := ActivityResult{
		Run: "activity-x", Window: jwin(1), Baseline: jwin(2), Until: jwin(1).To, Stored: true, Verdict: VerdictActive,
		Reasons:  []string{"r"},
		Disabled: []Disabled{{Kind: "detector", Name: "d"}},
		Sources:  []SourceResult{{Name: "a", Status: StatusOK, Events: 2, Unparsable: 1, Duplicates: 3, Err: errors.New("e")}},
		Detectors: []ActivityDetector{{Name: "d", Status: StatusError, Err: errors.New("x"), Findings: 1,
			Report: core.ActivityReport{Seen: 3, Unparsable: 1, Notes: []string{"n"}, Subjects: []core.ActivitySubject{
				{Subject: "s", Kind: "actor", Current: 1, Previous: 1, Last: last, LastEarlier: last, Active: true, Noise: 1, Ignored: 1, Note: "n"}}}}},
		Flagged: []string{"f"},
	}
	want := []string{
		"baseline[]", "common_action_events_preceding", "common_action_events_window", "common_actions_flagged[]", "complete",
		"detectors[].error", "detectors[].events_read", "detectors[].findings_before_stop", "detectors[].name", "detectors[].notes[]",
		"detectors[].status", "detectors[].subjects[].active", "detectors[].subjects[].ignored", "detectors[].subjects[].kind",
		"detectors[].subjects[].last_genuine", "detectors[].subjects[].last_genuine_preceding", "detectors[].subjects[].noise",
		"detectors[].subjects[].note", "detectors[].subjects[].preceding_events", "detectors[].subjects[].subject",
		"detectors[].subjects[].window_events", "detectors[].unparsable", "disabled[].kind", "disabled[].name",
		"genuine_events_preceding", "genuine_events_window", "reasons[]", "run", "sources[].duplicates", "sources[].error",
		"sources[].events", "sources[].high_unparsable", "sources[].name", "sources[].status", "sources[].unparsable",
		"sources[].unparsable_share", "stored", "until", "verdict", "window[]",
	}
	sort.Strings(want)
	if got := keysOf(t, r); !reflect.DeepEqual(got, want) {
		t.Errorf("activity keys:\n got %v\nwant %v", got, want)
	}
}
