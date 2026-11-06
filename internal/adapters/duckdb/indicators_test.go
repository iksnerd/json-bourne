package duckdb

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

func indEv(ip string, extra map[string]any) core.Event {
	f := map[string]any{}
	if ip != "" {
		f["client_ip"] = ip
	}
	for k, v := range extra {
		f[k] = v
	}
	return core.Event{Time: base, Source: "s", Kind: "request", Fields: f, Raw: []byte(`{"ip":"` + ip + `"}`)}
}

func TestLatestRunIndicatorsTakesTheLatestHuntAcrossItsSources(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	// An older hunt, whose addresses must not be returned.
	if err := s.SaveEvents(ctx, "hunt-1/kibana:a", seq(indEv("203.0.113.9", nil))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	// The latest hunt has two sources; 192.0.2.1 is the most frequent address.
	if err := s.SaveEvents(ctx, "hunt-2/kibana:a", seq(
		core.Event{Time: base, Source: "s", Kind: "k", Fields: map[string]any{"client_ip": "192.0.2.1"}, Raw: []byte(`1`)},
		core.Event{Time: base, Source: "s", Kind: "k", Fields: map[string]any{"client_ip": "192.0.2.1"}, Raw: []byte(`2`)},
		core.Event{Time: base, Source: "s", Kind: "k", Fields: map[string]any{"client_ip": "198.51.100.2", "src": "198.51.100.3"}, Raw: []byte(`3`)},
		core.Event{Time: base, Source: "s", Kind: "k", Fields: map[string]any{"status": 200.0}, Raw: []byte(`4`)},
	)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents(ctx, "hunt-2/kibana:b", seq(indEv("192.0.2.1", nil))); err != nil {
		t.Fatal(err)
	}
	run, got, err := s.LatestRunIndicators(ctx, []string{"client_ip", "src"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if run != "hunt-2" {
		t.Fatalf("run %q", run)
	}
	want := []string{"192.0.2.1", "198.51.100.2", "198.51.100.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v (most frequent first, ties by value)", got, want)
	}
	_, got, err = s.LatestRunIndicators(ctx, []string{"client_ip"}, 1)
	if err != nil || !reflect.DeepEqual(got, []string{"192.0.2.1"}) {
		t.Fatalf("limit: %v %v", got, err)
	}
}

func TestLatestRunIndicatorsDoesNotMatchRunsBySharedPrefix(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.SaveEvents(ctx, "hunt-20/x", seq(indEv("203.0.113.9", nil))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := s.SaveEvents(ctx, "hunt-2/x", seq(indEv("192.0.2.1", nil))); err != nil {
		t.Fatal(err)
	}
	_, got, err := s.LatestRunIndicators(ctx, []string{"client_ip"}, 10)
	if err != nil || !reflect.DeepEqual(got, []string{"192.0.2.1"}) {
		t.Fatalf("%v %v", got, err)
	}
}

func TestLatestRunIndicatorsErrorsWhereNothingCanBeSaid(t *testing.T) {
	s := openTest(t)
	if _, _, err := s.LatestRunIndicators(context.Background(), []string{"client_ip"}, 10); err == nil {
		t.Fatal("an empty store must be an error, not an empty list")
	}
	if err := s.SaveEvents(context.Background(), "hunt-1/x", seq(indEv("", map[string]any{"status": 200.0}))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LatestRunIndicators(context.Background(), []string{"client_ip"}, 10); err == nil {
		t.Fatal("a run with no value in the named fields must be an error")
	}
}

func fieldEv(at time.Duration, ua, raw string) core.Event {
	return core.Event{Time: base.Add(at), Source: "s", Kind: "http", Fields: map[string]any{"user_agent": ua, "path": "/x", "n": 1.0}, Raw: []byte(raw)}
}

func collectByField(t *testing.T, s *Store, field, value string) ([]core.Event, error) {
	t.Helper()
	var out []core.Event
	for ev, err := range s.EventsByField(context.Background(), field, value) {
		if err != nil {
			return out, err
		}
		out = append(out, ev)
	}
	return out, nil
}

func TestEventsByFieldIsExactAndNewestFirst(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.SaveEvents(ctx, "hunt-1/a", seq(
		fieldEv(1*time.Minute, "Example/1.0", "a"),
		fieldEv(3*time.Minute, "Example/1.0", "b"),
		fieldEv(2*time.Minute, "Example/1.0 extra", "c"), // a longer user agent: not equal
		fieldEv(4*time.Minute, "example/1.0", "d"),       // different case: not equal
		fieldEv(5*time.Minute, "Example/1.0", "e"),
	)); err != nil {
		t.Fatal(err)
	}
	got, err := collectByField(t, s, "user_agent", "Example/1.0")
	if err != nil || len(got) != 3 {
		t.Fatalf("got %d events, err %v, want the 3 exact matches", len(got), err)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Time.After(got[i-1].Time) {
			t.Fatalf("not newest first: %v", got)
		}
	}
	if !got[0].Time.Equal(base.Add(5*time.Minute)) || got[0].Fields["path"] != "/x" {
		t.Fatalf("first = %+v", got[0])
	}
	if got[0].Raw != nil {
		t.Fatal("raw documents are read although the caller only judges fields")
	}
	if none, err := collectByField(t, s, "user_agent", "Nobody/9"); err != nil || len(none) != 0 {
		t.Fatalf("none = %v, err %v", none, err)
	}
}

// The field and the value are parameters. Text that looks like SQL or like a JSON path
// is data and matches only an event that carries exactly that text.
func TestEventsByFieldTakesNoQueryText(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	hostile := `x' OR '1'='1`
	if err := s.SaveEvents(ctx, "r", seq(fieldEv(time.Minute, hostile, "a"), fieldEv(2*time.Minute, "benign", "b"))); err != nil {
		t.Fatal(err)
	}
	got, err := collectByField(t, s, "user_agent", hostile)
	if err != nil || len(got) != 1 || got[0].Fields["user_agent"] != hostile {
		t.Fatalf("got %v, err %v: the value was not treated as data", got, err)
	}
	for _, field := range []string{`user_agent"] OR 1=1 --`, `a\b`, ""} {
		if _, err := collectByField(t, s, field, "benign"); err == nil {
			t.Fatalf("field %q accepted", field)
		}
	}
	if _, err := collectByField(t, s, "user_agent", ""); err == nil {
		t.Fatal("an empty value was accepted")
	}
	if n, err := s.Stats(); err != nil || n.Events != 2 {
		t.Fatalf("stats = %+v, %v: the hostile input changed the store", n, err)
	}
}

func TestEventsByFieldWorksOnAReadOnlyStore(t *testing.T) {
	path := t.TempDir() + "/ro.duckdb"
	w, err := Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := w.SaveEvents(context.Background(), "r", seq(fieldEv(time.Minute, "Example/1.0", "a"))); err != nil {
		t.Fatal(err)
	}
	w.Close()
	ro, err := Open(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	got, err := collectByField(t, ro, "user_agent", "Example/1.0")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, err %v", got, err)
	}
}

// A backfill (jb hunt --until) is stored as hunt-until-<end>-w<seconds>/<source>. "Latest"
// is by created_at, as for any run: a backfill stored now is the newest run, whatever
// window it covers, and the answer names it. Saving a run again replaces its events but
// keeps its created_at, so repeating an old backfill does not make it the newest again.
// This test pins that decision (docs/BACKFILL.md); change it only on purpose.
func TestLatestRunIndicatorsOrdersABackfillByWhenItWasStored(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	save := func(run, ip string) {
		t.Helper()
		if err := s.SaveEvents(ctx, run, seq(indEv(ip, nil))); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	const (
		backfill = "hunt-until-20261001T120000Z-w86400s"
		live     = "hunt-20261105T120000Z"
	)
	save(backfill+"/kibana:a", "203.0.113.1")
	save(live+"/kibana:a", "203.0.113.2")
	run, got, err := s.LatestRunIndicators(ctx, []string{"client_ip"}, 10)
	if err != nil || run != live || !reflect.DeepEqual(got, []string{"203.0.113.2"}) {
		t.Fatalf("after a live hunt: %q %v %v", run, got, err)
	}
	// Repeating the old backfill replaces its events but keeps its place in time.
	save(backfill+"/kibana:a", "203.0.113.1")
	if run, _, _ = s.LatestRunIndicators(ctx, []string{"client_ip"}, 10); run != live {
		t.Errorf("a repeated backfill became the latest run: %q", run)
	}
	// A backfill stored after the live hunt is the newest run, by creation time, and is named.
	const fresh = "hunt-until-20260901T120000Z-w86400s"
	save(fresh+"/kibana:a", "203.0.113.3")
	run, got, err = s.LatestRunIndicators(ctx, []string{"client_ip"}, 10)
	if err != nil || run != fresh || !reflect.DeepEqual(got, []string{"203.0.113.3"}) {
		t.Fatalf("a backfill stored last: %q %v %v (its dashes must not make it match another hunt)", run, got, err)
	}
}
