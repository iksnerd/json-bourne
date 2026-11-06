package kibana

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type fakeDoc struct {
	id string
	ms int64 // milliseconds after epoch
}

// fakeKibana behaves like the 8.5.1 cluster we hit live: a sort that mentions _id
// returns total 0 and no hits, with HTTP 200 and no error. Everything else is an
// honest ES: range filters, ascending sort on the time field, size.
type fakeKibana struct {
	t        *testing.T
	docs     []fakeDoc
	calls    atomic.Int32
	idSorts  atomic.Int32
	searchAf atomic.Int32
	cursors  atomic.Int32 // epoch_millis gte clauses seen
}

func (f *fakeKibana) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Body map[string]any `json:"body"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			f.t.Errorf("decode: %v", err)
		}
		f.calls.Add(1)
		body := req.Params.Body
		if _, ok := body["search_after"]; ok {
			f.searchAf.Add(1)
		}
		sorts, _ := body["sort"].([]any)
		for _, s := range sorts {
			if m, ok := s.(map[string]any); ok {
				if _, has := m["_id"]; has {
					f.idSorts.Add(1)
					writeHits(w, 0, nil) // the silent wrong answer
					return
				}
			}
		}
		var match []fakeDoc
		for _, d := range f.docs {
			if f.matches(body["query"], d) {
				match = append(match, d)
			}
		}
		slices.SortStableFunc(match, func(a, b fakeDoc) int {
			if a.ms != b.ms {
				return int(a.ms - b.ms)
			}
			return strings.Compare(a.id, b.id)
		})
		total := len(match)
		size := int(body["size"].(float64))
		if len(match) > size {
			match = match[:size]
		}
		writeHits(w, total, match)
	})
}

func writeHits(w http.ResponseWriter, total int, docs []fakeDoc) {
	hits := make([]any, 0, len(docs))
	for _, d := range docs {
		ts := epoch.Add(time.Duration(d.ms) * time.Millisecond).Format(time.RFC3339Nano)
		hits = append(hits, map[string]any{
			"_index": "logs-example", "_id": d.id,
			"_source": map[string]any{"@timestamp": ts, "client_ip": "192.0.2.1", "id": d.id},
			"sort":    []any{d.ms + epoch.UnixMilli()},
		})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"rawResponse": map[string]any{
		"hits": map[string]any{"total": map[string]any{"value": total}, "hits": hits},
	}})
}

// matches evaluates the bool.filter list of range clauses on @timestamp.
func (f *fakeKibana) matches(q any, d fakeDoc) bool {
	filters := q.(map[string]any)["bool"].(map[string]any)["filter"].([]any)
	abs := d.ms + epoch.UnixMilli()
	for _, c := range filters {
		rng, ok := c.(map[string]any)["range"].(map[string]any)
		if !ok {
			continue
		}
		spec := rng["@timestamp"].(map[string]any)
		for op, v := range spec {
			if op == "format" {
				continue
			}
			var bound int64
			switch x := v.(type) {
			case string:
				tm, err := time.Parse(time.RFC3339Nano, x)
				if err != nil {
					f.t.Errorf("bad window bound %q: %v", x, err)
				}
				bound = tm.UnixMilli()
			case float64:
				if spec["format"] != "epoch_millis" {
					f.t.Errorf("numeric bound without format epoch_millis: %v", spec)
				}
				bound = int64(x)
				if op == "gte" {
					f.cursors.Add(1)
				}
			}
			switch op {
			case "gte":
				if abs < bound {
					return false
				}
			case "gt":
				if abs <= bound {
					return false
				}
			case "lt":
				if abs >= bound {
					return false
				}
			}
		}
	}
	return true
}

func corpus(segments ...[]fakeDoc) []fakeDoc {
	var out []fakeDoc
	for _, s := range segments {
		out = append(out, s...)
	}
	return out
}

// distinct makes n docs one second apart starting at start milliseconds.
func distinct(prefix string, n int, start int64) []fakeDoc {
	out := make([]fakeDoc, n)
	for i := range out {
		out[i] = fakeDoc{id: fmt.Sprintf("%s%04d", prefix, i), ms: start + int64(i)*1000}
	}
	return out
}

func tie(prefix string, n int, ms int64) []fakeDoc {
	out := make([]fakeDoc, n)
	for i := range out {
		out[i] = fakeDoc{id: fmt.Sprintf("%s%04d", prefix, i), ms: ms}
	}
	return out
}

func uniqueIDs(evs []core.Event) int {
	seen := map[string]bool{}
	for _, e := range evs {
		id, _ := e.Fields["id"].(string)
		seen[id] = true
	}
	return len(seen)
}

// The cluster returns nothing, silently, for any _id sort. Paging must never ask for
// one, and must read every page of a multi-page window.
func TestPagesWithoutIDSort(t *testing.T) {
	f := &fakeKibana{t: t, docs: distinct("a", 450, 0)}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	evs, err := collect(t, newSource(srv, 100), context.Background())
	if err != nil {
		t.Fatalf("err = %v (idSorts=%d)", err, f.idSorts.Load())
	}
	if len(evs) != 450 || uniqueIDs(evs) != 450 {
		t.Fatalf("events=%d unique=%d, want 450", len(evs), uniqueIDs(evs))
	}
	if f.idSorts.Load() != 0 || f.searchAf.Load() != 0 {
		t.Errorf("idSorts=%d search_after=%d, want 0 and 0", f.idSorts.Load(), f.searchAf.Load())
	}
	if f.calls.Load() != 5 {
		t.Errorf("calls = %d, want 5", f.calls.Load())
	}
	for i := 1; i < len(evs); i++ {
		if evs[i].Time.Before(evs[i-1].Time) {
			t.Fatalf("event %d out of order", i)
		}
	}
}

// 100 documents share one millisecond and straddle the page boundary (page size 200,
// the tie occupies positions 150..249). None may be lost and none doubled.
func TestTieStraddlingPageBoundary(t *testing.T) {
	f := &fakeKibana{t: t, docs: corpus(
		distinct("a", 150, 0),
		tie("t", 100, 500_000),
		distinct("z", 100, 600_000),
	)}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	s := newSource(srv, 200)
	evs, err := collect(t, s, context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(evs) != 350 || uniqueIDs(evs) != 350 {
		t.Fatalf("events=%d unique=%d, want 350 and 350", len(evs), uniqueIDs(evs))
	}
	if st := s.Stats(); st.Fetched != 350 || st.HitsTotal != 350 {
		t.Errorf("stats = %+v, want fetched 350 total 350", st)
	}
	if f.cursors.Load() == 0 {
		t.Error("no epoch_millis cursor clause was sent after page 1")
	}
}

// A full page that is entirely one millisecond cannot be walked. That must be an
// error, never a short result that looks complete.
func TestFullPageOnOneMillisecondIsAnError(t *testing.T) {
	f := &fakeKibana{t: t, docs: corpus(
		distinct("a", 30, 0),
		tie("t", 100, 500_000),
		distinct("z", 20, 600_000),
	)}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	evs, err := collect(t, newSource(srv, 100), context.Background())
	if err == nil {
		t.Fatalf("got %d events and no error; a stuck page must fail", len(evs))
	}
	if errors.Is(err, core.ErrNoRecords) {
		t.Errorf("error must not masquerade as no_records: %v", err)
	}
	if !strings.Contains(err.Error(), "timestamp") {
		t.Errorf("error does not say why: %v", err)
	}
}

// Guard on the fake itself: it must really return nothing for an _id sort, or the
// tests above prove nothing.
func TestFakeRefusesIDSortSilently(t *testing.T) {
	f := &fakeKibana{t: t, docs: distinct("a", 5, 0)}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	resp, err := newSource(srv, 10).Client.search(context.Background(), "logs-example", map[string]any{
		"size":  10,
		"query": map[string]any{"bool": map[string]any{"filter": []any{}}},
		"sort":  []any{map[string]any{"@timestamp": "asc"}, map[string]any{"_id": "asc"}},
	})
	if err != nil || resp.Total != 0 || len(resp.Hits) != 0 {
		t.Fatalf("fake did not mimic the cluster: %+v %v", resp, err)
	}
}
