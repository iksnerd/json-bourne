package kibana

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// filterServer answers like Kibana for a filtered source. A request that carries the
// filter clause gets `matching` hits. The liveness probe (size 0, no filter clause) gets
// `windowTotal` as the count and no hits. It records every request body.
type filterServer struct {
	mu          sync.Mutex
	bodies      []string
	matching    int
	windowTotal int
}

func (f *filterServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.bodies = append(f.bodies, string(raw))
		f.mu.Unlock()
		var req struct {
			Params struct {
				Body struct {
					Size int `json:"size"`
				} `json:"body"`
			} `json:"params"`
		}
		_ = json.Unmarshal(raw, &req)
		filtered := strings.Contains(string(raw), "match_phrase")
		total, n := f.windowTotal, 0
		if filtered {
			total, n = f.matching, f.matching
		}
		if req.Params.Body.Size == 0 {
			n = 0
		}
		var hits []string
		for i := 0; i < n; i++ {
			ms := 1_767_225_600_000 + int64(i)*1000
			hits = append(hits, fmt.Sprintf(
				`{"_index":"i","_id":"d%d","_source":{"@timestamp":"2026-01-01T00:00:%02dZ","message":"x"},"sort":[%d]}`, i, i, ms))
		}
		fmt.Fprintf(w, `{"rawResponse":{"hits":{"total":{"value":%d},"hits":[%s]}}}`, total, strings.Join(hits, ","))
	})
}

func filteredSource(srv *httptest.Server) *Source {
	s := newSource(srv, 100)
	s.Query = map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"match_phrase": map[string]any{"message": "x"}},
	}}}
	return s
}

func TestFilterIsSentToTheServer(t *testing.T) {
	f := &filterServer{matching: 2, windowTotal: 500}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	evs, err := collect(t, filteredSource(srv), context.Background())
	if err != nil || len(evs) != 2 {
		t.Fatalf("events=%d err=%v, want 2 events", len(evs), err)
	}
	if len(f.bodies) == 0 || !strings.Contains(f.bodies[0], "match_phrase") {
		t.Fatalf("the filter did not reach the server: %v", f.bodies)
	}
}

// With a selective filter, "nothing matched" is the normal quiet answer. It is only
// believable if the index is shown to be alive in the same window.
func TestFilteredEmptyOnALiveIndexIsNotAnError(t *testing.T) {
	f := &filterServer{matching: 0, windowTotal: 500}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	s := filteredSource(srv)
	evs, err := collect(t, s, context.Background())
	if err != nil || len(evs) != 0 {
		t.Fatalf("events=%d err=%v, want a clean empty result", len(evs), err)
	}
	if got := s.Stats().IndexTotal; got != 500 {
		t.Fatalf("Stats.IndexTotal = %d, want the window's unfiltered count 500", got)
	}
}

// If the unfiltered window is empty too, the index is silent or the source points at
// the wrong thing. That is not a quiet network.
func TestFilteredEmptyOnASilentIndexIsErrNoRecords(t *testing.T) {
	f := &filterServer{matching: 0, windowTotal: 0}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	_, err := collect(t, filteredSource(srv), context.Background())
	if !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want ErrNoRecords", err)
	}
}

// An unfiltered source keeps the old rule: an empty window is an error, and no probe
// is needed to say so.
func TestUnfilteredEmptyStillErrNoRecordsWithoutAProbe(t *testing.T) {
	f := &filterServer{matching: 0, windowTotal: 500}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	s := newSource(srv, 100) // no Query
	// the fake returns windowTotal hits-count with no hits for unfiltered size>0 requests
	_, err := collect(t, s, context.Background())
	if !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want ErrNoRecords", err)
	}
}

// Liveness is what lets an empty filtered window be told apart from a dead source, so
// it is set only by a probe that found documents, and never when the filter matched.
func TestLivenessIsReportedOnlyForAProbedEmptyWindow(t *testing.T) {
	t.Run("empty filtered window on a live index", func(t *testing.T) {
		f := &filterServer{matching: 0, windowTotal: 500}
		srv := httptest.NewServer(f.handler())
		defer srv.Close()
		s := filteredSource(srv)
		if _, err := collect(t, s, context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := s.Liveness(); !got.Probed || got.IndexTotal != 500 {
			t.Fatalf("Liveness = %+v, want probed with the probe's own count 500", got)
		}
	})
	t.Run("the filter matched, so no probe ran", func(t *testing.T) {
		f := &filterServer{matching: 2, windowTotal: 500}
		srv := httptest.NewServer(f.handler())
		defer srv.Close()
		s := filteredSource(srv)
		if _, err := collect(t, s, context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := s.Liveness(); got.Probed || got.IndexTotal != 0 {
			t.Fatalf("Liveness = %+v, want none: a probe that did not run proves nothing", got)
		}
		for _, b := range f.bodies {
			if strings.Contains(b, `"size":0`) {
				t.Fatalf("a liveness probe was sent although the filter matched: %s", b)
			}
		}
	})
	t.Run("a silent index is not alive", func(t *testing.T) {
		f := &filterServer{matching: 0, windowTotal: 0}
		srv := httptest.NewServer(f.handler())
		defer srv.Close()
		s := filteredSource(srv)
		if _, err := collect(t, s, context.Background()); !errors.Is(err, core.ErrNoRecords) {
			t.Fatalf("err = %v, want ErrNoRecords", err)
		}
		if s.Liveness().Probed {
			t.Fatal("Liveness.Probed is set for an index with no documents")
		}
	})
	t.Run("a new fetch resets it", func(t *testing.T) {
		f := &filterServer{matching: 0, windowTotal: 500}
		srv := httptest.NewServer(f.handler())
		defer srv.Close()
		s := filteredSource(srv)
		_, _ = collect(t, s, context.Background())
		f.mu.Lock()
		f.matching = 1
		f.mu.Unlock()
		_, _ = collect(t, s, context.Background())
		if s.Liveness().Probed {
			t.Fatal("the previous fetch's probe is still reported")
		}
	})
}
