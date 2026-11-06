package kibana

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const testKey = "SECRET-KEY-VALUE-0123"

var window = core.Window{
	From: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	To:   time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC),
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newSource(srv *httptest.Server, pageSize int) *Source {
	return &Source{Client: New(srv.URL, testKey), Index: "logs-example", PageSize: pageSize}
}

func collect(t *testing.T, s *Source, ctx context.Context) ([]core.Event, error) {
	t.Helper()
	var evs []core.Event
	var last error
	for ev, err := range s.Fetch(ctx, window) {
		if err != nil {
			last = err
			break
		}
		evs = append(evs, ev)
	}
	return evs, last
}

func TestMultiPageStreaming(t *testing.T) {
	pages := [][]byte{fixture(t, "page1.json"), fixture(t, "page2.json"), fixture(t, "page3.json")}
	var calls atomic.Int32
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "ApiKey "+testKey {
			t.Errorf("auth header = %q", got)
		}
		var req struct {
			Params struct {
				Index string         `json:"index"`
				Body  map[string]any `json:"body"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		bodies = append(bodies, req.Params.Body)
		n := int(calls.Add(1)) - 1
		w.Write(pages[n])
	}))
	defer srv.Close()

	s := newSource(srv, 2)
	evs, err := collect(t, s, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 5 || calls.Load() != 3 {
		t.Fatalf("events=%d calls=%d, want 5 and 3", len(evs), calls.Load())
	}
	// Pages after the first carry the last timestamp seen as an epoch_millis gte clause;
	// no request sorts on _id or uses search_after.
	wantCursor := []float64{0, 1767225602000, 1767225604000}
	for i, b := range bodies {
		if _, ok := b["search_after"]; ok {
			t.Errorf("page %d sent search_after", i)
		}
		if got, _ := json.Marshal(b["sort"]); strings.Contains(string(got), "_id") {
			t.Errorf("page %d sort = %s, must not include _id", i, got)
		}
		filters := b["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)
		var cursor float64
		for _, f := range filters {
			if rng, ok := f.(map[string]any)["range"].(map[string]any); ok {
				if spec, ok := rng["@timestamp"].(map[string]any); ok && spec["format"] == "epoch_millis" {
					cursor, _ = spec["gte"].(float64)
				}
			}
		}
		if cursor != wantCursor[i] {
			t.Errorf("page %d cursor = %v, want %v", i, cursor, wantCursor[i])
		}
	}
	if evs[0].Source != "kibana:logs-example" || evs[0].Fields["client_ip"] != "192.0.2.1" ||
		!evs[4].Time.Equal(time.Date(2026, 1, 1, 0, 0, 5, 0, time.UTC)) || len(evs[0].Raw) == 0 {
		t.Errorf("default mapping wrong: %+v", evs[0])
	}
	if st := s.Stats(); st.Fetched != 5 || st.HitsTotal != 5 {
		t.Errorf("stats = %+v", st)
	}
}

func TestStatsKeepTotalAndFetchedApart(t *testing.T) {
	// Index reports 9000 matches; the single page holds 1. Neither number may be derived from the other.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		_ = json.Unmarshal(fixture(t, "page3.json"), &p)
		p["rawResponse"].(map[string]any)["hits"].(map[string]any)["total"] = map[string]any{"value": 9000}
		_ = json.NewEncoder(w).Encode(p)
	}))
	defer srv.Close()
	s := newSource(srv, 10)
	if _, err := collect(t, s, context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); st.HitsTotal != 9000 || st.Fetched != 1 {
		t.Errorf("stats = %+v, want total 9000 fetched 1", st)
	}
}

func TestContextCancelStopsPaging(t *testing.T) {
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write(fixture(t, "page1.json")) // full page: would continue forever
	}))
	defer srv.Close()

	s := newSource(srv, 2)
	var n int
	var last error
	for _, err := range s.Fetch(ctx, window) {
		if err != nil {
			last = err
			break
		}
		n++
		cancel()
	}
	if !errors.Is(last, context.Canceled) {
		t.Fatalf("final error = %v, want context.Canceled", last)
	}
	if errors.Is(last, core.ErrSourceUnavailable) {
		t.Error("cancellation must not be reported as unavailable")
	}
	if calls.Load() != 1 || n != 2 {
		t.Errorf("calls=%d events=%d, want 1 and 2", calls.Load(), n)
	}
}

func TestUnauthorizedIsSourceUnavailable(t *testing.T) {
	for _, code := range []int{401, 403, 500, 503} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A hostile or sloppy proxy that reflects the credential.
			http.Error(w, "bad credential "+r.Header.Get("Authorization"), code)
		}))
		_, err := collect(t, newSource(srv, 2), context.Background())
		srv.Close()
		if !errors.Is(err, core.ErrSourceUnavailable) {
			t.Fatalf("HTTP %d: err = %v, want ErrSourceUnavailable", code, err)
		}
		if strings.Contains(err.Error(), testKey) {
			t.Errorf("HTTP %d: key leaked in error: %v", code, err)
		}
	}
}

func TestRefusedConnectionIsSourceUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // nothing listens any more
	_, err := collect(t, newSource(srv, 2), context.Background())
	if !errors.Is(err, core.ErrSourceUnavailable) {
		t.Fatalf("err = %v, want ErrSourceUnavailable", err)
	}
	if strings.Contains(err.Error(), testKey) {
		t.Error("key leaked in error")
	}
}

func TestEmptyWindowIsErrNoRecords(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture(t, "empty.json"))
	}))
	defer srv.Close()
	evs, err := collect(t, newSource(srv, 2), context.Background())
	if !errors.Is(err, core.ErrNoRecords) || len(evs) != 0 {
		t.Fatalf("events=%d err=%v, want ErrNoRecords", len(evs), err)
	}
}

func TestMapperErrorStopsStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture(t, "page1.json"))
	}))
	defer srv.Close()
	s := newSource(srv, 2)
	boom := errors.New("boom")
	s.Map = func(map[string]any) (core.Event, error) { return core.Event{}, boom }
	_, err := collect(t, s, context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}
