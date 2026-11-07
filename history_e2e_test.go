package jb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// historyKibana is the fake Kibana of the history test: every request except a filters
// aggregation is answered by fakeIndex; an aggregation is counted per bucket against the
// same documents. It records every request body.
type historyKibana struct {
	idx  *fakeIndex
	srv  *httptest.Server
	aggs []map[string]any
}

func newHistoryKibana(t *testing.T, docs []doc) *historyKibana {
	t.Helper()
	h := &historyKibana{idx: &fakeIndex{docs: docs, status: http.StatusOK}}
	h.srv = httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *historyKibana) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Params struct {
			Body map[string]any `json:"body"`
		} `json:"params"`
	}
	_ = json.Unmarshal(raw, &req)
	aggs, ok := req.Params.Body["aggs"].(map[string]any)
	if !ok {
		r.Body = io.NopCloser(bytes.NewReader(raw))
		h.idx.serve(w, r)
		return
	}
	h.idx.mu.Lock()
	h.idx.bodies = append(h.idx.bodies, req.Params.Body)
	h.aggs = append(h.aggs, req.Params.Body)
	h.idx.mu.Unlock()
	out := map[string]any{}
	for name, a := range aggs {
		buckets := map[string]any{}
		for bname, clause := range a.(map[string]any)["filters"].(map[string]any)["filters"].(map[string]any) {
			filter := append(append([]any(nil), topFilter(req.Params.Body)...), clause)
			n := 0
			for _, d := range h.idx.docs {
				if matchesFilters(d, filter) {
					n++
				}
			}
			buckets[bname] = map[string]any{"doc_count": n}
		}
		out[name] = map[string]any{"buckets": buckets}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"rawResponse": map[string]any{"aggregations": out}})
}

func historyConfig(t *testing.T, url string) *Config {
	t.Helper()
	y := fmt.Sprintf(`sources:
  - type: kibana
    url: %s
    api_key_env: JB_HISTORY_KEY
    index: logs-web
    filter:
      - match_phrase: {field: path, value: /admin/}
    key_match: {field: message, mode: phrase}
detectors:
  - type: newkey
    key_field: client_ip
    path_field: path
    sensitive_paths: [/admin/]
    min_hits: 3
    history:
      lookback: 168h
      min_events: 50
      max_candidates: 50
`, url)
	p := filepath.Join(t.TempDir(), "history.yaml")
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// historyDocs: 3 sensitive requests from the suspect in the window, and `earlier` events
// of any kind in the days before it. The earlier ones are on a path the source filter
// drops, so only an unfiltered count can see them.
func historyDocs(suspect string, earlier int) []doc {
	win := searchNow.Add(-time.Hour)
	var docs []doc
	for i := 0; i < 3; i++ {
		docs = append(docs, webDoc(win.Add(time.Duration(i+1)*time.Minute), "curl/8.4.0", "/admin/export", 200, suspect, "GET /admin/export from "+suspect))
	}
	for i := 0; i < earlier; i++ {
		docs = append(docs, webDoc(searchNow.Add(-48*time.Hour).Add(time.Duration(i)*time.Minute), "Mozilla/5.0", "/home", 200, suspect, "GET /home from "+suspect))
	}
	// Unrelated traffic keeps the index alive.
	docs = append(docs, webDoc(searchNow.Add(-72*time.Hour), "Mozilla/5.0", "/home", 200, "203.0.113.9", "GET /home from 203.0.113.9"))
	return docs
}

func huntHistory(t *testing.T, earlier int) (*Result, *historyKibana, error) {
	t.Helper()
	k := newHistoryKibana(t, historyDocs("192.0.2.50", earlier))
	res, err := Hunt(t.Context(), historyConfig(t, k.srv.URL), HuntOptions{
		Window: time.Hour, NoStore: true,
		Env: func(string) (string, bool) { return "k", true },
		Now: func() time.Time { return searchNow },
	})
	return res, k, err
}

func TestHuntHistoryReproducesTheDownstreamRule(t *testing.T) {
	// 49 earlier events of any kind: new. 50: known. Synthetic data only.
	res, k, err := huntHistory(t, 49)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete() || len(res.Findings) != 1 {
		t.Fatalf("49 earlier: complete %v findings %+v detectors %+v", res.Complete(), res.Findings, res.Detectors)
	}
	d := res.Findings[0].Detail
	if d["history_count"] != float64(49) && d["history_count"] != int64(49) {
		t.Errorf("history_count = %#v", d["history_count"])
	}
	if d["history_mode"] != "phrase" || d["history_min_events"] == nil {
		t.Errorf("detail = %v", d)
	}
	if len(k.aggs) != 1 {
		t.Errorf("%d aggregation requests, want one for the one index", len(k.aggs))
	}
	if strings.Contains(fmt.Sprint(k.aggs[0]), "/admin/") {
		t.Error("the source filter reached the history count")
	}

	res, _, err = huntHistory(t, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete() || len(res.Findings) != 0 {
		t.Fatalf("50 earlier: complete %v findings %+v", res.Complete(), res.Findings)
	}
}

func TestHuntHistoryIsIncompleteNotQuietWhenKibanaFailsTheProbe(t *testing.T) {
	k := newHistoryKibana(t, historyDocs("192.0.2.50", 10))
	// Fail only the aggregation: fetches succeed, the history count does not.
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if bytes.Contains(raw, []byte(`"aggs"`)) {
			http.Error(w, "boom 192.0.2.50", http.StatusBadGateway)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		k.serve(w, r)
	}))
	t.Cleanup(failing.Close)
	res, err := Hunt(t.Context(), historyConfig(t, failing.URL), HuntOptions{
		Window: time.Hour, NoStore: true,
		Env: func(string) (string, bool) { return "k", true },
		Now: func() time.Time { return searchNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() {
		t.Fatal("a failed history probe left the hunt complete: that reads as quiet")
	}
	var msg string
	for _, d := range res.Detectors {
		if d.Err != nil {
			msg = d.Err.Error()
		}
	}
	if !strings.Contains(msg, "1 candidate(s) not judged") || strings.Contains(msg, "192.0.2.50") {
		t.Errorf("detector error = %q", msg)
	}
}

// Two sources on one cluster with different key_match settings and time fields are two
// history requests, each carrying its own field, mode and time field (not the first
// source's).
func TestHuntHistorySendsEachGroupItsOwnSettings(t *testing.T) {
	k := newHistoryKibana(t, historyDocs("192.0.2.50", 10))
	y := fmt.Sprintf(`sources:
  - type: kibana
    url: %[1]s
    api_key_env: JB_HISTORY_KEY
    index: logs-web
    key_match: {field: message, mode: phrase}
  - type: kibana
    url: %[1]s
    api_key_env: JB_HISTORY_KEY
    index: logs-app
    time_field: event.created
    key_match: {field: client_ip, mode: term}
detectors:
  - type: newkey
    key_field: client_ip
    path_field: path
    sensitive_paths: [/admin/]
    min_hits: 3
    history:
      lookback: 168h
      min_events: 50
      max_candidates: 50
`, k.srv.URL)
	p := filepath.Join(t.TempDir(), "two.yaml")
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Hunt(t.Context(), cfg, HuntOptions{
		Window: time.Hour, NoStore: true,
		Env: func(string) (string, bool) { return "k", true },
		Now: func() time.Time { return searchNow },
	}); err != nil {
		t.Fatal(err)
	}
	var phrase, term bool
	for _, a := range k.aggs {
		s := fmt.Sprint(a)
		switch {
		case strings.Contains(s, "match_phrase:map[message:") && strings.Contains(s, "@timestamp"):
			phrase = true
		case strings.Contains(s, "term:map[client_ip:") && strings.Contains(s, "event.created") && !strings.Contains(s, "@timestamp"):
			term = true
		}
	}
	if len(k.aggs) != 2 || !phrase || !term {
		t.Errorf("%d aggregation requests (phrase on message %v, term on client_ip %v): %v", len(k.aggs), phrase, term, k.aggs)
	}
}
