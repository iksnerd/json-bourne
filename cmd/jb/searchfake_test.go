package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// doc is one document of the fake index.
type doc struct {
	at     time.Time
	fields map[string]any
}

// fakeIndex answers like Kibana for an index of docs: it applies the time range, the
// match_phrase and term clauses it is sent (a phrase matches as a case-insensitive
// substring of the field), pages by the timestamp cursor, and answers a size-0 request
// with the count alone. It records every request body, so a test can see exactly what
// reached the server.
type fakeIndex struct {
	mu     sync.Mutex
	docs   []doc
	status int // non-200 answers every request with it
	bodies []map[string]any
	srv    *httptest.Server
}

func newFakeIndex(t *testing.T, docs []doc) *fakeIndex {
	t.Helper()
	f := &fakeIndex{docs: docs, status: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIndex) requests() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.bodies...)
}

func (f *fakeIndex) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Params struct {
			Body map[string]any `json:"body"`
		} `json:"params"`
	}
	_ = json.Unmarshal(raw, &req)
	f.mu.Lock()
	f.bodies = append(f.bodies, req.Params.Body)
	status := f.status
	f.mu.Unlock()
	if status != http.StatusOK {
		http.Error(w, "boom", status)
		return
	}
	body := req.Params.Body
	size, _ := body["size"].(float64)
	// _id is the document's position in the index, so it is the same whichever filter
	// returns it, as in a real index.
	type idoc struct {
		doc
		n int
	}
	var matched []idoc
	for n, d := range f.docs {
		if matches(d, body) {
			matched = append(matched, idoc{d, n})
		}
	}
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].at.Before(matched[j].at) })
	var hits []map[string]any
	for _, d := range matched {
		if len(hits) >= int(size) {
			break
		}
		src := map[string]any{"@timestamp": d.at.Format(time.RFC3339Nano)}
		for k, v := range d.fields {
			src[k] = v
		}
		hits = append(hits, map[string]any{
			"_id": fmt.Sprintf("d%d", d.n), "_index": "i", "_source": src,
			"sort": []any{d.at.UnixMilli()},
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"rawResponse": map[string]any{
		"hits": map[string]any{"total": map[string]any{"value": len(matched)}, "hits": hits},
	}})
}

func matches(d doc, body map[string]any) bool {
	return matchesFilters(d, filterClauses(body))
}

func matchesFilters(d doc, filters []any) bool {
	for _, c := range filters {
		cm, _ := c.(map[string]any)
		for kind, v := range cm {
			vm, _ := v.(map[string]any)
			switch kind {
			case "bool":
				inner, _ := vm["filter"].([]any)
				if !matchesFilters(d, inner) {
					return false
				}
				if should, ok := vm["should"].([]any); ok {
					// minimum_should_match 1: at least one alternative must match.
					any1 := false
					for _, alt := range should {
						if matchesFilters(d, []any{alt}) {
							any1 = true
						}
					}
					if !any1 {
						return false
					}
				}
			case "range":
				rng, _ := vm["@timestamp"].(map[string]any)
				if gte, ok := rng["gte"]; ok {
					switch g := gte.(type) {
					case string:
						if t, err := time.Parse(time.RFC3339Nano, g); err == nil && d.at.Before(t) {
							return false
						}
					case float64:
						if d.at.UnixMilli() < int64(g) {
							return false
						}
					}
				}
				if lt, ok := rng["lt"].(string); ok {
					if t, err := time.Parse(time.RFC3339Nano, lt); err == nil && !d.at.Before(t) {
						return false
					}
				}
			case "match_phrase":
				for field, want := range vm {
					got := strings.ToLower(fmt.Sprint(d.fields[field]))
					if !strings.Contains(got, strings.ToLower(fmt.Sprint(want))) {
						return false
					}
				}
			case "term":
				for field, want := range vm {
					if fmt.Sprint(d.fields[field]) != fmt.Sprint(want) {
						return false
					}
				}
			}
		}
	}
	return true
}

// topFilter returns the bool.filter list of a recorded request body.
func topFilter(body map[string]any) []any {
	q, _ := body["query"].(map[string]any)
	b, _ := q["bool"].(map[string]any)
	f, _ := b["filter"].([]any)
	return f
}

// filterClauses returns the leaf clauses of a request body's filter: the time range and
// every phrase or term, with the nested bool the source builds flattened away.
func filterClauses(body map[string]any) []any {
	var out []any
	var walk func(fs []any)
	walk = func(fs []any) {
		for _, c := range fs {
			cm, _ := c.(map[string]any)
			if inner, ok := cm["bool"].(map[string]any); ok {
				if _, has := inner["should"]; has {
					out = append(out, cm) // an any_of clause stays whole
					continue
				}
				in, _ := inner["filter"].([]any)
				walk(in)
				continue
			}
			out = append(out, c)
		}
	}
	walk(topFilter(body))
	return out
}

// webDoc is one synthetic web request. message is the log line a --search term is looked
// for in; the canonical fields are what the detectors read.
func webDoc(at time.Time, ua, path string, status int, ip, message string) doc {
	return doc{at: at, fields: map[string]any{
		"user_agent": ua, "path": path, "status": status, "client_ip": ip, "method": "GET", "message": message,
	}}
}
