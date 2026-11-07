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
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const sourceFilterMark = "SOURCE-FILTER-MARK"

var lookbackWin = core.Window{
	From: time.Date(2025, 12, 25, 0, 0, 0, 0, time.UTC),
	To:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
}

// fakeIndex is a Kibana that records every request body and answers a filters
// aggregation from a table of counts per key.
type fakeIndex struct {
	mu     sync.Mutex
	bodies []string
	urls   []string
	index  []string
	counts map[string]int64
	total  int64
	status int
	reply  string // when set, sent verbatim instead of the computed answer
	delay  time.Duration
}

func (f *fakeIndex) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.bodies = append(f.bodies, string(raw))
		f.urls = append(f.urls, r.URL.String())
		f.mu.Unlock()
		if f.delay > 0 {
			time.Sleep(f.delay)
		}
		if f.status != 0 {
			w.WriteHeader(f.status)
			_, _ = w.Write(raw) // a proxy that reflects the request
			return
		}
		if f.reply != "" {
			_, _ = io.WriteString(w, f.reply)
			return
		}
		var req struct {
			Params struct {
				Index string         `json:"index"`
				Body  map[string]any `json:"body"`
			} `json:"params"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Errorf("request is not JSON: %v", err)
		}
		f.mu.Lock()
		f.index = append(f.index, req.Params.Index)
		f.mu.Unlock()
		resp := map[string]any{"hits": map[string]any{"total": map[string]any{"value": f.total}}}
		if aggs, ok := req.Params.Body["aggs"].(map[string]any); ok {
			out := map[string]any{}
			for name, a := range aggs {
				buckets := map[string]any{}
				filters := a.(map[string]any)["filters"].(map[string]any)["filters"].(map[string]any)
				for bname, clause := range filters {
					var val string
					for _, inner := range clause.(map[string]any) { // match_phrase or term
						for _, v := range inner.(map[string]any) {
							val = v.(string)
						}
					}
					buckets[bname] = map[string]any{"doc_count": f.counts[val]}
				}
				out[name] = map[string]any{"buckets": buckets}
			}
			resp["aggregations"] = out
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rawResponse": resp})
	}
}

func newKeySource(t *testing.T, f *fakeIndex, mode string) (*Source, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	return &Source{
		Client: New(srv.URL, testKey), Index: "logs-example", TimeField: "ts",
		Query:    map[string]any{"bool": map[string]any{"filter": []any{map[string]any{"match_phrase": map[string]any{"path": sourceFilterMark}}}}},
		KeyMatch: &KeyMatch{Field: "message", Mode: mode},
	}, srv
}

func decodeBody(t *testing.T, raw string) map[string]any {
	t.Helper()
	var req struct {
		Params struct {
			Body map[string]any `json:"body"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatal(err)
	}
	return req.Params.Body
}

func TestCountKeysSendsOneRequestWithTheLookbackRangeAndNoSourceFilter(t *testing.T) {
	for _, tc := range []struct{ mode, clause string }{{ModePhrase, "match_phrase"}, {ModeTerm, "term"}} {
		t.Run(tc.mode, func(t *testing.T) {
			f := &fakeIndex{counts: map[string]int64{"192.0.2.7": 12, "198.51.100.9": 3}}
			s, _ := newKeySource(t, f, tc.mode)
			got, err := s.CountKeys(context.Background(), []string{"192.0.2.7", "198.51.100.9", "203.0.113.1"}, lookbackWin)
			if err != nil {
				t.Fatal(err)
			}
			if got["192.0.2.7"] != 12 || got["198.51.100.9"] != 3 || got["203.0.113.1"] != 0 || len(got) != 3 {
				t.Errorf("counts = %v", got)
			}
			if len(f.bodies) != 1 {
				t.Fatalf("%d requests, want exactly one for all keys", len(f.bodies))
			}
			raw := f.bodies[0]
			if strings.Contains(raw, sourceFilterMark) {
				t.Error("the source's own filter was applied to the history count")
			}
			body := decodeBody(t, raw)
			if body["size"] != float64(0) {
				t.Errorf("size = %v, want 0", body["size"])
			}
			rng := body["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)
			if len(rng) != 1 {
				t.Fatalf("filter has %d clauses, want only the range", len(rng))
			}
			r := rng[0].(map[string]any)["range"].(map[string]any)["ts"].(map[string]any)
			if r["gte"] != "2025-12-25T00:00:00Z" || r["lt"] != "2026-01-01T00:00:00Z" {
				t.Errorf("range = %v, want the lookback interval on the time field", r)
			}
			aggs := body["aggs"].(map[string]any)
			if len(aggs) != 1 {
				t.Fatalf("aggs = %v", aggs)
			}
			for _, a := range aggs {
				fl := a.(map[string]any)["filters"].(map[string]any)["filters"].(map[string]any)
				if len(fl) != 3 {
					t.Fatalf("%d buckets, want one per key", len(fl))
				}
				seen := map[string]bool{}
				for name, c := range fl {
					if strings.Contains(name, "192.0.2") || strings.Contains(name, "198.51") {
						t.Errorf("bucket name %q carries a key", name)
					}
					inner := c.(map[string]any)[tc.clause].(map[string]any)
					v, ok := inner["message"].(string)
					if !ok || len(inner) != 1 {
						t.Fatalf("clause = %v, want %s on key_match.field with a JSON string value", c, tc.clause)
					}
					seen[v] = true
				}
				if !seen["192.0.2.7"] || !seen["198.51.100.9"] || !seen["203.0.113.1"] {
					t.Errorf("values %v", seen)
				}
			}
			if f.index[0] != "logs-example" {
				t.Errorf("index %q", f.index[0])
			}
			// The key is data in the body only: never in the path or query string.
			if strings.Contains(f.urls[0], "192.0.2") {
				t.Errorf("a key reached the URL: %s", f.urls[0])
			}
		})
	}
}

func TestCountKeysWithoutKeysSendsNothing(t *testing.T) {
	f := &fakeIndex{}
	s, _ := newKeySource(t, f, ModePhrase)
	got, err := s.CountKeys(context.Background(), nil, lookbackWin)
	if err != nil || len(got) != 0 || len(f.bodies) != 0 {
		t.Fatalf("got %v err %v requests %d", got, err, len(f.bodies))
	}
}

func TestCountKeysCountsADuplicateKeyOnce(t *testing.T) {
	f := &fakeIndex{counts: map[string]int64{"192.0.2.7": 4}}
	s, _ := newKeySource(t, f, ModeTerm)
	got, err := s.CountKeys(context.Background(), []string{"192.0.2.7", "192.0.2.7"}, lookbackWin)
	if err != nil || got["192.0.2.7"] != 4 {
		t.Fatalf("got %v err %v", got, err)
	}
	fl := decodeBody(t, f.bodies[0])["aggs"].(map[string]any)
	for _, a := range fl {
		if n := len(a.(map[string]any)["filters"].(map[string]any)["filters"].(map[string]any)); n != 1 {
			t.Errorf("%d buckets for one distinct key", n)
		}
	}
}

func TestCountAllIsTheSameRangeWithNoKeyClause(t *testing.T) {
	f := &fakeIndex{total: 8123}
	s, _ := newKeySource(t, f, ModePhrase)
	n, err := s.CountAll(context.Background(), lookbackWin)
	if err != nil || n != 8123 {
		t.Fatalf("n %d err %v", n, err)
	}
	if len(f.bodies) != 1 || strings.Contains(f.bodies[0], sourceFilterMark) || strings.Contains(f.bodies[0], "message") {
		t.Fatalf("bodies %v: want one request, no source filter, no key clause", f.bodies)
	}
	body := decodeBody(t, f.bodies[0])
	if body["size"] != float64(0) || body["aggs"] != nil {
		t.Errorf("body = %v", body)
	}
	r := body["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)[0].(map[string]any)["range"].(map[string]any)["ts"].(map[string]any)
	if r["gte"] != "2025-12-25T00:00:00Z" || r["lt"] != "2026-01-01T00:00:00Z" {
		t.Errorf("range = %v", r)
	}
}

func TestCountKeysRefusesUnsafeKeysBeforeAnyRequest(t *testing.T) {
	bad := []string{
		"", "192.0.2.7 OR *", `192.0.2.7"`, "192.0.2.7*", "a b", "x\ny", `back\slash`, "q?", "(a)", "a/b", "a,b",
		"192.0.2.1, 198.51.100.2", // a forwarded-for chain
		"ü", "ok.example.com:80\x00", strings.Repeat("a", 257),
	}
	for _, k := range bad {
		f := &fakeIndex{}
		s, _ := newKeySource(t, f, ModePhrase)
		_, err := s.CountKeys(context.Background(), []string{"192.0.2.7", k}, lookbackWin)
		if err == nil {
			t.Errorf("key %q was accepted", k)
		}
		if len(f.bodies) != 0 {
			t.Errorf("key %q: %d requests were sent, want none", k, len(f.bodies))
		}
		if err != nil && k != "" && strings.Contains(err.Error(), k) {
			t.Errorf("the refusal for %q echoes the key: %v", k, err)
		}
	}
	// The limit itself, IPv6 and an address:port pass the character set. A phrase on an
	// analysed field splits an IPv6 address into tokens, so it can over-count; that is the
	// documented direction (quiet, never a false alarm).
	for _, k := range []string{strings.Repeat("a", 256), "2001:db8::1", "198.51.100.9:443", "user@example.com", "a_b-c.d"} {
		f := &fakeIndex{}
		s, _ := newKeySource(t, f, ModePhrase)
		if _, err := s.CountKeys(context.Background(), []string{k}, lookbackWin); err != nil {
			t.Errorf("key %q refused: %v", k, err)
		}
	}
}

func TestCountKeysNeedsKeyMatch(t *testing.T) {
	for name, km := range map[string]*KeyMatch{"none": nil, "no mode": {Field: "message"}, "bad mode": {Field: "message", Mode: "regex"}, "no field": {Mode: ModeTerm}} {
		f := &fakeIndex{}
		s, _ := newKeySource(t, f, ModeTerm)
		s.KeyMatch = km
		if _, err := s.CountKeys(context.Background(), []string{"192.0.2.7"}, lookbackWin); err == nil {
			t.Errorf("%s: CountKeys ran", name)
		}
		if _, err := s.CountAll(context.Background(), lookbackWin); err == nil && km == nil {
			t.Errorf("%s: CountAll ran without key_match", name)
		}
		if len(f.bodies) != 0 {
			t.Errorf("%s: %d requests", name, len(f.bodies))
		}
	}
}

// Every error path is forced and none may carry the key, the API key or a reflected body.
func TestKeyCountErrorsNeverContainTheKey(t *testing.T) {
	const key = "192.0.2.77"
	type tc struct {
		name string
		f    *fakeIndex
		prep func(*Source)
	}
	cases := []tc{
		{"non-200 that reflects the request", &fakeIndex{status: http.StatusBadGateway}, nil},
		{"unauthorised", &fakeIndex{status: http.StatusUnauthorized}, nil},
		{"not JSON", &fakeIndex{reply: "<html>" + key + "</html>"}, nil},
		{"no aggregations", &fakeIndex{reply: `{"rawResponse":{"hits":{"total":{"value":3}}}}`}, nil},
		{"aggregation without the bucket", &fakeIndex{reply: `{"rawResponse":{"aggregations":{"keys":{"buckets":{}}}}}`}, nil},
		{"bucket without a count", &fakeIndex{reply: `{"rawResponse":{"aggregations":{"keys":{"buckets":{"k0":{"doc_count":"many"}}}}}}`}, nil},
		{"negative count", &fakeIndex{reply: `{"rawResponse":{"aggregations":{"keys":{"buckets":{"k0":{"doc_count":-1}}}}}}`}, nil},
		{"timeout", &fakeIndex{delay: 300 * time.Millisecond}, func(s *Source) { s.Client.HTTP = &http.Client{Timeout: 40 * time.Millisecond} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newKeySource(t, c.f, ModePhrase)
			if c.prep != nil {
				c.prep(s)
			}
			// The aggregation name is the source's; make the canned replies match it.
			_, err := s.CountKeys(context.Background(), []string{key}, lookbackWin)
			if err == nil {
				t.Fatal("no error")
			}
			if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), testKey) {
				t.Errorf("error carries a key: %v", err)
			}
			_, err = s.CountAll(context.Background(), lookbackWin)
			if c.name != "no aggregations" && c.name != "aggregation without the bucket" && c.name != "bucket without a count" && c.name != "negative count" && err == nil {
				t.Error("CountAll: no error")
			}
			if err != nil && (strings.Contains(err.Error(), key) || strings.Contains(err.Error(), testKey)) {
				t.Errorf("CountAll error carries a key: %v", err)
			}
		})
	}
}

func TestKeyCountErrorsKeepTheirKind(t *testing.T) {
	f := &fakeIndex{status: http.StatusServiceUnavailable}
	s, _ := newKeySource(t, f, ModePhrase)
	_, err := s.CountKeys(context.Background(), []string{"192.0.2.7"}, lookbackWin)
	if !errors.Is(err, core.ErrSourceUnavailable) {
		t.Errorf("err = %v, want ErrSourceUnavailable", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.CountAll(ctx, lookbackWin); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestSourceImplementsTheKeyCounterPort(t *testing.T) {
	var _ core.KeyCounter = (*Source)(nil)
	s := &Source{Client: New("https://kibana.example.com", testKey), Index: "logs-a", KeyMatch: &KeyMatch{Field: "message", Mode: ModeTerm}}
	if s.KeyMode() != "term" || s.IndexName() != "logs-a" {
		t.Errorf("mode %q index %q", s.KeyMode(), s.IndexName())
	}
	_ = fmt.Sprint(s)
}

// CountingIndices sends the union of the expressions as one comma-joined target, once
// per call, so Elasticsearch counts a document that matches both a single time.
func TestCountingIndicesSendsTheUnionAsOneTarget(t *testing.T) {
	f := &fakeIndex{counts: map[string]int64{"192.0.2.7": 30}, total: 99}
	s, _ := newKeySource(t, f, ModeTerm)
	kc, err := s.CountingIndices([]string{"logs-*", "logs-web-*", "logs-*"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := kc.CountKeys(context.Background(), []string{"192.0.2.7"}, lookbackWin)
	if err != nil || got["192.0.2.7"] != 30 {
		t.Fatalf("counts %v err %v", got, err)
	}
	if n, err := kc.CountAll(context.Background(), lookbackWin); err != nil || n != 99 {
		t.Fatalf("CountAll = %d, %v", n, err)
	}
	if len(f.index) != 2 || f.index[0] != "logs-*,logs-web-*" || f.index[1] != "logs-*,logs-web-*" {
		t.Errorf("targets = %q, want the two distinct expressions joined once, one request per call", f.index)
	}
	if strings.Contains(f.bodies[0], sourceFilterMark) {
		t.Error("the source's own filter was applied")
	}
}

func TestCountingIndicesRefusesAnExpressionThatChangesTheTarget(t *testing.T) {
	s, _ := newKeySource(t, &fakeIndex{}, ModeTerm)
	for _, bad := range []string{"", "a,b", "a b", "a\n"} {
		if _, err := s.CountingIndices([]string{"logs-*", bad}); err == nil {
			t.Errorf("expression %q accepted", bad)
		}
	}
	if _, err := s.CountingIndices(nil); err == nil {
		t.Error("no expression accepted")
	}
}
