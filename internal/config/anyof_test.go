package config

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/kibana"
	"github.com/iksnerd/json-bourne/internal/core"
)

func buildKibana(t *testing.T, lines string) *kibana.Source {
	t.Helper()
	f, err := Parse([]byte(withKibanaLines(lines)))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	return rt.Sources[0].(*kibana.Source)
}

func TestAnyOfCompilesToShouldNestedInTheAND(t *testing.T) {
	src := buildKibana(t, `    filter:
      - term: {field: status, value: "200"}
      - any_of:
          - match_phrase: {field: path, value: /oauth/device/code}
          - term: {field: "path.keyword", value: /oauth/token}
`)
	got, _ := json.Marshal(src.Query)
	want := `{"bool":{"filter":[{"term":{"status":"200"}},{"bool":{"minimum_should_match":1,"should":[{"match_phrase":{"path":"/oauth/device/code"}},{"term":{"path.keyword":"/oauth/token"}}]}}]}}`
	if string(got) != want {
		t.Fatalf("query = %s\nwant    %s", got, want)
	}
}

// --search still ANDs on top of an any_of: the term is a sibling of the should-bool in
// the same filter list, never inside it, so it narrows every alternative.
func TestAnyOfWithSearchStaysANDed(t *testing.T) {
	f, err := Parse([]byte(withKibanaLines(`    filter:
      - any_of:
          - match_phrase: {field: path, value: /a}
          - match_phrase: {field: path, value: /b}
`)))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.WithSearch([]string{"needle"}, ""); err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(rt.Sources[0].(*kibana.Source).Query)
	want := `{"bool":{"filter":[{"match_phrase":{"message":"needle"}},{"bool":{"minimum_should_match":1,"should":[{"match_phrase":{"path":"/a"}},{"match_phrase":{"path":"/b"}}]}}]}}`
	if string(got) != want {
		t.Fatalf("query = %s\nwant    %s", got, want)
	}
}

func anyOfN(n int) string {
	var b strings.Builder
	b.WriteString("    filter:\n      - any_of:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "          - term: {field: f, value: v%d}\n", i)
	}
	return b.String()
}

func TestAnyOfBoundsAndShapeRejectedAtLoad(t *testing.T) {
	five := "    filter:\n" + strings.Repeat("      - any_of:\n"+strings.Repeat("          - term: {field: f, value: v}\n", 16), 5)
	for name, bad := range map[string]string{
		"one member":         anyOfN(1),
		"empty any_of":       "    filter:\n      - any_of: []\n",
		"seventeen members":  anyOfN(17),
		"nested any_of":      "    filter:\n      - any_of:\n          - any_of:\n              - term: {field: f, value: a}\n              - term: {field: f, value: b}\n          - term: {field: f, value: c}\n",
		"member with both":   "    filter:\n      - any_of:\n          - term: {field: f, value: a}\n            match_phrase: {field: f, value: a}\n          - term: {field: f, value: b}\n",
		"empty member":       "    filter:\n      - any_of:\n          - {}\n          - term: {field: f, value: b}\n",
		"bad member field":   "    filter:\n      - any_of:\n          - term: {field: \"a b\", value: a}\n          - term: {field: f, value: b}\n",
		"empty member value": "    filter:\n      - any_of:\n          - term: {field: f, value: \"\"}\n          - term: {field: f, value: b}\n",
		"long member value":  "    filter:\n      - any_of:\n          - term: {field: f, value: \"" + strings.Repeat("x", 513) + "\"}\n          - term: {field: f, value: b}\n",
		"newline in value":   "    filter:\n      - any_of:\n          - term: {field: f, value: \"a\\nb\"}\n          - term: {field: f, value: b}\n",
		"escape in value":    "    filter:\n      - any_of:\n          - term: {field: f, value: \"a\\u001bb\"}\n          - term: {field: f, value: b}\n",
		"any_of and term":    "    filter:\n      - term: {field: f, value: a}\n        any_of:\n          - term: {field: f, value: a}\n          - term: {field: f, value: b}\n",
		"unknown member key": "    filter:\n      - any_of:\n          - term: {field: f, value: a, boost: 2}\n          - term: {field: f, value: b}\n",
		"too many leaves":    five, // 5 entries (under 8) but 80 match clauses (over 64)
		"nine entries":       "    filter:\n" + strings.Repeat("      - any_of:\n          - term: {field: f, value: a}\n          - term: {field: f, value: b}\n", 9),
	} {
		if _, err := Parse([]byte(withKibanaLines(bad))); err == nil {
			t.Errorf("%s: accepted at load", name)
		}
	}
	for name, ok := range map[string]string{"two members": anyOfN(2), "sixteen members": anyOfN(16)} {
		if _, err := Parse([]byte(withKibanaLines(ok))); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// 4 x 16 = 64 leaves is the most a filter may hold.
	if _, err := Parse([]byte(withKibanaLines("    filter:\n" + strings.Repeat("      - any_of:\n"+strings.Repeat("          - term: {field: f, value: v}\n", 16), 4)))); err != nil {
		t.Errorf("64 leaves: %v", err)
	}
}

// An any_of is one entry of the 8-clause bound that --search shares, however many members
// it has: seven any_of plus one term fits, a second term does not.
func TestAnyOfCountsAsOneClauseForSearch(t *testing.T) {
	seven := "    filter:\n" + strings.Repeat("      - any_of:\n          - term: {field: f, value: a}\n          - term: {field: f, value: b}\n", 7)
	f, err := Parse([]byte(withKibanaLines(seven)))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.WithSearch([]string{"one"}, ""); err != nil {
		t.Fatalf("7 entries + 1 term: %v", err)
	}
	if err := f.WithSearch([]string{"one", "two"}, ""); err == nil {
		t.Fatal("7 entries + 2 terms accepted, over the 8-clause bound")
	}
}

func TestAnyOfSatisfiesEmptyIsQuiet(t *testing.T) {
	cfg := withKibanaLines("    filter:\n      - any_of:\n          - term: {field: f, value: a}\n          - term: {field: f, value: b}\n")
	cfg = strings.Replace(cfg, "detectors:\n", "detectors:\n  - type: fingerprint\n    actors: [a.yaml]\n    empty_is_quiet: true\n", 1)
	if _, err := Parse([]byte(cfg)); err != nil {
		t.Fatalf("empty_is_quiet with an any_of filter: %v", err)
	}
}

// The exact bodies the server receives: the any_of reaches it as a should-bool with the
// values as JSON strings (a value full of query syntax is not interpreted), and the
// liveness probe after an empty result is still the window alone, with no filter.
func TestAnyOfRequestBodyAndLivenessProbe(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Params struct {
				Body map[string]any `json:"body"`
			} `json:"params"`
		}
		_ = json.Unmarshal(raw, &req)
		mu.Lock()
		bodies = append(bodies, req.Params.Body)
		mu.Unlock()
		total := 0
		if size, _ := req.Params.Body["size"].(float64); size == 0 {
			total = 500 // the unfiltered count: the index is alive
		}
		fmt.Fprintf(w, `{"rawResponse":{"hits":{"total":{"value":%d},"hits":[]}}}`, total)
	}))
	defer srv.Close()

	hostile := `x" OR path:* AND NOT {"match_all":{}}`
	cfg := strings.Replace(valid, "https://kibana.example.com", srv.URL, 1)
	cfg = strings.Replace(cfg, "    index: logs-auth-*\n", "    index: logs-auth-*\n    filter:\n      - any_of:\n          - match_phrase: {field: path, value: '"+strings.ReplaceAll(hostile, "'", "''")+"'}\n          - term: {field: \"path.keyword\", value: /oauth/token}\n", 1)
	f, err := Parse([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	src := rt.Sources[0]
	w := core.Window{From: time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 11, 5, 1, 0, 0, 0, time.UTC)}
	for _, err := range src.Fetch(context.Background(), w) {
		if err != nil {
			t.Fatalf("an empty filtered result on a live index must not be an error: %v", err)
		}
	}
	if len(bodies) != 2 {
		t.Fatalf("%d requests, want the filtered search and the liveness probe", len(bodies))
	}
	filter := func(b map[string]any) []any {
		return b["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)
	}
	main := filter(bodies[0])
	if len(main) != 2 { // the window, then the source's query
		t.Fatalf("filtered search filter has %d clauses: %v", len(main), main)
	}
	got, _ := json.Marshal(main[1].(map[string]any)["bool"].(map[string]any)["filter"].([]any)[0]) // the any_of, the one configured clause
	want, _ := json.Marshal(map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": []any{
		map[string]any{"match_phrase": map[string]any{"path": hostile}},
		map[string]any{"term": map[string]any{"path.keyword": "/oauth/token"}},
	}}})
	if string(got) != string(want) {
		t.Fatalf("any_of on the wire = %s\nwant            %s", got, want)
	}
	probe := filter(bodies[1])
	if bodies[1]["size"].(float64) != 0 || len(probe) != 1 {
		t.Fatalf("liveness probe = %v, want size 0 and the window range alone", bodies[1])
	}
	if b, _ := json.Marshal(bodies[1]); strings.Contains(string(b), "should") || strings.Contains(string(b), "match_phrase") {
		t.Fatalf("the liveness probe carries the filter: %s", b)
	}
}

func TestSourceNameDefaultCustomAndInvalid(t *testing.T) {
	if got := buildKibana(t, "").Name(); got != "kibana:logs-auth-*" {
		t.Errorf("default name = %q", got)
	}
	if got := buildKibana(t, "    name: auth.token-paths\n").Name(); got != "auth.token-paths" {
		t.Errorf("custom name = %q", got)
	}
	for _, bad := range []string{"A", "1a", "a/b", "a b", "-a", strings.Repeat("a", 65), "a\\u0000b", "\"\""} {
		line := "    name: \"" + bad + "\"\n"
		if bad == "\"\"" {
			line = "    name: \"\"\n" // empty means the default, accepted
			if _, err := Parse([]byte(withKibanaLines(line))); err != nil {
				t.Errorf("empty name rejected: %v", err)
			}
			continue
		}
		if _, err := Parse([]byte(withKibanaLines(line))); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
}

func twoSources(a, b string) string {
	src := func(name string) string {
		n := ""
		if name != "" {
			n = "    name: " + name + "\n"
		}
		return "  - type: kibana\n    url: https://kibana.example.com\n    api_key_env: JB_KIBANA_API_KEY\n    index: logs-auth-*\n" + n
	}
	return "sources:\n" + src(a) + src(b) + "detectors:\n  - type: authspike\n    key_field: client_ip\n    status_field: status\nstore:\n  path: /tmp/jb-test.duckdb\n"
}

func TestTwoSourcesOnOneIndexNeedDistinctNames(t *testing.T) {
	f, err := Parse([]byte(twoSources("first", "second")))
	if err != nil {
		t.Fatalf("two named sources on one index: %v", err)
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	if rt.Sources[0].Name() != "first" || rt.Sources[1].Name() != "second" {
		t.Errorf("names = %q, %q", rt.Sources[0].Name(), rt.Sources[1].Name())
	}
	for name, cfg := range map[string]string{
		"both default":       twoSources("", ""),
		"same custom name":   twoSources("same", "same"),
		"custom is default":  strings.ReplaceAll(twoSources("", "kibana:logs-auth"), "logs-auth-*", "logs-auth"),
		"default then named": strings.ReplaceAll(twoSources("kibana:logs-auth", ""), "logs-auth-*", "logs-auth"),
	} {
		_, err := Parse([]byte(cfg))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), "sources[0]") || !strings.Contains(err.Error(), "sources[1]") {
			t.Errorf("%s: error does not name both sources: %v", name, err)
		}
	}
}
