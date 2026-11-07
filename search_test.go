package jb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var searchNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func searchDocs() []doc {
	cur := searchNow.Add(-time.Hour)
	return []doc{
		webDoc(cur.Add(1*time.Minute), "OtherClient/1.0", "/login", 200, "203.0.113.10", "GET /login from 203.0.113.10"),
		webDoc(cur.Add(2*time.Minute), "OtherClient/1.0", "/login", 200, "203.0.113.11", "GET /login needle-token from 203.0.113.11"),
		webDoc(cur.Add(3*time.Minute), "OtherClient/1.0", "/home", 200, "203.0.113.12", "GET /home needle-token from 203.0.113.12"),
		webDoc(cur.Add(4*time.Minute), "OtherClient/1.0", "/home", 200, "203.0.113.13", "GET /home from 203.0.113.13"),
	}
}

// searchCase is the example case with its fingerprint config pointed at idx.
func searchCase(t *testing.T, idx *fakeIndex) string {
	t.Helper()
	dir := copyCase(t)
	p := filepath.Join(dir, "config", "fingerprint.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "https://kibana.example.com") {
		t.Fatal("fingerprint.yaml does not name the placeholder host")
	}
	if err := os.WriteFile(p, []byte(strings.ReplaceAll(string(b), "https://kibana.example.com", idx.srv.URL)), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func searchOpts(search ...string) CaseHuntOptions {
	return CaseHuntOptions{Config: "config/fingerprint.yaml", HuntOptions: HuntOptions{
		Window: time.Hour, Search: search, NoStore: true,
		Env: func(string) (string, bool) { return "k", true },
		Now: func() time.Time { return searchNow },
	}}
}

func TestHuntCaseSearchNarrowsOnTheServer(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	res, err := HuntCase(t.Context(), dir, searchOpts("needle-token"))
	if res == nil {
		t.Fatalf("no result: %v", err)
	}
	if !strings.HasPrefix(res.Run, "search-") {
		t.Errorf("run = %q, want a search- run", res.Run)
	}
	if len(res.Sources) != 1 || res.Sources[0].Events != 2 {
		t.Fatalf("sources = %+v, want the 2 matching events", res.Sources)
	}
	if got := res.Search; len(got) != 1 || got[0] != "needle-token" {
		t.Errorf("Result.Search = %v", got)
	}
	if res.SearchAbsent() {
		t.Error("a matching search reads as absent")
	}
	var sawTerm bool
	for _, r := range idx.requests() {
		for _, c := range filterClauses(r) {
			if m, ok := c.(map[string]any)["match_phrase"].(map[string]any); ok && m["message"] == "needle-token" {
				sawTerm = true
			}
		}
	}
	if !sawTerm {
		t.Error("the term never reached the server as a match_phrase clause")
	}
}

func TestHuntCaseWithoutSearchHasNoSearchResult(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	res, _ := HuntCase(t.Context(), searchCase(t, idx), searchOpts())
	if res == nil || res.Search != nil || res.SearchAbsent() || strings.HasPrefix(res.Run, "search-") {
		t.Fatalf("result = %+v", res)
	}
}

func TestHuntCaseSearchAbsentTermIsAnAnswer(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	res, err := HuntCase(t.Context(), searchCase(t, idx), searchOpts("no-such-term"))
	if err != nil || res == nil {
		t.Fatalf("err = %v", err)
	}
	if !res.SearchAbsent() {
		t.Fatalf("absent term not reported: %+v", res.Sources)
	}
	if s := res.Sources[0]; !s.IndexAlive || s.IndexDocs != 4 || s.Outcome() != "no match; index alive" {
		t.Errorf("source = %+v", s)
	}
}

func TestHuntCaseSearchOnAnEmptyIndexIsNotAbsent(t *testing.T) {
	idx := newFakeIndex(t, nil)
	res, _ := HuntCase(t.Context(), searchCase(t, idx), searchOpts("needle-token"))
	if res == nil || res.SearchAbsent() {
		t.Fatalf("an empty index reads as an absent term: %+v", res)
	}
}

func TestHuntSearchDoesNotChangeTheCallersConfig(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	cfg, err := LoadConfig(filepath.Join(dir, "config", "fingerprint.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	o := searchOpts("needle-token").HuntOptions
	if _, err := Hunt(t.Context(), cfg, o); err != nil {
		t.Logf("hunt: %v", err)
	}
	if len(cfg.f.Search()) != 0 {
		t.Fatalf("Hunt left the search on the caller's config: %v", cfg.f.Search())
	}
}

func TestHuntSearchRefusalsAreUsageErrorsAndSendNothing(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	for name, o := range map[string]HuntOptions{
		"newline":              {Search: []string{"a\nb"}},
		"nul":                  {Search: []string{"a\x00b"}},
		"escape":               {Search: []string{"\x1b[2J"}},
		"empty":                {Search: []string{""}},
		"blank":                {Search: []string{"   "}},
		"too long":             {Search: []string{strings.Repeat("a", 257)}},
		"too many":             {Search: []string{"a", "b", "c", "d", "e"}},
		"field without search": {SearchField: "path"},
		"bad field":            {Search: []string{"a"}, SearchField: "a b"},
	} {
		t.Run(name, func(t *testing.T) {
			opts := searchOpts()
			opts.HuntOptions.Search, opts.HuntOptions.SearchField = o.Search, o.SearchField
			res, err := HuntCase(t.Context(), dir, opts)
			if !IsUsage(err) {
				t.Fatalf("err = %v, want a UsageError", err)
			}
			if res != nil {
				t.Errorf("a refused search returned a result: %+v", res)
			}
		})
	}
	if n := len(idx.requests()); n != 0 {
		t.Fatalf("%d request(s) reached the server for refused input", n)
	}
}

func TestHuntSearchFieldOverrideReachesTheServer(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	opts := searchOpts("/home")
	opts.HuntOptions.SearchField = "path"
	res, _ := HuntCase(t.Context(), searchCase(t, idx), opts)
	if res == nil || res.Sources[0].Events != 2 {
		t.Fatalf("result = %+v, want the 2 /home events", res)
	}
}
