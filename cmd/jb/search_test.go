package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// searchCase builds a case whose fingerprint config points at idx, in a git work tree
// so the evidence guard passes, with a one hour default window.
func searchCase(t *testing.T, idx *fakeIndex) string {
	t.Helper()
	dir := copyExampleCase(t, idx.srv.URL)
	gitInit(t, dir)
	editFile(t, filepath.Join(dir, fpConfigRel), "https://kibana.example.com", idx.srv.URL)
	editFile(t, filepath.Join(dir, "case.yaml"), "default: 24h", "default: 1h")
	return dir
}

func searchDocs() []doc {
	cur := fixedNow.Add(-time.Hour)
	return []doc{
		webDoc(cur.Add(1*time.Minute), "OtherClient/1.0", "/login", 200, "203.0.113.10", "GET /login from 203.0.113.10"),
		webDoc(cur.Add(2*time.Minute), exampleUA, "/login", 200, "203.0.113.11", "GET /login needle-token from 203.0.113.11"),
		webDoc(cur.Add(3*time.Minute), "OtherClient/1.0", "/home", 200, "203.0.113.12", "GET /home needle-token from 203.0.113.12"),
		webDoc(cur.Add(4*time.Minute), "OtherClient/1.0", "/home", 200, "203.0.113.13", "GET /home from 203.0.113.13"),
	}
}

type searchJSON struct {
	Run      string `json:"run"`
	Complete bool   `json:"complete"`
	Search   *struct {
		Terms  []string `json:"terms"`
		Absent bool     `json:"absent"`
	} `json:"search"`
	Sources []struct {
		Status         string `json:"status"`
		Events         *int64 `json:"events"`
		Outcome        string `json:"outcome"`
		IndexAlive     *bool  `json:"index_alive"`
		IndexDocuments *int64 `json:"index_documents"`
	} `json:"sources"`
}

func runSearchHunt(t *testing.T, dir string, args ...string) (code int, out searchJSON, stdout, stderr string) {
	t.Helper()
	all := append([]string{"hunt", "--output", "json", "--case", dir, "--config", fpConfigRel}, args...)
	code, stdout, stderr = run(t, testDeps(huntEnv), all...)
	_ = json.Unmarshal([]byte(stdout), &out)
	return
}

func TestHuntSearchNarrowsOnTheServerAndCountsWhatWasFetched(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	code, out, stdout, stderr := runSearchHunt(t, dir, "--search", "needle-token")
	if out.Run == "" {
		t.Fatalf("not JSON (exit %d)\n%s\n%s", code, stdout, stderr)
	}
	if !strings.HasPrefix(out.Run, "search-") {
		t.Errorf("run = %q, want a search- run so a narrowed subset is not mistaken for a hunt", out.Run)
	}
	if len(out.Sources) != 1 || out.Sources[0].Events == nil || *out.Sources[0].Events != 2 || out.Sources[0].Outcome != "matched" {
		t.Fatalf("sources = %+v, want the 2 matching events fetched", out.Sources)
	}
	if out.Sources[0].IndexAlive != nil {
		t.Errorf("a source that matched reports a liveness probe: %+v", out.Sources[0])
	}
	if out.Search == nil || out.Search.Absent || len(out.Search.Terms) != 1 {
		t.Errorf("search = %+v", out.Search)
	}
	reqs := idx.requests()
	if len(reqs) == 0 {
		t.Fatal("no request reached the server")
	}
	for _, r := range reqs {
		fs := filterClauses(r)
		b, _ := json.Marshal(fs)
		if !strings.Contains(string(b), `"match_phrase":{"message":"needle-token"}`) {
			t.Fatalf("a request went out without the term: %s", b)
		}
	}
	if !strings.Contains(stderr, "narrowed by 1 search term") {
		t.Errorf("stderr lacks the narrowing note: %q", stderr)
	}
}

func TestHuntWithoutSearchSendsNoPhraseClause(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	code, out, stdout, stderr := runSearchHunt(t, dir)
	if out.Run == "" || len(out.Sources) != 1 || *out.Sources[0].Events != 4 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if out.Search != nil || strings.HasPrefix(out.Run, "search-") {
		t.Errorf("an ordinary hunt looks like a search: %+v", out)
	}
	for _, r := range idx.requests() {
		if b, _ := json.Marshal(filterClauses(r)); strings.Contains(string(b), "match_phrase") {
			t.Fatalf("a phrase clause was sent without --search: %s", b)
		}
	}
}

// The term matched nothing but the index answered a count: the term is absent. That is
// an answer (exit 0), and it must say so and give the count the probe returned.
func TestHuntSearchTermAbsentFromALiveIndex(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	code, out, stdout, stderr := runSearchHunt(t, dir, "--search", "no-such-term")
	if code != 0 {
		t.Fatalf("exit %d, want 0: an absent term in a live index is an answer\n%s\n%s", code, stdout, stderr)
	}
	s := out.Sources[0]
	if s.Status != "ok" || *s.Events != 0 || s.Outcome != "no match; index alive" || s.IndexAlive == nil || !*s.IndexAlive {
		t.Fatalf("source = %+v", s)
	}
	// 4 documents in the window and the one before it, counted by the probe itself.
	if s.IndexDocuments == nil || *s.IndexDocuments != 4 {
		t.Fatalf("index_documents = %v, want the probe's own count 4", s.IndexDocuments)
	}
	if out.Search == nil || !out.Search.Absent || !out.Complete {
		t.Fatalf("search = %+v complete = %v", out.Search, out.Complete)
	}
	// The probe is an unfiltered size-0 count.
	var probe bool
	for _, r := range idx.requests() {
		if r["size"] == float64(0) {
			probe = true
			if b, _ := json.Marshal(filterClauses(r)); strings.Contains(string(b), "match_phrase") {
				t.Fatalf("the liveness probe carried the term: %s", b)
			}
		}
	}
	if !probe {
		t.Fatal("no liveness probe was sent")
	}

	code, stdout, stderr = run(t, testDeps(huntEnv), "hunt", "--case", dir, "--config", fpConfigRel, "--search", "no-such-term")
	if code != 0 {
		t.Fatalf("table: exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{"no match; index alive", "the term is absent", "the index is not empty"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "INCOMPLETE") {
		t.Errorf("an absent term is reported as incomplete:\n%s", stdout)
	}
}

// An index with nothing in the window is not "term absent": nothing can be said.
func TestHuntSearchOnAnEmptyIndexIsNotAnAbsentTerm(t *testing.T) {
	idx := newFakeIndex(t, nil)
	dir := searchCase(t, idx)
	code, out, stdout, stderr := runSearchHunt(t, dir, "--search", "needle-token")
	if code != exitFailure {
		t.Fatalf("exit %d, want 1\n%s\n%s", code, stdout, stderr)
	}
	s := out.Sources[0]
	if s.Status != "no_records" || s.Outcome != "index empty or nothing readable" || s.IndexAlive != nil {
		t.Fatalf("source = %+v", s)
	}
	if out.Search == nil || out.Search.Absent || out.Complete {
		t.Fatalf("search = %+v complete = %v", out.Search, out.Complete)
	}
	_, tbl, _ := run(t, testDeps(huntEnv), "hunt", "--case", dir, "--config", fpConfigRel, "--search", "needle-token")
	if !strings.Contains(tbl, "index empty or nothing readable; nothing can be said about the term here") || strings.Contains(tbl, "the term is absent") {
		t.Errorf("table:\n%s", tbl)
	}
}

func TestHuntSearchOnAnUnreachableIndexIsNotAnAbsentTerm(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	idx.status = 502
	dir := searchCase(t, idx)
	code, out, stdout, stderr := runSearchHunt(t, dir, "--search", "needle-token")
	if code != exitFailure || out.Sources[0].Outcome != "unreachable" || out.Search.Absent {
		t.Fatalf("exit %d, sources %+v\n%s\n%s", code, out.Sources, stdout, stderr)
	}
}

// With two sources one matching and one absent, the absent one is named and the
// verdict is not "absent": the term was found.
func TestHuntSearchTermsAreANDedAndRepeatable(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	_, out, _, _ := runSearchHunt(t, dir, "--search", "needle-token", "--search", "/login")
	if out.Sources[0].Events == nil || *out.Sources[0].Events != 1 {
		t.Fatalf("sources = %+v, want 1 event matching both terms", out.Sources)
	}
	for _, r := range idx.requests() {
		b, _ := json.Marshal(filterClauses(r))
		if strings.Count(string(b), "match_phrase") != 2 {
			t.Fatalf("want two phrase clauses, got %s", b)
		}
	}
}

func TestHuntSearchFieldOverride(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	_, out, _, _ := runSearchHunt(t, dir, "--search", "/home", "--search-field", "path")
	if out.Sources[0].Events == nil || *out.Sources[0].Events != 2 {
		t.Fatalf("sources = %+v", out.Sources)
	}
	for _, r := range idx.requests() {
		if b, _ := json.Marshal(filterClauses(r)); !strings.Contains(string(b), `"match_phrase":{"path":"/home"}`) {
			t.Fatalf("the field override did not reach the server: %s", b)
		}
	}
}

// A hostile term is one string in one clause. The request has exactly the clauses it
// would have for a harmless term, and the term arrives verbatim.
func TestHuntSearchTermIsDataInTheRequest(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	term := `x"}}, {"match_all": {}}, {"match_phrase": {"message": "y`
	run(t, testDeps(huntEnv), "hunt", "--case", dir, "--config", fpConfigRel, "--search", term)
	var sawTerm bool
	for _, r := range idx.requests() {
		if r["size"] == float64(0) {
			continue
		}
		fs := filterClauses(r)
		if len(fs) != 2 { // the time range and the one phrase
			t.Fatalf("%d filter clauses, want 2: %v", len(fs), fs)
		}
		mp, _ := fs[1].(map[string]any)["match_phrase"].(map[string]any)
		if mp["message"] != term {
			t.Fatalf("clause = %v, want the term verbatim", fs[1])
		}
		sawTerm = true
	}
	if !sawTerm {
		t.Fatal("no search request was sent")
	}
}

func TestHuntSearchRefusalsAreUsageErrorsAndSendNothing(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	for name, args := range map[string][]string{
		"newline":              {"--search", "a\nb"},
		"nul":                  {"--search", "a\x00b"},
		"escape":               {"--search", "\x1b[2J"},
		"empty":                {"--search", ""},
		"blank":                {"--search", "   "},
		"too long":             {"--search", strings.Repeat("a", 257)},
		"too many":             {"--search", "a", "--search", "b", "--search", "c", "--search", "d", "--search", "e"},
		"field without search": {"--search-field", "path"},
		"bad field":            {"--search", "a", "--search-field", "a b"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := run(t, testDeps(huntEnv), append([]string{"hunt", "--case", dir, "--config", fpConfigRel}, args...)...)
			if code != exitUsage {
				t.Fatalf("exit %d, want 2\n%s\n%s", code, stdout, stderr)
			}
		})
	}
	if n := len(idx.requests()); n != 0 {
		t.Fatalf("%d request(s) reached the server for refused input", n)
	}
}
