package contract

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite contract/testdata/*.json")

// now is the fixed clock of every test that compares a window.
var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return now }

// env answers every credential variable with a fixed synthetic value.
func env(string) (string, bool) { return "synthetic-key-0123456789", true }

const (
	fpConfig  = "config/fingerprint.yaml"
	exampleUA = "ExampleBrowser/9.1 (Plan9; Win64; x64) InventedKit/537.36 (like Gecko) Chrome/9.1.0.0 Safari/537.36"
)

// doc is one document of the fake index.
type doc struct {
	at     time.Time
	fields map[string]any
}

func webDoc(at time.Time, ua, path string, status int, ip, message string) doc {
	return doc{at: at, fields: map[string]any{
		"user_agent": ua, "path": path, "status": status, "client_ip": ip, "method": "GET", "message": message,
	}}
}

// cur is minutes into the current window (11:00 to 12:00 of now).
func cur(m int) time.Time { return now.Add(-time.Hour).Add(time.Duration(m) * time.Minute) }

// searchDocs are the four documents the CLI golden files of hunt and activity were
// recorded over (cmd/jb/search_test.go).
func searchDocs() []doc {
	return []doc{
		webDoc(cur(1), "OtherClient/1.0", "/login", 200, "203.0.113.10", "GET /login from 203.0.113.10"),
		webDoc(cur(2), exampleUA, "/login", 200, "203.0.113.11", "GET /login needle-token from 203.0.113.11"),
		webDoc(cur(3), "OtherClient/1.0", "/home", 200, "203.0.113.12", "GET /home needle-token from 203.0.113.12"),
		webDoc(cur(4), "OtherClient/1.0", "/home", 200, "203.0.113.13", "GET /home from 203.0.113.13"),
	}
}

// fakeKibana answers like Kibana's search endpoint for a list of documents: it applies
// the time range and the match_phrase and term clauses it is sent, and answers a size 0
// request with the total alone. Knobs make it fail, time out or block.
type fakeKibana struct {
	mu       sync.Mutex
	docs     []doc
	status   int           // non-200 answers every request with it
	failFrom int           // when > 0, request number failFrom and later answer 500
	timedOut bool          // answers with "timed_out": true
	block    chan struct{} // when set, a request waits for it (or its own cancel)
	served   int
	srv      *httptest.Server
}

func newKibana(t *testing.T, docs []doc) *fakeKibana {
	t.Helper()
	f := &fakeKibana{docs: docs, status: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.close)
	return f
}

func (f *fakeKibana) close() {
	f.srv.CloseClientConnections()
	f.srv.Close()
}

func (f *fakeKibana) requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.served
}

func (f *fakeKibana) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Params struct {
			Body map[string]any `json:"body"`
		} `json:"params"`
	}
	_ = json.Unmarshal(raw, &req)
	f.mu.Lock()
	f.served++
	n, status, failFrom, timedOut, block := f.served, f.status, f.failFrom, f.timedOut, f.block
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-r.Context().Done():
			return
		}
	}
	if status != http.StatusOK || (failFrom > 0 && n >= failFrom) {
		if status == http.StatusOK {
			status = http.StatusInternalServerError
		}
		http.Error(w, "boom", status)
		return
	}
	body := req.Params.Body
	size, _ := body["size"].(float64)
	var matched []int
	for i, d := range f.docs {
		if matchesFilters(d, filterClauses(body)) {
			matched = append(matched, i)
		}
	}
	sort.SliceStable(matched, func(a, b int) bool { return f.docs[matched[a]].at.Before(f.docs[matched[b]].at) })
	var hits []map[string]any
	for _, i := range matched {
		if len(hits) >= int(size) {
			break
		}
		d := f.docs[i]
		src := map[string]any{"@timestamp": d.at.Format(time.RFC3339Nano)}
		for k, v := range d.fields {
			src[k] = v
		}
		hits = append(hits, map[string]any{
			"_id": fmt.Sprintf("d%d", i), "_index": "i", "_source": src, "sort": []any{d.at.UnixMilli()},
		})
	}
	raw2 := map[string]any{"hits": map[string]any{"total": map[string]any{"value": len(matched)}, "hits": hits}}
	if timedOut {
		raw2["timed_out"] = true
		raw2["_shards"] = map[string]any{"total": 5, "successful": 5, "skipped": 0, "failed": 0}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"rawResponse": raw2})
}

func topFilter(body map[string]any) []any {
	q, _ := body["query"].(map[string]any)
	b, _ := q["bool"].(map[string]any)
	fl, _ := b["filter"].([]any)
	return fl
}

// filterClauses flattens the nested bool the source builds into its leaf clauses.
func filterClauses(body map[string]any) []any {
	var out []any
	var walk func(fs []any)
	walk = func(fs []any) {
		for _, c := range fs {
			cm, _ := c.(map[string]any)
			if inner, ok := cm["bool"].(map[string]any); ok {
				if _, has := inner["should"]; has {
					out = append(out, cm)
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

func matchesFilters(d doc, filters []any) bool {
	for _, c := range filters {
		cm, _ := c.(map[string]any)
		for kind, v := range cm {
			vm, _ := v.(map[string]any)
			switch kind {
			case "range":
				rng, _ := vm["@timestamp"].(map[string]any)
				switch g := rng["gte"].(type) {
				case string:
					if t, err := time.Parse(time.RFC3339Nano, g); err == nil && d.at.Before(t) {
						return false
					}
				case float64:
					if d.at.UnixMilli() < int64(g) {
						return false
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

// copyTree copies a directory tree.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if e.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// editFile replaces old with new once, and fails if old is not there.
func editFile(t *testing.T, path, old, new string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), old) {
		t.Fatalf("%s does not contain %q", path, old)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), old, new, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// exampleCase copies the shipped examples/case to a temp dir. With a Kibana, both of its
// configs point at it and the default window is one hour, as the CLI tests do.
func exampleCase(t *testing.T, k *fakeKibana) string {
	t.Helper()
	dir := t.TempDir()
	copyTree(t, filepath.Join("..", "examples", "case"), dir)
	if k != nil {
		editFile(t, filepath.Join(dir, fpConfig), "https://kibana.example.com", k.srv.URL)
		editFile(t, filepath.Join(dir, "config", "hunt.yaml"), "https://kibana.example.com", k.srv.URL)
		editFile(t, filepath.Join(dir, "case.yaml"), "default: 24h", "default: 1h")
	}
	return dir
}

// partialCase is the case of the RFC 0012 contract: one behaviour detector that fires a
// finding and cannot judge another of its actions (max_keys 2 against three keys).
func partialCase(t *testing.T) (dir string, k *fakeKibana) {
	t.Helper()
	k = newKibana(t, []doc{
		webDoc(cur(1), "ExampleAgent/1.0", "/home", 200, "203.0.113.10", "x"),
		webDoc(cur(5), "ExampleAgent/1.0", "/oauth/device/code", 200, "203.0.113.55", "x"),
		webDoc(cur(6), "ExampleAgent/1.0", "/admin/login", 200, "198.51.100.1", "x"),
		webDoc(cur(7), "ExampleAgent/1.0", "/admin/login", 200, "198.51.100.2", "x"),
		webDoc(cur(8), "ExampleAgent/1.0", "/admin/login", 200, "198.51.100.3", "x"),
	})
	dir = exampleCase(t, k)
	body := `sources:
  - type: kibana
    url: ` + k.srv.URL + `
    api_key_env: JB_KIBANA_API_KEY
    index: logs-http-*
detectors:
  - type: behaviour
    key_field: client_ip
    path_field: path
    method_field: method
    max_keys: 2
    actions:
      - {name: device-code, class: rare, path: /oauth/device/code, methods: [GET]}
      - {name: admin-login, class: rare, path: /admin/login, methods: [GET], min_events_per_key: 3}
store:
  path: ""
`
	if err := os.WriteFile(filepath.Join(dir, "config", "behaviour.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	editFile(t, filepath.Join(dir, "case.yaml"), "config:\n", "config:\n  - config/behaviour.yaml\n")
	return dir, k
}

// ---- golden helpers ----

// shape reduces a JSON document to its skeleton: object keys and nesting stay, every
// scalar becomes the name of its JSON type, an array becomes a one element array holding
// the skeleton of its first element (or an empty array). A renamed or removed key, a
// value that turns null and an absent key all change the skeleton; the values, which
// differ by machine and run, do not.
func shape(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = shape(e)
		}
		return out
	case []any:
		if len(x) == 0 {
			return []any{}
		}
		return []any{shape(x[0])}
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	case nil:
		return "null"
	}
	return fmt.Sprintf("%T", v)
}

// pinShape marshals v, reduces it to its skeleton and compares it with
// testdata/<name>.json (written with -update).
func pinShape(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s: marshal: %v", name, err)
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("%s: not JSON: %v\n%s", name, err, raw)
	}
	got, _ := json.MarshalIndent(shape(decoded), "", "  ")
	got = append(got, '\n')
	path := filepath.Join("testdata", name+".json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (generate it with go test -run %s -update)", name, err, t.Name())
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s: the JSON shape changed\n--- got\n%s--- want\n%s", name, got, want)
	}
}
