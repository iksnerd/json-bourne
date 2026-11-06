package config

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

func TestKibanaMapperKey(t *testing.T) {
	with := func(line string) string {
		return strings.Replace(valid, "    index: logs-auth-*\n", "    index: logs-auth-*\n"+line, 1)
	}
	for _, ok := range []string{"", "    mapper: nginx_ingress\n", "    mapper: default\n"} {
		f, err := Parse([]byte(with(ok)))
		if err != nil {
			t.Fatalf("%q: %v", ok, err)
		}
		if _, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret})); err != nil {
			t.Fatalf("%q: build: %v", ok, err)
		}
	}
	for _, bad := range []string{"    mapper: nginx-ingress\n", "    mapper: ecs\n", "    mapper: NGINX_INGRESS\n", "    mapper: [nginx_ingress]\n"} {
		_, err := Parse([]byte(with(bad)))
		if err == nil {
			t.Fatalf("%q was accepted at load", bad)
		}
	}
	// The error names the key and lists the valid names, like an unknown type does.
	_, err := Parse([]byte(with("    mapper: ecs\n")))
	if err == nil || !strings.Contains(err.Error(), "mapper") || !strings.Contains(err.Error(), "nginx_ingress") {
		t.Errorf("error should name the key and list known mappers: %v", err)
	}
}

type readerOf func(context.Context, core.Window) iter.Seq2[core.Event, error]

func (f readerOf) Events(ctx context.Context, w core.Window) iter.Seq2[core.Event, error] {
	return f(ctx, w)
}

// TestNginxIngressToAuthspikeEndToEnd runs the real config path: YAML -> kibana
// source with the nginx_ingress mapper -> authspike. The Kibana is a loopback test
// server holding only raw `message` lines, like the real ingress index.
func TestNginxIngressToAuthspikeEndToEnd(t *testing.T) {
	nginxToAuthspike(t, "    mapper: nginx_ingress\n")
}

// nginxToAuthspike runs the scenario above with the given mapper lines in the source
// and returns the finding tags. The built-in mapper and a configured plugin must give
// the same answer, which is what plugin_test.go checks.
func nginxToAuthspike(t *testing.T, mapperYAML string) []string {
	t.Helper()
	cur := core.Window{From: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC), To: time.Date(2026, 11, 5, 12, 10, 0, 0, time.UTC)}
	prev := core.Window{From: cur.From.Add(-10 * time.Minute), To: cur.From}

	type doc struct {
		at   time.Time
		line string
	}
	var docs []doc
	add := func(w core.Window, ip string, n, status int) {
		for i := 0; i < n; i++ {
			at := w.From.Add(time.Duration(i+1) * time.Second)
			docs = append(docs, doc{at, fmt.Sprintf(
				`%s - - [05/Nov/2026:12:00:00 +0000] "POST /auth/login?client=web HTTP/1.1" %d 52 "-" "ExampleAgent/1.0 (Fake OS)" 310 0.004 [example-svc-80] [] 10.0.0.5:8080 52 0.004 200 r%d`,
				ip, status, len(docs))})
		}
	}
	const attacker = "198.51.100.7"
	add(prev, attacker, 30, 200)
	add(prev, "203.0.113.5", 30, 200)
	add(cur, attacker, 30, 401)
	add(cur, "203.0.113.5", 30, 200)
	docs = append(docs, doc{cur.From.Add(time.Minute), "not an access line"}) // counted, not fatal

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Body struct {
					Query struct {
						Bool struct {
							Filter []map[string]map[string]map[string]any `json:"filter"`
						} `json:"bool"`
					} `json:"query"`
				} `json:"body"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var from, to time.Time
		for _, f := range req.Params.Body.Query.Bool.Filter {
			if rg, ok := f["range"]["@timestamp"]; ok && rg["format"] == nil {
				from, _ = time.Parse(time.RFC3339Nano, rg["gte"].(string))
				to, _ = time.Parse(time.RFC3339Nano, rg["lt"].(string))
			}
		}
		var hits []map[string]any
		for i, d := range docs {
			if d.at.Before(from) || !d.at.Before(to) {
				continue
			}
			hits = append(hits, map[string]any{"_index": "ingress", "_id": fmt.Sprint(i),
				"_source": map[string]any{"@timestamp": d.at.Format(time.RFC3339), "message": d.line},
				"sort":    []any{d.at.UnixMilli()}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rawResponse": map[string]any{"hits": map[string]any{
			"total": map[string]any{"value": len(hits)}, "hits": hits}}})
	}))
	defer srv.Close()

	y := fmt.Sprintf(`
sources:
  - type: kibana
    url: %s
    api_key_env: JB_KIBANA_API_KEY
    index: ingress-example
%sdetectors:
  - type: authspike
    key_field: client_ip
    status_field: status
    path_field: path
    path_contains: /auth/login
`, srv.URL, mapperYAML)
	f, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	src := rt.Sources[0]
	r := readerOf(func(ctx context.Context, w core.Window) iter.Seq2[core.Event, error] { return src.Fetch(ctx, w) })

	fs, err := rt.Detectors[0].Detect(context.Background(), r, r, cur)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, fd := range fs {
		got = append(got, fd.Tag)
	}
	if len(fs) != 1 || !strings.Contains(fs[0].Tag, attacker) {
		t.Fatalf("findings = %v, want exactly one for %s", got, attacker)
	}
	return got
}
