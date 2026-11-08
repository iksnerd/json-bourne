package config

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const rdSource = `
sources:
  - type: kibana
    name: app
    url: %s
    api_key_env: JB_KIBANA_API_KEY
    index: app-example-*
    mapper: request_dump
    mapper_config:
      client_ip_header: x-example-edge-client
      header_fields:
        probe_marker: x-example-probe
    filter: [{match_phrase: {field: message, value: "=== Request Info ==="}}]
`

const rdDetectors = `detectors:
  - type: newkey
    name: gateway
    sources: [app]
    key_field: client_ip
    path_field: path
    sensitive_paths: [/verify]
    min_hits: 3
    user_agent_field: user_agent
    user_agent_matches: ["curl/*", "python-requests/*"]
    empty_is_quiet: true
  - type: signature
    name: signature
    sources: [app]
    field: probe_marker
    present: true
    key_field: client_ip
    path_field: path
    empty_is_quiet: true
`

func dumpMsg(path, ip, ua string, extra ...string) string {
	lines := []string{"=== Request Info ===", "method = POST", "path = " + path, "query = ",
		"header = User-Agent    value = " + ua,
		"header = X-Example-Edge-Client    value = " + ip}
	for _, e := range extra {
		lines = append(lines, "header = "+e)
	}
	return strings.Join(lines, "\n") + "\n"
}

// TestRequestDumpToGatewayAndSignatureEndToEnd runs the real config path: YAML -> kibana
// source with the request_dump mapper -> newkey (scripted clients) and signature, over
// a loopback Kibana that holds only raw request-dump documents.
func TestRequestDumpToGatewayAndSignatureEndToEnd(t *testing.T) {
	cur := core.Window{From: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC), To: time.Date(2026, 11, 5, 12, 10, 0, 0, time.UTC)}
	prev := core.Window{From: cur.From.Add(-10 * time.Minute), To: cur.From}
	const (
		newcomer = "198.51.100.7"
		regular  = "192.0.2.10"
		prober   = "203.0.113.9"
		browser  = "Mozilla/5.0 (Fake OS) Browser/1"
	)
	type doc struct {
		at  time.Time
		msg string
	}
	var docs []doc
	add := func(w core.Window, n int, msg string) {
		for i := 0; i < n; i++ {
			docs = append(docs, doc{w.From.Add(time.Duration(i+1) * time.Second), msg})
		}
	}
	add(prev, 20, dumpMsg("/v1/example/home", regular, browser))
	add(cur, 20, dumpMsg("/v1/example/home", regular, browser))
	add(cur, 4, dumpMsg("/v1/example/verify?code=111111", newcomer, "curl/8.4.0", "Authorization    value = Bearer sentinel-bearer-1"))
	add(cur, 5, dumpMsg("/v1/example/verify", regular, "curl/8.4.0")) // scripted, but has history
	add(cur, 2, dumpMsg("/v1/example/items", prober, browser,
		"X-Example-Probe    value = case-17", "Cookie    value = sid=sentinel-cookie-2"))
	docs = append(docs, doc{cur.From.Add(time.Minute), "=== Response Info ===\nstatus = 200"}) // counted, not fatal

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
			hits = append(hits, map[string]any{"_index": "app", "_id": fmt.Sprint(i),
				"_source": map[string]any{"@timestamp": d.at.Format(time.RFC3339), "message": d.msg,
					"event": map[string]any{"original": d.msg}},
				"sort": []any{d.at.UnixMilli()}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rawResponse": map[string]any{"hits": map[string]any{
			"total": map[string]any{"value": len(hits)}, "hits": hits}}})
	}))
	defer srv.Close()

	f, err := Parse([]byte(fmt.Sprintf(rdSource, srv.URL) + rdDetectors))
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

	byName := map[string][]core.Finding{}
	for _, d := range rt.Detectors {
		fs, err := d.Detect(context.Background(), r, r, cur)
		if err != nil {
			t.Fatalf("%s: %v", d.Name(), err)
		}
		byName[d.Name()] = fs
	}
	if fs := byName["gateway"]; len(fs) != 1 || fs[0].Tag != "gateway:"+newcomer || fs[0].Detail["key_cur_sensitive_hits"] != 4 {
		t.Errorf("gateway findings = %+v, want one for %s with 4 scripted hits (regular has history, prober is not scripted)", fs, newcomer)
	}
	if fs := byName["signature"]; len(fs) != 1 || fs[0].Tag != "signature:probe_marker" || fs[0].Detail["events"] != 2 || fs[0].Detail["distinct_keys"] != 1 {
		t.Errorf("signature findings = %+v, want one marker finding with 2 events from 1 key", fs)
	}
	// Nothing credential-shaped is in a finding or in any event the evidence store would keep.
	var all strings.Builder
	for _, fs := range byName {
		for _, fd := range fs {
			fmt.Fprint(&all, fd.Tag, fd.Summary, fd.Detail)
		}
	}
	for ev, err := range src.Fetch(context.Background(), core.Window{From: prev.From, To: cur.To}) {
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprint(&all, ev.Fields, string(ev.Raw))
	}
	for _, s := range []string{"sentinel-bearer-1", "sentinel-cookie-2", "code=111111", "111111"} {
		if strings.Contains(all.String(), s) {
			t.Errorf("%q reached a finding or a stored event", s)
		}
	}
}

func TestRequestDumpConfigIsCheckedAtLoad(t *testing.T) {
	src := func(mc string) string {
		return fmt.Sprintf("sources:\n  - {type: kibana, name: app, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: app-*, mapper: request_dump%s}\ndetectors:\n  - {type: newkey, key_field: client_ip, path_field: path, sensitive_paths: [/x]}\n", mc)
	}
	for name, tc := range map[string]struct{ cfg, want string }{
		"credential header":     {src(", mapper_config: {header_fields: {m: authorization}}"), "never emitted"},
		"cookie as client ip":   {src(", mapper_config: {client_ip_header: Cookie}"), "never emitted"},
		"unknown key":           {src(", mapper_config: {headers: {m: x-a}}"), "unknown field"},
		"owned field name":      {src(", mapper_config: {header_fields: {path: x-a}}"), "owns"},
		"config on keycloak":    {strings.Replace(src(", mapper_config: {a: 1}"), "request_dump", "keycloak", 1), "mapper_config is only valid"},
		"config on nginx":       {strings.Replace(src(", mapper_config: {a: 1}"), "request_dump", "nginx_ingress", 1), "mapper_config is only valid"},
		"config without mapper": {strings.Replace(src(", mapper_config: {a: 1}"), "mapper: request_dump,", "", 1), "mapper_config is only valid"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.cfg))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
	// The control: defaults and a good config load.
	for _, ok := range []string{src(""), src(", mapper_config: {client_ip_header: x-example-edge-client, header_fields: {m: x-example-probe}}")} {
		if _, err := Parse([]byte(ok)); err != nil {
			t.Errorf("control: %v", err)
		}
	}
}

// A signature detector on a field the source's mapper never emits would be quiet whatever
// the log holds; Parse refuses it.
func TestSignatureFieldMustBeEmittedByTheSourceMapper(t *testing.T) {
	y := fmt.Sprintf(rdSource, "https://kibana.example.com")
	det := func(field string) string {
		return fmt.Sprintf("detectors:\n  - {type: signature, field: %s, present: true, key_field: client_ip, sources: [app]}\n", field)
	}
	_, err := Parse([]byte(y + det("probe_markr")))
	if err == nil || !strings.Contains(err.Error(), `"probe_markr"`) || !strings.Contains(err.Error(), "header_fields") {
		t.Fatalf("typo in field: err = %v", err)
	}
	if _, err := Parse([]byte(y + det("probe_marker"))); err != nil {
		t.Fatalf("correct field: %v", err)
	}
	// A source with a mapper whose output is not known from its config is not second-guessed.
	other := "sources:\n  - {type: kibana, name: app, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: app-*}\n"
	if _, err := Parse([]byte(other + det("whatever_field"))); err != nil {
		t.Fatalf("default mapper: %v", err)
	}
}

func TestSignatureAndNewkeyUAFilterRejectBadInputAtLoad(t *testing.T) {
	head := fmt.Sprintf(rdSource, "https://kibana.example.com") + "detectors:\n"
	for name, d := range map[string]string{
		"signature neither mode":       "  - {type: signature, field: probe_marker, key_field: client_ip}\n",
		"signature both modes":         "  - {type: signature, field: probe_marker, present: true, equals: [a], key_field: client_ip}\n",
		"signature unknown key":        "  - {type: signature, field: probe_marker, present: true, key_field: client_ip, header: x}\n",
		"signature personal key":       "  - {type: signature, field: probe_marker, present: true, key_field: email}\n",
		"signature quiet needs filter": "  - {type: signature, field: probe_marker, present: true, key_field: client_ip, empty_is_quiet: true}\n",
		"newkey star only":             "  - {type: newkey, key_field: client_ip, path_field: path, sensitive_paths: [/x], user_agent_field: user_agent, user_agent_matches: ['*']}\n",
		"newkey field alone":           "  - {type: newkey, key_field: client_ip, path_field: path, sensitive_paths: [/x], user_agent_field: user_agent}\n",
	} {
		t.Run(name, func(t *testing.T) {
			y := head + d
			if name == "signature quiet needs filter" {
				y = strings.Replace(head, "    filter: [{match_phrase: {field: message, value: \"=== Request Info ===\"}}]\n", "", 1) + d
			}
			if _, err := Parse([]byte(y)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// The documented gateway and signature configs are what people will copy: they must load.
func TestDocumentedGatewayExamplesLoad(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "config", "detector-scoping.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(doc), "## Example: gateway and signature")
	if !ok {
		t.Fatal("docs/config/detector-scoping.md lost its gateway example")
	}
	_, block, _ := strings.Cut(after, "```yaml\n")
	block, _, _ = strings.Cut(block, "```")
	f, err := Parse([]byte(block))
	if err != nil {
		t.Fatalf("CONFIG.md example: %v", err)
	}
	if len(f.Detectors) != 2 || f.Detectors[0].Type != "newkey" || f.Detectors[1].Type != "signature" {
		t.Errorf("CONFIG.md example: detectors = %+v", f.Detectors)
	}

	ex, err := os.ReadFile(filepath.Join("..", "..", "examples", "jb.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok = strings.Cut(string(ex), "# Gateway and signature over an application request log")
	if !ok {
		t.Fatal("jb.example.yaml lost its gateway example")
	}
	var un []string
	started := false
	for _, l := range strings.Split(after, "\n") {
		if strings.HasPrefix(l, "# sources:") {
			started = true
		}
		if started && !strings.HasPrefix(l, "#") {
			break
		}
		if started {
			un = append(un, strings.TrimPrefix(strings.TrimPrefix(l, "#"), " "))
		}
	}
	if _, err := Parse([]byte(strings.Join(un, "\n"))); err != nil {
		t.Fatalf("jb.example.yaml gateway example: %v", err)
	}
}
