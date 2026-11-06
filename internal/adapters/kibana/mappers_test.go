package kibana

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// All lines are synthetic: example.com, RFC 5737 / RFC 3849 addresses, made-up UAs.
const (
	lineNormal = `192.0.2.10 - - [05/Nov/2026:12:00:01 +0000] "POST /auth/login HTTP/1.1" 401 52 "-" "ExampleAgent/1.0" 310 0.004 [example-svc-80] [] 10.0.0.5:8080 52 0.004 401 req0001`
	lineSpaces = `192.0.2.11 - - [05/Nov/2026:12:00:02 +0000] "GET /home HTTP/2.0" 200 1024 "https://www.example.com/start?x=1" "Example Browser 2.1 (Test OS; rv:1) Gecko/20260101 Fake/9.9" 400 0.010 [example-svc-80] [] 10.0.0.5:8080 1024 0.010 200 req0002`
	lineQuery  = `192.0.2.12 - - [05/Nov/2026:12:00:03 +0000] "GET /search/items?q=a+b&page=2 HTTP/1.1" 200 77 "-" "ExampleAgent/1.0" 120 0.002 [example-svc-80] [] 10.0.0.5:8080 77 0.002 200 req0003`
	lineIPv6   = `2001:db8::1 - - [05/Nov/2026:12:00:04 +0000] "GET /v6 HTTP/1.1" 404 9 "-" "ExampleAgent/1.0" 90 0.001 [example-svc-80] [] 10.0.0.5:8080 9 0.001 404 req0004`
	// The referer names a login path, and an upstream status of 200 follows the UA.
	// Only the path in the request and the status after it are the client's.
	lineReferer = `192.0.2.13 - - [05/Nov/2026:12:00:05 +0000] "GET /static/app.js HTTP/1.1" 304 0 "https://www.example.com/auth/login" "ExampleAgent/1.0" 100 0.001 [example-svc-80] [] 10.0.0.5:8080 0 0.001 200 req0005`
)

func srcOf(msg any) map[string]any {
	return map[string]any{"@timestamp": "2026-11-05T12:00:00Z", "message": msg}
}

func TestNginxIngressMapper(t *testing.T) {
	m, ok := LookupMapper("nginx_ingress")
	if !ok {
		t.Fatal("nginx_ingress is not registered")
	}
	cases := []struct {
		name, line string
		want       map[string]any
		absent     []string
	}{
		{"normal line", lineNormal, map[string]any{
			"client_ip": "192.0.2.10", "method": "POST", "path": "/auth/login", "status": 401, "user_agent": "ExampleAgent/1.0",
		}, []string{"referer"}},
		{"quoted UA with spaces and a referer", lineSpaces, map[string]any{
			"client_ip": "192.0.2.11", "method": "GET", "path": "/home", "status": 200,
			"user_agent": "Example Browser 2.1 (Test OS; rv:1) Gecko/20260101 Fake/9.9",
			"referer":    "https://www.example.com/start?x=1",
		}, nil},
		{"query string is not part of the path", lineQuery, map[string]any{
			"client_ip": "192.0.2.12", "path": "/search/items", "status": 200,
		}, nil},
		{"IPv6 client", lineIPv6, map[string]any{"client_ip": "2001:db8::1", "path": "/v6", "status": 404}, nil},
		{"referer is not the path, upstream status is not the status", lineReferer, map[string]any{
			"path": "/static/app.js", "status": 304, "referer": "https://www.example.com/auth/login",
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, err := m(srcOf(c.line))
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range c.want {
				if ev.Fields[k] != v {
					t.Errorf("Fields[%q] = %#v (%T), want %#v (%T)", k, ev.Fields[k], ev.Fields[k], v, v)
				}
			}
			for _, k := range c.absent {
				if _, has := ev.Fields[k]; has {
					t.Errorf("Fields[%q] present, want absent", k)
				}
			}
			if !ev.Time.Equal(time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)) {
				t.Errorf("Time = %v, want the document's @timestamp", ev.Time)
			}
			if !strings.Contains(string(ev.Raw), "req000") {
				t.Errorf("Raw does not carry the original document: %s", ev.Raw)
			}
		})
	}
}

func TestNginxIngressMapperRejectsWhatIsNotAnAccessLine(t *testing.T) {
	m, _ := LookupMapper("nginx_ingress")
	bad := map[string]any{
		"empty":            "",
		"json blob":        `{"level":"error","msg":"upstream timed out"}`,
		"no request":       `192.0.2.10 - - [05/Nov/2026:12:00:01 +0000] "-" 400 0 "-" "-"`,
		"not an address":   `host.example.com - - [05/Nov/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 1 "-" "x"`,
		"no status":        `192.0.2.10 - - [05/Nov/2026:12:00:01 +0000] "GET / HTTP/1.1" abc 1 "-" "x"`,
		"missing message":  nil,
		"message not text": 42,
	}
	for name, msg := range bad {
		t.Run(name, func(t *testing.T) {
			src := srcOf(msg)
			if msg == nil {
				delete(src, "message")
			}
			_, err := m(src)
			if !errors.Is(err, ErrUnparsable) {
				t.Fatalf("err = %v, want ErrUnparsable", err)
			}
		})
	}
	// A bad timestamp is not an unparsable line: it stays the fatal error it is today.
	_, err := m(map[string]any{"message": lineNormal})
	if err == nil || errors.Is(err, ErrUnparsable) {
		t.Fatalf("missing @timestamp: err = %v, want a non-ErrUnparsable error", err)
	}
}

func TestMapperRegistry(t *testing.T) {
	if _, ok := LookupMapper("no_such_mapper"); ok {
		t.Fatal("unknown name resolved")
	}
	if _, ok := LookupMapper("default"); !ok {
		t.Fatal("default is not registered")
	}
	names := strings.Join(MapperNames(), ",")
	if names != "default,keycloak,nginx_ingress,request_dump" {
		t.Errorf("MapperNames = %q", names)
	}
}

// serveMessages serves one page of hits whose _source holds the given messages.
func serveMessages(t *testing.T, msgs []any) *httptest.Server {
	t.Helper()
	var hits []map[string]any
	for i, m := range msgs {
		ts := time.Date(2026, 1, 1, 0, 0, i+1, 0, time.UTC)
		hits = append(hits, map[string]any{
			"_index": "ingress-example", "_id": fmt.Sprintf("id%03d", i),
			"_source": map[string]any{"@timestamp": ts.Format(time.RFC3339), "message": m},
			"sort":    []any{ts.UnixMilli()},
		})
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"rawResponse": map[string]any{"hits": map[string]any{
			"total": map[string]any{"value": len(hits)}, "hits": hits}}})
	}))
}

func nginxSource(srv *httptest.Server) *Source {
	m, _ := LookupMapper("nginx_ingress")
	return &Source{Client: New(srv.URL, testKey), Index: "ingress-example", Map: m, PageSize: 100}
}

func TestUnparsableLinesAreCountedNotDropped(t *testing.T) {
	srv := serveMessages(t, []any{lineNormal, "garbage one", lineQuery, `{"level":"error"}`, lineIPv6})
	defer srv.Close()
	s := nginxSource(srv)
	evs, err := collect(t, s, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 3 {
		t.Fatalf("events = %d, want the 3 parsable lines", len(evs))
	}
	st := s.Stats()
	if st.Fetched != 3 || st.Unparsable != 2 || st.HitsTotal != 5 {
		t.Errorf("stats = %+v, want fetched 3, unparsable 2, total 5", st)
	}
	// The use case reads it through core.ParseCounter, without importing this package.
	var pc core.ParseCounter = s
	if pc.Unparsable() != 2 {
		t.Errorf("Unparsable() = %d, want 2", pc.Unparsable())
	}
}

func TestAllLinesUnparsableIsAnErrorNotAQuietWindow(t *testing.T) {
	srv := serveMessages(t, []any{"garbage one", "garbage two", `{"a":1}`})
	defer srv.Close()
	s := nginxSource(srv)
	evs, err := collect(t, s, context.Background())
	if len(evs) != 0 {
		t.Fatalf("events = %d, want 0", len(evs))
	}
	if !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want core.ErrNoRecords", err)
	}
	if !strings.Contains(err.Error(), "3 ") || !strings.Contains(err.Error(), "unparsable") {
		t.Errorf("error must say how many documents failed to parse: %v", err)
	}
	if st := s.Stats(); st.Unparsable != 3 || st.Fetched != 0 {
		t.Errorf("stats = %+v", st)
	}
}

// Keycloak lines are synthetic: example.com, RFC 5737 addresses, made-up realm and client.
const (
	kcLogin    = `type="LOGIN_ERROR", realmName="demo", clientId="web-app", userId="null", ipAddress="192.0.2.10", error="user_not_found", auth_method="openid-connect"`
	kcRegister = `type="REGISTER", realmName="demo", clientId="web-app", userId="u-1", ipAddress="192.0.2.11", email="new@example.com", username="new@example.com"`
)

func kcSource(srv *httptest.Server) *Source {
	m, _ := LookupMapper("keycloak")
	return &Source{Client: New(srv.URL, testKey), Index: "kc-example", Map: m, PageSize: 100}
}

func TestKeycloakMapperEmitsRealFieldsAndNoStatus(t *testing.T) {
	m, ok := LookupMapper("keycloak")
	if !ok {
		t.Fatal("keycloak is not registered")
	}
	ev, err := m(srcOf(kcLogin))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"event_type": "LOGIN_ERROR", "outcome": "error", "error": "user_not_found", "client_ip": "192.0.2.10", "realm": "demo", "client_id": "web-app"}
	for k, v := range want {
		if ev.Fields[k] != v {
			t.Errorf("Fields[%q] = %#v, want %#v", k, ev.Fields[k], v)
		}
	}
	for _, k := range []string{"status", "username", "path", "method"} {
		if _, has := ev.Fields[k]; has {
			t.Errorf("Fields[%q] present; the line has no such value", k)
		}
	}
	if len(ev.Fields) != len(want) {
		t.Errorf("fields = %v", ev.Fields)
	}
}

func TestKeycloakUnparsableIsCountedAndBadTimeIsFatal(t *testing.T) {
	m, _ := LookupMapper("keycloak")
	_, err := m(srcOf(lineNormal))
	if !errors.Is(err, ErrUnparsable) {
		t.Fatalf("an nginx line: err = %v, want ErrUnparsable", err)
	}
	_, err = m(map[string]any{"message": kcLogin})
	if err == nil || errors.Is(err, ErrUnparsable) {
		t.Fatalf("missing @timestamp: err = %v, want a fatal error", err)
	}

	srv := serveMessages(t, []any{kcLogin, "garbage", kcRegister, `{"a":1}`, nil})
	defer srv.Close()
	s := kcSource(srv)
	evs, err := collect(t, s, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); len(evs) != 2 || st.Unparsable != 3 || st.Fetched != 2 {
		t.Errorf("events %d, stats %+v; want 2 events and 3 unparsable counted", len(evs), st)
	}
}

func TestKeycloakAllUnparsableIsNoRecords(t *testing.T) {
	srv := serveMessages(t, []any{lineNormal, "garbage", `{"a":1}`})
	defer srv.Close()
	_, err := collect(t, kcSource(srv), context.Background())
	if !errors.Is(err, core.ErrNoRecords) || !strings.Contains(err.Error(), "unparsable") {
		t.Fatalf("err = %v, want core.ErrNoRecords naming the unparsable count", err)
	}
}
