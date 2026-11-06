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

// TestKeycloakToAuthspikeAndSignupEndToEnd runs YAML -> kibana source with the
// keycloak mapper -> authspike (fail_values) and signup (event_field). The Kibana
// is a loopback server holding raw Keycloak message lines; everything is synthetic.
func TestKeycloakToAuthspikeAndSignupEndToEnd(t *testing.T) {
	cur := core.Window{From: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC), To: time.Date(2026, 11, 5, 12, 10, 0, 0, time.UTC)}
	prev := core.Window{From: cur.From.Add(-10 * time.Minute), To: cur.From}
	const (
		attacker = "198.51.100.7"
		victim   = "sentinel.person@example.com"
	)
	type doc struct {
		at  time.Time
		msg string
	}
	var docs []doc
	add := func(w core.Window, n int, format string, a ...any) {
		for i := 0; i < n; i++ {
			docs = append(docs, doc{w.From.Add(time.Duration(i+1) * time.Second), fmt.Sprintf(format, a...)})
		}
	}
	login := func(w core.Window, ip string, ok, bad int) {
		add(w, ok, `type="LOGIN", realmName="demo", clientId="web-app", userId="u-1", ipAddress="%s", auth_method="openid-connect", username="%s"`, ip, victim)
		add(w, bad, `type="LOGIN_ERROR", realmName="demo", clientId="web-app", userId="null", ipAddress="%s", error="invalid_user_credentials", username="%s"`, ip, victim)
	}
	login(prev, attacker, 28, 2)
	login(prev, "203.0.113.5", 30, 0)
	login(cur, attacker, 5, 45)
	login(cur, "203.0.113.5", 30, 0)
	add(prev, 1, `type="REGISTER", realmName="demo", clientId="web-app", ipAddress="203.0.113.9", email="a@mail.example", username="a@mail.example"`)
	add(cur, 9, `type="REGISTER", realmName="demo", clientId="web-app", ipAddress="203.0.113.9", email="%s", username="%s"`, "x"+victim, "x"+victim)
	add(cur, 30, `type="REGISTER_ERROR", realmName="demo", clientId="web-app", ipAddress="203.0.113.9", error="email_in_use"`)
	docs = append(docs, doc{cur.From.Add(time.Minute), "not a keycloak line"})

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
			hits = append(hits, map[string]any{"_index": "kc", "_id": fmt.Sprint(i),
				"_source": map[string]any{"@timestamp": d.at.Format(time.RFC3339), "message": d.msg},
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
    index: keycloak-example-*
    mapper: keycloak
detectors:
  - type: authspike
    name: kc-stuffing
    key_field: client_ip
    status_field: outcome
    fail_values: [error]
    path_field: event_type
    path_contains: LOGIN
  - type: signup
    name: kc-signup
    event_field: event_type
    create_values: [REGISTER]
    attempt_values: [REGISTER_ERROR]
    address_field: email
    disposable_domains: [mail.example]
`, srv.URL)
	f, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	src := rt.Sources[0]
	r := readerOf(func(ctx context.Context, w core.Window) iter.Seq2[core.Event, error] { return src.Fetch(ctx, w) })

	fs, err := rt.Detectors[0].Detect(context.Background(), r, r, cur)
	if err != nil || len(fs) != 1 || fs[0].Tag != "kc-stuffing:"+attacker {
		t.Fatalf("authspike: findings %+v, err %v; want one for %s", fs, err, attacker)
	}
	fs2, err := rt.Detectors[1].Detect(context.Background(), r, r, cur)
	if err != nil || len(fs2) != 1 || fs2[0].Tag != "kc-signup" {
		t.Fatalf("signup: findings %+v, err %v", fs2, err)
	}
	if fs2[0].Detail["creations_cur"] != 9 || fs2[0].Detail["attempts_cur"] != 39 {
		t.Errorf("signup counted %v creations of %v attempts, want 9 of 39 (REGISTER, not REGISTER_ERROR)", fs2[0].Detail["creations_cur"], fs2[0].Detail["attempts_cur"])
	}
	b, _ := json.Marshal(append(fs, fs2...))
	for _, part := range []string{"sentinel.person", "@example.com"} {
		if strings.Contains(string(b), part) {
			t.Errorf("findings leak %q: %s", part, b)
		}
	}
}

func TestKeycloakConfigIsStrict(t *testing.T) {
	base := "sources:\n  - {type: kibana, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: x, mapper: keycloak}\ndetectors:\n"
	for name, det := range map[string]string{
		"both fail lists":      "  - {type: authspike, key_field: client_ip, status_field: outcome, fail_statuses: [401], fail_values: [error]}\n",
		"username unhashed":    "  - {type: authspike, key_field: username, status_field: outcome, fail_values: [error]}\n",
		"typo in key":          "  - {type: authspike, key_field: client_ip, status_field: outcome, fail_value: [error]}\n",
		"signup mixed modes":   "  - {type: signup, event_field: event_type, create_values: [REGISTER], path_field: path}\n",
		"signup event no vals": "  - {type: signup, event_field: event_type}\n",
		"signup typo":          "  - {type: signup, event_field: event_type, create_value: [REGISTER]}\n",
	} {
		if _, err := Parse([]byte(base + det)); err == nil {
			t.Errorf("%s: accepted at load", name)
		}
	}
	if _, err := Parse([]byte(base + "  - {type: authspike, key_field: username, hash_keys: true, status_field: outcome, fail_values: [error]}\n")); err != nil {
		t.Errorf("hashed username key refused: %v", err)
	}
}
