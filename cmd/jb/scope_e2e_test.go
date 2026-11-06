package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

// Two fake Kibanas, two indices, two mappers, one hunt. The ingress index holds nginx
// access lines, the Keycloak index holds Keycloak event lines; each detector is scoped
// to the index it can read. Everything is synthetic (RFC 5737 addresses, example.com).

func nginxLine(at time.Time, ip, method, path string, status int) doc {
	line := fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d 52 "-" "ExampleAgent/1.0" 310 0.004 [example-svc-80] [] 10.0.0.5:8080 52 0.004 %d req0001`,
		ip, at.UTC().Format("02/Jan/2006:15:04:05 -0700"), method, path, status, status)
	return doc{at: at, fields: map[string]any{"message": line}}
}

func kcLine(at time.Time, typ, ip string) doc {
	line := fmt.Sprintf(`type="%s", realmName="demo", clientId="web-app", userId="null", ipAddress="%s"`, typ, ip)
	if strings.HasSuffix(typ, "_ERROR") {
		line += `, error="email_in_use"`
	}
	return doc{at: at, fields: map[string]any{"message": line}}
}

const scopeE2EHead = `
sources:
  - type: kibana
    name: ingress
    url: %s
    api_key_env: JB_KIBANA_API_KEY
    index: ingress-example-*
    mapper: nginx_ingress
    filter:
      - match_phrase: {field: message, value: /auth/login}
  - type: kibana
    name: keycloak
    url: %s
    api_key_env: JB_KIBANA_API_KEY
    index: keycloak-example-*
    mapper: keycloak
    filter:
      - match_phrase: {field: message, value: REGISTER}
detectors:
`

const scopedDetectors = `
  - type: authspike
    name: ingress-stuffing
    sources: [ingress]
    empty_is_quiet: true
    key_field: client_ip
    status_field: status
    path_field: path
    path_contains: /auth/login
  - type: signup
    name: kc-signup
    sources: [keycloak]
    empty_is_quiet: true
    event_field: event_type
    create_values: [REGISTER]
    attempt_values: [REGISTER_ERROR]
    min_attempts: 20
`

// The same detectors as a first attempt would have written them: every source, no
// quiet option. They are the control that shows what scoping fixes.
const unscopedDetectors = `
  - type: authspike
    name: ingress-stuffing
    key_field: client_ip
    status_field: status
    path_field: path
    path_contains: /auth/login
  - type: signup
    name: kc-signup
    event_field: event_type
    create_values: [REGISTER]
    attempt_values: [REGISTER_ERROR]
    min_attempts: 20
`

func huntTwoSources(t *testing.T, ingress, kc []doc, detectors string) app.Result {
	t.Helper()
	ing := newFakeIndex(t, ingress)
	kci := newFakeIndex(t, kc)
	f, err := config.Parse([]byte(fmt.Sprintf(scopeE2EHead, ing.srv.URL, kci.srv.URL) + detectors))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(func(string) (string, bool) { return secretKey, true })
	if err != nil {
		t.Fatal(err)
	}
	st, err := duckdb.Open(filepath.Join(t.TempDir(), "e2e.duckdb"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	w := core.Window{From: fixedNow.Add(-time.Hour), To: fixedNow}
	res, err := app.Hunt(context.Background(), runDeps(rt, rt.Detectors, st), "e2e", w)
	if err != nil {
		t.Fatalf("hunt: %v", err)
	}
	return res
}

// Ordinary hour: logins that mostly work, Keycloak logins and nobody registering.
func ordinaryHour(w time.Time) (ingress, kc []doc) {
	for i := 0; i < 30; i++ {
		at := w.Add(time.Duration(i+1) * time.Minute)
		status := 200
		if i%15 == 0 {
			status = 401
		}
		ingress = append(ingress, nginxLine(at, "198.51.100."+fmt.Sprint(10+i%5), "POST", "/auth/login", status))
		kc = append(kc, kcLine(at, "LOGIN", "203.0.113.20"))
	}
	return ingress, kc
}

func TestScopedDetectorsRunQuietInAnHourWithNoRegistrations(t *testing.T) {
	var ingress, kc []doc
	for _, w := range []time.Time{fixedNow.Add(-2 * time.Hour), fixedNow.Add(-time.Hour)} {
		i, k := ordinaryHour(w)
		ingress, kc = append(ingress, i...), append(kc, k...)
	}

	res := huntTwoSources(t, ingress, kc, scopedDetectors)
	if !res.Complete() {
		t.Fatalf("a quiet hour made the hunt incomplete: %+v", res.Failures())
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings in a quiet hour: %+v", res.Findings)
	}
	var kcSrc app.SourceResult
	for _, s := range res.Sources {
		if s.Name == "keycloak" {
			kcSrc = s
		}
	}
	if !kcSrc.NoMatch() {
		t.Errorf("the keycloak source should report no match with its index alive, got %+v", kcSrc)
	}

	// Control: the same hour with the detectors reading every source and no quiet option
	// is INCOMPLETE, which is the failure this change fixes.
	ctl := huntTwoSources(t, ingress, kc, unscopedDetectors)
	if ctl.Complete() {
		t.Fatal("control: unscoped detectors without empty_is_quiet should fail in an hour with no registrations")
	}
}

func TestScopedDetectorsStillFlagAFailedSignupBurst(t *testing.T) {
	var ingress, kc []doc
	for _, w := range []time.Time{fixedNow.Add(-2 * time.Hour), fixedNow.Add(-time.Hour)} {
		i, k := ordinaryHour(w)
		ingress, kc = append(ingress, i...), append(kc, k...)
	}
	cur := fixedNow.Add(-time.Hour)
	for i := 0; i < 40; i++ {
		kc = append(kc, kcLine(cur.Add(time.Duration(i+1)*time.Minute/2), "REGISTER_ERROR", "203.0.113.30"))
	}
	kc = append(kc, kcLine(fixedNow.Add(-90*time.Minute), "REGISTER_ERROR", "203.0.113.30")) // one in the baseline

	res := huntTwoSources(t, ingress, kc, scopedDetectors)
	if !res.Complete() {
		t.Fatalf("incomplete: %+v", res.Failures())
	}
	var got *core.Finding
	for i, f := range res.Findings {
		if f.Tag == "kc-signup:attempts" {
			got = &res.Findings[i]
		}
	}
	if got == nil {
		t.Fatalf("the failed-signup burst was not flagged: %+v", res.Findings)
	}
	// Counted from the Keycloak events alone: the 30 ingress lines of the hour are not
	// in the detector's count, not even as unparsable.
	if got.Detail["attempts_cur"] != 40 || got.Detail["unparsable_cur"] != 0 {
		t.Errorf("detail = %v, want 40 attempts and 0 unparsable (ingress events must not reach this detector)", got.Detail)
	}
}
