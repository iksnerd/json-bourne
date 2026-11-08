package jb

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const intelTestKey = "SENTINEL-GN-KEY-0123456789abcdef"

// intelCaseWithFeed copies the example case and adds a greynoise feed pointed at a fake
// server. Answers: 192.0.2.7 is malicious, 192.0.2.99 was never seen (404), any other
// address makes the feed fail with HTTP 500.
func intelCaseWithFeed(t *testing.T) (dir string, paths func() []string) {
	t.Helper()
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.URL.Path)
		mu.Unlock()
		switch strings.TrimPrefix(r.URL.Path, "/v3/community/") {
		case "192.0.2.7":
			fmt.Fprint(w, `{"ip":"192.0.2.7","noise":true,"riot":false,"classification":"malicious","last_seen":"2026-11-03"}`)
		case "192.0.2.99":
			w.WriteHeader(404)
		default:
			w.WriteHeader(500)
			fmt.Fprintf(w, "echo %s", intelTestKey)
		}
	}))
	t.Cleanup(srv.Close)
	dir = copyCase(t)
	p := filepath.Join(dir, "config", "hunt.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	add := fmt.Sprintf("\nfeeds:\n  - type: greynoise\n    base_url: %s\n    api_key_env: JB_GREYNOISE_API_KEY\n    min_interval: 0s\n", srv.URL)
	if err := os.WriteFile(p, append(b, []byte(add)...), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), got...) }
}

func intelEnv(k string) (string, bool) {
	if k == "JB_GREYNOISE_API_KEY" {
		return intelTestKey, true
	}
	return "", false
}

func TestIntelAsksTheFeedAndSaysWhenALookupGotNoAnswer(t *testing.T) {
	dir, paths := intelCaseWithFeed(t)
	res, err := Intel(t.Context(), dir, []string{"192.0.2.7", "192.0.2.99", "192.0.2.50"}, IntelOptions{Env: intelEnv})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() || len(res.Failures) != 1 || res.Failures[0].Indicator != "192.0.2.50" {
		t.Fatalf("the feed failed for one address, so the result is incomplete: %+v", res)
	}
	verdicts := map[string]string{}
	for _, r := range res.Results {
		verdicts[r.Indicator] = r.Verdict
	}
	if len(verdicts) != 2 || verdicts["192.0.2.99"] != "not_found" || !strings.HasPrefix(verdicts["192.0.2.7"], "classification=malicious") {
		t.Errorf("verdicts %v", verdicts)
	}
	m := keysOf(t, res)
	hasKeys(t, "IntelResult", m, "note", "complete", "results", "failures")
	if string(m["complete"]) != "false" {
		t.Errorf("complete = %s", m["complete"])
	}
	if b := fmt.Sprint(m); strings.Contains(b, intelTestKey) {
		t.Error("the credential or a hostile body reached the result")
	}
	for _, p := range paths() {
		if !strings.HasPrefix(p, "/v3/community/192.0.2.") {
			t.Errorf("request %q", p)
		}
	}
}

func TestIntelRefusesMistakesBeforeAskingAnyone(t *testing.T) {
	dir, paths := intelCaseWithFeed(t)
	for name, c := range map[string]struct {
		dir string
		ips []string
	}{
		"not an address":       {dir, []string{"example.com"}},
		"neither case nor cfg": {"", []string{"192.0.2.7"}},
	} {
		t.Run(name, func(t *testing.T) {
			if res, err := Intel(t.Context(), c.dir, c.ips, IntelOptions{Env: intelEnv}); !IsUsage(err) || res != nil {
				t.Errorf("want usage error, got %v, %v", res, err)
			}
		})
	}
	if _, err := Intel(t.Context(), dir, []string{"192.0.2.7"}, IntelOptions{Env: func(string) (string, bool) { return "", false }}); err == nil || IsUsage(err) || !strings.Contains(err.Error(), "JB_GREYNOISE_API_KEY") {
		t.Errorf("an unset key is a failure naming the variable, never a keyless fallback: %v", err)
	}
	if n := len(paths()); n != 0 {
		t.Errorf("refused runs reached the feed %d time(s)", n)
	}
}

func TestIntelWithoutAFeedIsAnErrorNotAnEmptyResult(t *testing.T) {
	if res, err := Intel(t.Context(), copyCase(t), []string{"192.0.2.7"}, IntelOptions{Env: intelEnv}); err == nil || res != nil || !strings.Contains(err.Error(), "feed") {
		t.Errorf("%v %v", res, err)
	}
}
