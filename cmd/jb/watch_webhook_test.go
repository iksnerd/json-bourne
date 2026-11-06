package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const hookToken = "T0K3N-sentinel-cli-1a2b3c4d5e"

// hook is a hostile webhook receiver: on failure it reflects the URL path it was called on.
type hook struct {
	srv    *httptest.Server
	mu     sync.Mutex
	texts  []string
	status int
}

func newHook(t *testing.T, status int) *hook {
	t.Helper()
	h := &hook{status: status}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]string
		_ = json.Unmarshal(b, &m)
		h.mu.Lock()
		h.texts = append(h.texts, m["text"])
		h.mu.Unlock()
		w.WriteHeader(h.status)
		fmt.Fprintf(w, "ok? you called %s on %s", r.URL.Path, r.Host)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hook) url() string { return h.srv.URL + "/services/" + hookToken }

func withWebhook(t *testing.T, dir string) {
	t.Helper()
	p := filepath.Join(dir, "config", "hunt.yaml")
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("\nalerts:\n  - type: webhook\n    url_env: JB_ALERT_WEBHOOK_URL\n    min_severity: high\n    timeout: 5s\n    min_interval: 0s\n    allow_insecure_loopback: true\n"); err != nil {
		t.Fatal(err)
	}
}

// nothingHoldsTheToken fails if the token is in any file of the case, the evidence
// store included, or in what the command printed.
func nothingHoldsTheToken(t *testing.T, dir string, printed ...string) {
	t.Helper()
	for _, p := range printed {
		if strings.Contains(p, hookToken) {
			t.Errorf("the webhook token was printed:\n%s", p)
		}
	}
	_ = filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), hookToken) {
			t.Errorf("the webhook token is in %s", p)
		}
		return nil
	})
}

func TestWatchOnceDeliversToTheWebhookInAdditionToTheLog(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	withWebhook(t, dir)
	h := newHook(t, http.StatusOK)
	env := map[string]string{"JB_KIBANA_API_KEY": secretKey, "JB_ALERT_WEBHOOK_URL": h.url()}
	code, stdout, stderr := run(t, testDeps(env), "watch", "--case", dir, "--once")
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if len(h.texts) != 1 || !strings.Contains(h.texts[0], "192.0.2.7") || !strings.HasPrefix(h.texts[0], "[high] ") {
		t.Errorf("webhook got %q (the cycle line is info and below min_severity)", h.texts)
	}
	if !strings.Contains(readEvidence(t, dir, "watch.log"), "192.0.2.7") || !strings.Contains(stdout, "192.0.2.7") {
		t.Error("the log and stdout must still hold the alert")
	}
	nothingHoldsTheToken(t, dir, stdout, stderr)
}

func TestWatchOnceWebhookDownFailsTheCycleButTheLogHasTheAlert(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	withWebhook(t, dir)
	h := newHook(t, http.StatusServiceUnavailable)
	env := map[string]string{"JB_KIBANA_API_KEY": secretKey, "JB_ALERT_WEBHOOK_URL": h.url()}
	code, stdout, stderr := run(t, testDeps(env), "watch", "--case", dir, "--once")
	if code != exitFailure {
		t.Fatalf("exit %d, want 1\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	for _, want := range []string{"192.0.2.7", "CYCLE FAILED", "not delivered to an optional sink"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if !strings.Contains(stderr, "HTTP 503") {
		t.Errorf("stderr does not say why: %q", stderr)
	}
	if !strings.Contains(readEvidence(t, dir, "watch-state.json"), "192.0.2.7") {
		t.Error("an alert the log has must be remembered")
	}
	nothingHoldsTheToken(t, dir, stdout, stderr)
}

func TestWatchWebhookConfigurationErrorsStopBeforeAnyHunt(t *testing.T) {
	dir, served := watchCase(t, http.StatusOK)
	withWebhook(t, dir)
	for name, url := range map[string]string{
		"unset":                             "",
		"plain http to a non-loopback host": "http://198.51.100.7/services/" + hookToken,
	} {
		t.Run(name, func(t *testing.T) {
			env := map[string]string{"JB_KIBANA_API_KEY": secretKey}
			if url != "" {
				env["JB_ALERT_WEBHOOK_URL"] = url
			}
			code, stdout, stderr := run(t, testDeps(env), "watch", "--case", dir, "--once")
			if code == 0 || !strings.Contains(stderr, "alerts[0]") {
				t.Errorf("exit %d stderr %q", code, stderr)
			}
			nothingHoldsTheToken(t, dir, stdout, stderr)
		})
	}
	if served() != 0 {
		t.Errorf("a misconfigured webhook let the hunt run (%d requests)", served())
	}
}

func TestWatchPastedURLInUrlEnvIsRefusedAtLoad(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	withWebhook(t, dir)
	editFile(t, filepath.Join(dir, "config", "hunt.yaml"), "url_env: JB_ALERT_WEBHOOK_URL", "url_env: \"https://hooks.example.test/services/"+hookToken+"\"")
	code, stdout, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once")
	if code == 0 || !strings.Contains(stderr, "url_env") {
		t.Errorf("exit %d stderr %q", code, stderr)
	}
	if strings.Contains(stdout+stderr, hookToken) || strings.Contains(stdout+stderr, "hooks.example") {
		t.Errorf("the pasted URL was echoed:\n%s%s", stdout, stderr)
	}
}
