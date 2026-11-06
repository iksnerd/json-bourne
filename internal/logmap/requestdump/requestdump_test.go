package requestdump

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// testConfig is the configuration the corpus is written against. Every name is made up.
var testConfig = Config{
	ClientIPHeader:  "x-example-edge-client",
	UserAgentHeader: "user-agent",
	HeaderFields:    map[string]string{"probe_marker": "x-example-probe"},
}

func mapper(t testing.TB) *Mapper {
	t.Helper()
	m, err := New(testConfig)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The corpus is the contract. Each NAME.in.json is a document, each NAME.want.json is
// one of {"time","fields"}, {"unparsable":true} or {"bad_time":true}.
type want struct {
	Time       string         `json:"time"`
	Fields     map[string]any `json:"fields"`
	Unparsable bool           `json:"unparsable"`
	BadTime    bool           `json:"bad_time"`
}

func TestCorpus(t *testing.T) {
	ins, err := filepath.Glob("testdata/corpus/*.in.json")
	if err != nil || len(ins) < 30 {
		t.Fatalf("corpus not found or too small: %d files, err %v", len(ins), err)
	}
	m := mapper(t)
	for _, in := range ins {
		name := strings.TrimSuffix(filepath.Base(in), ".in.json")
		t.Run(name, func(t *testing.T) {
			doc, err := os.ReadFile(in)
			if err != nil {
				t.Fatal(err)
			}
			wb, err := os.ReadFile(strings.TrimSuffix(in, ".in.json") + ".want.json")
			if err != nil {
				t.Fatal(err)
			}
			var w want
			if err := json.Unmarshal(wb, &w); err != nil {
				t.Fatal(err)
			}
			ev, err := m.Map(doc)
			switch {
			case w.Unparsable:
				if !errors.Is(err, ErrUnparsable) {
					t.Fatalf("err = %v, want ErrUnparsable (event %v)", err, ev.Fields)
				}
				if ev.Fields != nil {
					t.Errorf("an unparsable document returned fields: %v", ev.Fields)
				}
			case w.BadTime:
				if !errors.Is(err, ErrBadTime) || errors.Is(err, ErrUnparsable) {
					t.Fatalf("err = %v, want ErrBadTime and not ErrUnparsable", err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				wt, perr := time.Parse(time.RFC3339Nano, w.Time)
				if perr != nil {
					t.Fatal(perr)
				}
				if !ev.Time.Equal(wt) {
					t.Errorf("time = %v, want %v", ev.Time, wt)
				}
				if !reflect.DeepEqual(ev.Fields, w.Fields) {
					t.Errorf("fields = %#v\nwant     %#v", ev.Fields, w.Fields)
				}
				if !json.Valid(ev.Raw) {
					t.Errorf("Raw is not JSON: %q", ev.Raw)
				}
			}
		})
	}
}

// Mapping is deterministic and does not keep the input.
func TestCorpusIsDeterministic(t *testing.T) {
	m := mapper(t)
	ins, _ := filepath.Glob("testdata/corpus/*.in.json")
	for _, in := range ins {
		doc, _ := os.ReadFile(in)
		a, ea := m.Map(doc)
		b, eb := m.Map(doc)
		if (ea == nil) != (eb == nil) || !reflect.DeepEqual(a, b) {
			t.Errorf("%s: two runs differ", filepath.Base(in))
		}
	}
}

// The header allowlist: whatever the dump holds and whatever the config says, no
// credential header reaches a field or Raw. Sentinels make a leak greppable.
func TestCredentialHeadersNeverReachFieldsOrRaw(t *testing.T) {
	const s1, s2, s3, s4 = "sentinel-bearer-1", "sentinel-cookie-2", "sentinel-key-3", "sentinel-query-4"
	msg := "=== Request Info ===\nmethod = POST\npath = /v1/example/items?otp=" + s4 + "\n" +
		"header = User-Agent    value = ExampleAgent/1.0\n" +
		"header = Authorization    value = Bearer " + s1 + "\n" +
		"header = Cookie    value = sid=" + s2 + "\n" +
		"header = Set-Cookie    value = sid=" + s2 + "\n" +
		"header = X-Api-Key    value = " + s3 + "\n" +
		"header = X-Example-Probe    value = ok\n"
	b, _ := json.Marshal(map[string]any{"@timestamp": "2026-11-05T12:00:00Z", "message": msg,
		"event": map[string]any{"original": msg}})
	ev, err := mapper(t).Map(b)
	if err != nil {
		t.Fatal(err)
	}
	all := fmt.Sprint(ev.Fields) + string(ev.Raw)
	for _, s := range []string{s1, s2, s3, s4} {
		if strings.Contains(all, s) {
			t.Errorf("sentinel %q leaked into the event", s)
		}
	}
	if !strings.Contains(string(ev.Raw), "[redacted]") || !strings.Contains(string(ev.Raw), "/v1/example/items") {
		t.Errorf("Raw should keep the dump with redactions: %s", ev.Raw)
	}
	if strings.Contains(string(ev.Raw), "event") {
		t.Errorf("Raw kept a member other than the redacted dump: %s", ev.Raw)
	}
	if ev.Fields["probe_marker"] != "ok" {
		t.Errorf("allowlisted marker missing: %v", ev.Fields)
	}
}

// Even if a configuration asks for one, a credential-bearing header is refused.
func TestConfigRefusesCredentialHeaders(t *testing.T) {
	for _, h := range []string{"Authorization", "proxy-authorization", "Cookie", "set-cookie", "x-auth-token",
		"x-api-key", "X-ApiKey", "x-csrf-token", "x-session-id", "x-xsrf", "x-client-secret", "x-bearer", "x-jwt", "x-password"} {
		for name, c := range map[string]Config{
			"header_fields":     {HeaderFields: map[string]string{"m": h}},
			"client_ip_header":  {ClientIPHeader: h},
			"user_agent_header": {UserAgentHeader: h},
		} {
			if _, err := New(c); err == nil || !strings.Contains(err.Error(), "never emitted") {
				t.Errorf("%s %q accepted: %v", name, h, err)
			}
		}
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []Config{
		{HeaderFields: map[string]string{"Bad": "x-a"}},
		{HeaderFields: map[string]string{"m": "has space"}},
		{HeaderFields: map[string]string{"m": ""}},
		{HeaderFields: map[string]string{"client_ip": "x-a"}},
		{HeaderFields: map[string]string{"path": "x-a"}},
		{ClientIPHeader: "x_a.b"},
		{ClientIPHeader: strings.Repeat("a", 65)},
	}
	for i, c := range bad {
		if _, err := New(c); err == nil {
			t.Errorf("bad config %d accepted: %+v", i, c)
		}
	}
	tooMany := map[string]string{}
	for i := 0; i <= MaxHeaderFields; i++ {
		tooMany[fmt.Sprintf("f%d", i)] = fmt.Sprintf("x-h%d", i)
	}
	if _, err := New(Config{HeaderFields: tooMany}); err == nil {
		t.Error("more than MaxHeaderFields accepted")
	}
	if _, err := ParseConfig(map[string]any{"client_ip_header": "x-a", "typo": 1}); err == nil {
		t.Error("unknown config key accepted")
	}
	if c, err := ParseConfig(nil); err != nil || !reflect.DeepEqual(c, Config{}) {
		t.Errorf("nil config: %+v, %v", c, err)
	}
	// The zero config reads method, path and the user agent only.
	m, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := m.Map([]byte(`{"@timestamp":"2026-11-05T12:00:00Z","message":"=== Request Info ===\nmethod = GET\npath = /x\nheader = User-Agent    value = A/1\nheader = X-Example-Edge-Client    value = 198.51.100.7\n"}`))
	if err != nil || !reflect.DeepEqual(ev.Fields, map[string]any{"method": "GET", "path": "/x", "user_agent": "A/1"}) {
		t.Errorf("zero config: %v, %v", ev.Fields, err)
	}
}

// A marker value over MaxMarkerBytes (but under the header limit) is not carried as a
// different value: the field is absent.
func TestOversizedMarkerValueIsNotCarried(t *testing.T) {
	msg := "=== Request Info ===\nmethod = GET\npath = /x\nheader = X-Example-Probe    value = " + strings.Repeat("v", MaxMarkerBytes+1) + "\n"
	b, _ := json.Marshal(map[string]any{"@timestamp": "2026-11-05T12:00:00Z", "message": msg})
	ev, err := mapper(t).Map(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := ev.Fields["probe_marker"]; has {
		t.Errorf("oversized marker carried: %v", ev.Fields)
	}
}

// No status is invented: the dump has none.
func TestNoStatusIsInvented(t *testing.T) {
	ins, _ := filepath.Glob("testdata/corpus/*.in.json")
	m := mapper(t)
	for _, in := range ins {
		doc, _ := os.ReadFile(in)
		if ev, err := m.Map(doc); err == nil {
			if _, has := ev.Fields["status"]; has {
				t.Errorf("%s: status emitted", filepath.Base(in))
			}
		}
	}
}

// Hostile input never panics and stays linear: a long run of header-looking text and a
// pathological value return promptly.
func TestHostileInputTerminates(t *testing.T) {
	m := mapper(t)
	cases := []string{
		`{"@timestamp":"2026-11-05T12:00:00Z","message":"=== Request Info ===\nmethod = GET\npath = /x\n` + strings.Repeat(`header = `, 6000) + `"}`,
		`{"@timestamp":"2026-11-05T12:00:00Z","message":"=== Request Info ===\nmethod = GET\npath = /x\nheader = ` + strings.Repeat("a", 60000) + `"}`,
		`{"@timestamp":"2026-11-05T12:00:00Z","message":"=== Request Info ===\nmethod = GET\npath = /x\nheader = X` + strings.Repeat(" ", 60000) + `value ="}`,
		strings.Repeat("{", 100000),
		"",
		"null",
	}
	start := time.Now()
	for i, c := range cases {
		_, _ = m.Map([]byte(c))
		_ = i
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("hostile input took %v", d)
	}
}

func FuzzMap(f *testing.F) {
	f.Add([]byte(`{"@timestamp":"2026-11-05T12:00:00Z","message":"=== Request Info ===\nmethod = GET\npath = /x\nheader = User-Agent    value = A\n"}`))
	m, _ := New(testConfig)
	f.Fuzz(func(t *testing.T, b []byte) {
		ev, err := m.Map(b)
		if err != nil && ev.Fields != nil {
			t.Fatal("error with fields")
		}
	})
}
