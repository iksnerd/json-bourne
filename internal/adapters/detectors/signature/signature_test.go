package signature

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/piiguard"
)

// All data is synthetic: RFC 5737 addresses and an invented marker.
const (
	addrA = "198.51.100.7"
	addrB = "203.0.113.9"
	addrC = "192.0.2.44"
)

var (
	t0  = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	win = core.Window{From: t0, To: t0.Add(10 * time.Minute)}
)

type reader struct {
	evs []core.Event
	err error
}

func (r reader) Events(_ context.Context, _ core.Window) iter.Seq2[core.Event, error] {
	return func(yield func(core.Event, error) bool) {
		for _, ev := range r.evs {
			if !yield(ev, nil) {
				return
			}
		}
		if r.err != nil {
			yield(core.Event{}, r.err)
		}
	}
}

// explode fails the test if the detector reads it.
type explode struct{ t *testing.T }

func (e explode) Events(context.Context, core.Window) iter.Seq2[core.Event, error] {
	e.t.Helper()
	e.t.Fatal("the preceding window was read")
	return nil
}

type ev struct {
	ip, path string
	marker   any // nil = header absent
	at       int // seconds after t0
}

func events(es ...ev) []core.Event {
	var out []core.Event
	for _, e := range es {
		f := map[string]any{}
		if e.ip != "" {
			f["client_ip"] = e.ip
		}
		if e.path != "" {
			f["path"] = e.path
		}
		if e.marker != nil {
			f["probe_marker"] = e.marker
		}
		out = append(out, core.Event{Time: t0.Add(time.Duration(e.at) * time.Second), Source: "synthetic", Fields: f})
	}
	return out
}

func presentCfg() Config {
	return Config{Field: "probe_marker", Present: true, KeyField: "client_ip", PathField: "path"}
}

func run(t *testing.T, c Config, cur []core.Event) ([]core.Finding, error) {
	t.Helper()
	d, err := New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d.Detect(context.Background(), reader{evs: cur}, explode{t}, win)
}

func TestPresentRaisesHighOnFirstSight(t *testing.T) {
	cur := events(
		ev{ip: addrC, path: "/v1/a"}, ev{ip: addrC, path: "/v1/b"}, // ordinary traffic
		ev{ip: addrA, path: "/v1/items", marker: "sentinel-value-1", at: 30},
		ev{ip: addrA, path: "/v1/items", marker: "sentinel-value-1", at: 90},
		ev{ip: addrB, path: "/v1/other", marker: "sentinel-value-2", at: 10},
		ev{path: "/v1/other", marker: "sentinel-value-2", at: 20}, // no client address
	)
	fs, err := run(t, presentCfg(), cur)
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings %+v, err %v", fs, err)
	}
	f := fs[0]
	if f.Tag != "signature:probe_marker" || f.Detector != "signature" || f.Severity != core.SevHigh || f.Window != win {
		t.Errorf("tag %q detector %q severity %v window %v", f.Tag, f.Detector, f.Severity, f.Window)
	}
	d := f.Detail
	if d["events"] != 4 || d["distinct_keys"] != 2 || d["unkeyed_events"] != 1 || d["events_in_window"] != 6 ||
		d["first"] != "2026-11-05T12:00:10Z" || d["last"] != "2026-11-05T12:01:30Z" || d["distinct_paths"] != 2 ||
		d["distinct_values"] != 2 || d["mode"] != "present" {
		t.Errorf("detail %v", d)
	}
	// What the finding must say: that a hit is a sent marker, not an identity.
	if !strings.Contains(f.Summary, "not who sent it") {
		t.Errorf("summary does not say a hit proves the marker was sent, not by whom: %s", f.Summary)
	}
}

// A finding never repeats a header value, a path or the user's ordinary traffic.
func TestFindingNeverCarriesTheValueOrPaths(t *testing.T) {
	cur := events(ev{ip: addrA, path: "/v1/secret-path-sentinel", marker: "sentinel-value-1"})
	fs, err := run(t, presentCfg(), cur)
	if err != nil || len(fs) != 1 {
		t.Fatalf("%+v, %v", fs, err)
	}
	s := fmt.Sprint(fs[0].Tag, "|", fs[0].Summary, "|", fs[0].Detail)
	if strings.Contains(s, "sentinel") {
		t.Fatalf("finding leaks a value or path: %s", s)
	}
	hs, _ := fs[0].Detail["value_hashes"].([]string)
	if len(hs) != 1 || hs[0] != piiguard.Hash("sentinel-value-1") {
		t.Errorf("value_hashes = %v, want the digest of the value", fs[0].Detail["value_hashes"])
	}
}

func TestPresentCountsAnEmptyValueAsPresent(t *testing.T) {
	fs, err := run(t, presentCfg(), events(ev{ip: addrA, marker: ""}, ev{ip: addrC}))
	if err != nil || len(fs) != 1 || fs[0].Detail["events"] != 1 {
		t.Fatalf("%+v, %v", fs, err)
	}
}

func TestWindowWithEventsAndNoMarkerIsQuiet(t *testing.T) {
	fs, err := run(t, presentCfg(), events(ev{ip: addrC, path: "/v1/a"}, ev{ip: addrB, path: "/v1/b"}))
	if err != nil || len(fs) != 0 {
		t.Fatalf("%+v, %v; want quiet", fs, err)
	}
}

func TestEqualsMatchesOnlyTheListedValues(t *testing.T) {
	c := Config{Field: "probe_marker", Equals: []string{"case-17", "case-18"}, KeyField: "client_ip"}
	cur := events(
		ev{ip: addrA, marker: "case-17"}, ev{ip: addrA, marker: "case-17"},
		ev{ip: addrB, marker: "case-18"},
		ev{ip: addrC, marker: "CASE-17"},  // exact, case-sensitive
		ev{ip: addrC, marker: "case-17 "}, // not trimmed here: the mapper trims
		ev{ip: addrC, marker: "other-unlisted-sentinel"},
	)
	fs, err := run(t, c, cur)
	if err != nil || len(fs) != 2 {
		t.Fatalf("%+v, %v", fs, err)
	}
	if fs[0].Tag != "signature:probe_marker=case-17" || fs[1].Tag != "signature:probe_marker=case-18" {
		t.Errorf("tags %q %q", fs[0].Tag, fs[1].Tag)
	}
	if fs[0].Detail["events"] != 2 || fs[0].Detail["expected_value"] != "case-17" || fs[1].Detail["events"] != 1 || fs[0].Detail["mode"] != "equals" {
		t.Errorf("detail %v / %v", fs[0].Detail, fs[1].Detail)
	}
	for _, f := range fs {
		if strings.Contains(fmt.Sprint(f.Summary, f.Detail), "unlisted-sentinel") {
			t.Errorf("a value that is not a configured marker appears: %v", f)
		}
		if _, has := f.Detail["value_hashes"]; has {
			t.Errorf("equals mode needs no hashes: the matched value is the configured one")
		}
	}
}

func TestEmptyWindowIsNoRecordsUnlessQuietIsEnabled(t *testing.T) {
	if _, err := run(t, presentCfg(), nil); !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want ErrNoRecords", err)
	}
	c := presentCfg()
	c.EmptyIsQuiet = true
	if fs, err := run(t, c, nil); err != nil || len(fs) != 0 {
		t.Fatalf("%+v, %v; want quiet", fs, err)
	}
}

// Events that exist but cannot be read are a blind detector even with empty_is_quiet.
func TestUnreadableEventsAreNoRecordsEvenWhenQuiet(t *testing.T) {
	c := presentCfg()
	c.EmptyIsQuiet = true
	_, err := run(t, c, events(ev{ip: addrA, marker: 17}, ev{ip: addrB, marker: true}))
	if !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want ErrNoRecords", err)
	}
	// One readable event among them is enough to judge, and the unreadable ones are counted.
	fs, err := run(t, c, events(ev{ip: addrA, marker: 17}, ev{ip: addrB, marker: "x"}))
	if err != nil || len(fs) != 1 || fs[0].Detail["unreadable_events"] != 1 {
		t.Fatalf("%+v, %v", fs, err)
	}
}

func TestSourceErrorStopsTheDetector(t *testing.T) {
	d, _ := New(presentCfg())
	boom := errors.New("backend down")
	_, err := d.Detect(context.Background(), reader{evs: events(ev{ip: addrA, marker: "x"}), err: boom}, explode{t}, win)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the reader's error", err)
	}
}

func TestCancelledContextStops(t *testing.T) {
	d, _ := New(presentCfg())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Detect(ctx, reader{evs: events(ev{ip: addrA, marker: "x"})}, explode{t}, win); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestIgnoredKeysNeverCount(t *testing.T) {
	c := presentCfg()
	c.IgnoreKeys = []string{addrA} // our own test machine
	cur := events(ev{ip: addrA, marker: "x"}, ev{ip: addrA, marker: "x"})
	fs, err := run(t, c, cur)
	if err != nil || len(fs) != 0 {
		t.Fatalf("an ignored key was raised: %+v, %v", fs, err)
	}
	fs, err = run(t, c, append(cur, events(ev{ip: addrB, marker: "x"})...))
	if err != nil || len(fs) != 1 || fs[0].Detail["events"] != 1 || fs[0].Detail["ignored_events"] != 2 {
		t.Fatalf("%+v, %v", fs, err)
	}
}

func TestPersonalKeyNeedsHashing(t *testing.T) {
	c := presentCfg()
	c.KeyField = "email"
	if _, err := New(c); err == nil || !strings.Contains(err.Error(), "personal data") {
		t.Fatalf("err = %v", err)
	}
	c.HashKeys = true
	d, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	cur := []core.Event{{Time: t0, Fields: map[string]any{"email": "sentinel.person@example.com", "probe_marker": "x"}}}
	fs, err := d.Detect(context.Background(), reader{evs: cur}, explode{t}, win)
	if err != nil || len(fs) != 1 {
		t.Fatalf("%+v, %v", fs, err)
	}
	if s := fmt.Sprint(fs[0].Tag, fs[0].Summary, fs[0].Detail); strings.Contains(s, "sentinel") || strings.Contains(s, "@") {
		t.Fatalf("finding leaks the key: %s", s)
	}
}

func TestTagIsStableAcrossRuns(t *testing.T) {
	a, _ := run(t, presentCfg(), events(ev{ip: addrA, marker: "x"}))
	b, _ := run(t, presentCfg(), events(ev{ip: addrB, marker: "y"}, ev{ip: addrC, marker: "z"}))
	if len(a) != 1 || len(b) != 1 || a[0].Tag != b[0].Tag {
		t.Fatalf("tags differ across runs: %v vs %v", a, b)
	}
}

func TestKeysListIsBounded(t *testing.T) {
	var es []ev
	for i := 0; i < 40; i++ {
		es = append(es, ev{ip: fmt.Sprintf("192.0.2.%d", i+1), marker: "x"})
	}
	fs, err := run(t, presentCfg(), events(es...))
	if err != nil || len(fs) != 1 {
		t.Fatal(fs, err)
	}
	if ks, _ := fs[0].Detail["keys"].([]string); len(ks) != maxKeysShow || fs[0].Detail["distinct_keys"] != 40 || fs[0].Detail["keys_truncated"] != true {
		t.Errorf("keys %v distinct %v truncated %v", fs[0].Detail["keys"], fs[0].Detail["distinct_keys"], fs[0].Detail["keys_truncated"])
	}
}

func TestConfigIsStrict(t *testing.T) {
	good := presentCfg()
	for name, mod := range map[string]func(*Config){
		"neither mode":      func(c *Config) { c.Present = false },
		"both modes":        func(c *Config) { c.Equals = []string{"a"} },
		"no field":          func(c *Config) { c.Field = "" },
		"bad field":         func(c *Config) { c.Field = "has space" },
		"no key field":      func(c *Config) { c.KeyField = " " },
		"bad name":          func(c *Config) { c.Name = "Bad Name" },
		"empty equals":      func(c *Config) { c.Present = false; c.Equals = []string{""} },
		"multi-line equals": func(c *Config) { c.Present = false; c.Equals = []string{"a\nb"} },
		"long equals":       func(c *Config) { c.Present = false; c.Equals = []string{strings.Repeat("a", maxValue+1)} },
		"too many equals": func(c *Config) {
			c.Present = false
			c.Equals = nil
			for i := 0; i <= maxEquals; i++ {
				c.Equals = append(c.Equals, fmt.Sprint("v", i))
			}
		},
	} {
		c := good
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
}

func TestNilReader(t *testing.T) {
	d, _ := New(presentCfg())
	if _, err := d.Detect(context.Background(), nil, nil, win); err == nil {
		t.Fatal("nil reader accepted")
	}
}
