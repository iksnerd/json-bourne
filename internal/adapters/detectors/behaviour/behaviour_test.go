package behaviour

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// All data is synthetic: RFC 5737 documentation addresses and example names.
const (
	gateway = "192.0.2.1"
	c1      = "198.51.100.7"
)

var (
	t0  = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	win = core.Window{From: t0, To: t0.Add(10 * time.Minute)}
)

type ev struct {
	key, path, method, ua string
	status                any
	n                     int
	extra                 map[string]any
	noKey                 bool
}

func events(w core.Window, es ...ev) []core.Event {
	var out []core.Event
	for _, e := range es {
		for i := 0; i < e.n; i++ {
			f := map[string]any{"path": e.path, "status": e.status, "method": e.method, "ua": e.ua}
			if e.status == nil {
				f["status"] = 200
			}
			if !e.noKey {
				f["client"] = e.key
			}
			for k, v := range e.extra {
				f[k] = v
			}
			out = append(out, core.Event{Time: w.From.Add(time.Duration(len(out)) * time.Millisecond), Fields: f})
		}
	}
	return out
}

type fakeReader struct {
	evs []core.Event
	err error
}

func (f fakeReader) Events(_ context.Context, _ core.Window) iter.Seq2[core.Event, error] {
	return func(yield func(core.Event, error) bool) {
		for _, e := range f.evs {
			if !yield(e, nil) {
				return
			}
		}
		if f.err != nil {
			yield(core.Event{}, f.err)
		}
	}
}

func cfg() Config {
	return Config{
		KeyField: "client", PathField: "path", MethodField: "method", StatusField: "status",
		UserAgentField: "ua", IgnoreKeys: []string{gateway}, IgnoreUserAgents: []string{"gateway-http"},
		Actions: []Action{
			{Name: "device-code", Class: ClassRare, Path: "/oauth/device/code", Methods: []string{"POST"}},
			{Name: "signup", Class: ClassRare, Path: "/signup", Methods: []string{"POST"}, Statuses: []int{200, 201, 302}},
			{Name: "token", Class: ClassCommon, Path: "/oauth/token", Methods: []string{"POST"}},
		},
	}
}

func mustNew(t *testing.T, c Config) *Detector {
	t.Helper()
	d, err := New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func detect(t *testing.T, c Config, cur, prev []core.Event) ([]core.Finding, error) {
	t.Helper()
	return mustNew(t, c).Detect(context.Background(), fakeReader{evs: cur}, fakeReader{evs: prev}, win)
}

// noise is ordinary platform traffic on a path that is no action: it keeps the
// windows non-empty.
func noise() ev { return ev{key: "203.0.113.5", path: "/home", method: "GET", n: 50} }

// tokenTraffic is a busy common action: ok 2xx and bad 401s.
func tokenTraffic(ok, bad int) []ev {
	return []ev{
		{key: "203.0.113.10", path: "/oauth/token", method: "POST", n: ok},
		{key: "203.0.113.11", path: "/oauth/token", method: "POST", status: 401, n: bad},
	}
}

func byTag(fs []core.Finding) map[string]core.Finding {
	m := map[string]core.Finding{}
	for _, f := range fs {
		m[f.Tag] = f
	}
	return m
}

func TestRareActionRaisedWithKeyCount(t *testing.T) {
	cur := events(win, noise(),
		ev{key: c1, path: "/oauth/device/code", method: "POST", n: 3},
		ev{key: "198.51.100.8", path: "/oauth/device/code", method: "POST", n: 1})
	prev := events(win.Previous(), noise())
	fs, err := detect(t, cfg(), cur, prev)
	if err != nil {
		t.Fatal(err)
	}
	f, ok := byTag(fs)["behaviour:device-code"]
	if !ok || len(fs) != 1 {
		t.Fatalf("findings %+v", fs)
	}
	if f.Severity != core.SevActivity {
		t.Errorf("severity %v", f.Severity)
	}
	d := f.Detail
	if d["cur_events"] != 4 || d["prev_events"] != 0 || d["keys_cur"] != 2 || d["new"] != true || d["baseline_empty"] != false {
		t.Errorf("detail %+v", d)
	}
	if !strings.Contains(f.Summary, "2 distinct key") {
		t.Errorf("summary must state the key count: %s", f.Summary)
	}
	if f.Window != win || f.Baseline != win.Previous() {
		t.Errorf("windows %v %v", f.Window, f.Baseline)
	}
}

func TestRareSoleKeyReportedOnlyWhenOne(t *testing.T) {
	cur := events(win, noise(), ev{key: c1, path: "/oauth/device/code", method: "POST", n: 2})
	fs, _ := detect(t, cfg(), cur, events(win.Previous(), noise()))
	if fs[0].Detail["sole_key"] != c1 || fs[0].Detail["keys_cur"] != 1 {
		t.Errorf("detail %+v", fs[0].Detail)
	}
}

func TestRareBelowMinEventsAndNothingNotRaised(t *testing.T) {
	c := cfg()
	c.Actions[0].MinEvents = 3
	cur := events(win, noise(), ev{key: c1, path: "/oauth/device/code", method: "POST", n: 2})
	fs, err := detect(t, c, cur, events(win.Previous(), noise()))
	if err != nil || len(fs) != 0 {
		t.Fatalf("fs %+v err %v", fs, err)
	}
	fs, err = detect(t, cfg(), events(win, noise()), events(win.Previous(), noise()))
	if err != nil || len(fs) != 0 {
		t.Fatalf("clean window: fs %+v err %v", fs, err)
	}
}

func TestRareWithBaselineStillRaisedAndShowsBoth(t *testing.T) {
	cur := events(win, noise(), ev{key: c1, path: "/oauth/device/code", method: "POST", n: 4})
	prev := events(win.Previous(), noise(), ev{key: c1, path: "/oauth/device/code", method: "POST", n: 2})
	fs, _ := detect(t, cfg(), cur, prev)
	if len(fs) != 1 || fs[0].Detail["new"] != false || fs[0].Detail["prev_events"] != 2 || fs[0].Detail["cur_events"] != 4 {
		t.Fatalf("%+v", fs)
	}
	if !strings.Contains(fs[0].Summary, "preceding window 2") {
		t.Errorf("summary %s", fs[0].Summary)
	}
}

func TestEmptyBaselineLowersSeverityAndIsReported(t *testing.T) {
	cur := events(win, noise(),
		ev{key: c1, path: "/oauth/device/code", method: "POST", n: 1})
	fs, err := detect(t, cfg(), cur, nil)
	if err != nil || len(fs) != 1 {
		t.Fatalf("fs %+v err %v", fs, err)
	}
	if fs[0].Severity != core.SevCheck || fs[0].Detail["baseline_empty"] != true {
		t.Errorf("%v %+v", fs[0].Severity, fs[0].Detail)
	}
	// common action: one step below high.
	cur = events(win, tokenTraffic(10, 40)...)
	fs, err = detect(t, cfg(), cur, nil)
	if err != nil || len(fs) != 1 || fs[0].Severity != core.SevActivity || fs[0].Detail["baseline_empty"] != true {
		t.Fatalf("fs %+v err %v", fs, err)
	}
}

func TestEmptyCurrentWindowIsNoRecords(t *testing.T) {
	_, err := detect(t, cfg(), nil, events(win.Previous(), noise()))
	if !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err %v", err)
	}
	// Only ignored infrastructure, or events with no path, is no judged event.
	cur := events(win, ev{key: gateway, path: "/oauth/device/code", method: "POST", n: 5},
		ev{key: c1, path: "", n: 3})
	_, err = detect(t, cfg(), cur, events(win.Previous(), noise()))
	if !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("ignored-only window: err %v", err)
	}
}

func TestInfrastructureIsNeverASuspect(t *testing.T) {
	cur := events(win, noise(),
		ev{key: gateway, path: "/oauth/device/code", method: "POST", n: 30},
		ev{key: c1, path: "/oauth/device/code", method: "POST", ua: "Gateway-HTTP/1.0", n: 30})
	fs, err := detect(t, cfg(), cur, events(win.Previous(), noise()))
	if err != nil || len(fs) != 0 {
		t.Fatalf("fs %+v err %v", fs, err)
	}
	// And ignored events never count as history either.
	cur = events(win, noise(), ev{key: c1, path: "/oauth/device/code", method: "POST", n: 1})
	prev := events(win.Previous(), noise(), ev{key: gateway, path: "/oauth/device/code", method: "POST", n: 9})
	fs, _ = detect(t, cfg(), cur, prev)
	if len(fs) != 1 || fs[0].Detail["prev_events"] != 0 || fs[0].Detail["ignored_prev"] != 9 {
		t.Fatalf("%+v", fs)
	}
}

func TestMatchersAreExactNeverSubstrings(t *testing.T) {
	for _, p := range []string{"/signup/form", "/v2/signup", "/signupx", "/SIGNUP", "/oauth/device/code/extra", "/x/oauth/device/code"} {
		cur := events(win, noise(), ev{key: c1, path: p, method: "POST", n: 5})
		fs, err := detect(t, cfg(), cur, events(win.Previous(), noise()))
		if err != nil || len(fs) != 0 {
			t.Errorf("path %q matched: %+v %v", p, fs, err)
		}
	}
	// Query string and one trailing slash are not part of the path.
	for _, p := range []string{"/signup?next=/home", "/signup/", "/signup#x"} {
		cur := events(win, noise(), ev{key: c1, path: p, method: "post", n: 1})
		fs, _ := detect(t, cfg(), cur, events(win.Previous(), noise()))
		if len(fs) != 1 || fs[0].Tag != "behaviour:signup" {
			t.Errorf("path %q: %+v", p, fs)
		}
	}
}

func TestMethodAndStatusSetsRestrict(t *testing.T) {
	cur := events(win, noise(),
		ev{key: c1, path: "/signup", method: "GET", n: 5},                 // form render
		ev{key: c1, path: "/signup", method: "POST", status: 422, n: 5},   // failed attempt
		ev{key: c1, path: "/signup", method: "POST", status: "n/a", n: 2}) // unreadable
	fs, err := detect(t, cfg(), cur, events(win.Previous(), noise()))
	if err != nil || len(fs) != 0 {
		t.Fatalf("fs %+v err %v", fs, err)
	}
	cur = append(cur, events(win, ev{key: c1, path: "/signup", method: "POST", status: 302, n: 2})...)
	fs, _ = detect(t, cfg(), cur, events(win.Previous(), noise()))
	if len(fs) != 1 || fs[0].Detail["cur_events"] != 2 || fs[0].Detail["unparsable_cur"] != 2 {
		t.Fatalf("%+v", fs)
	}
}

func TestPathPatternAndFieldMatchersAreAnchored(t *testing.T) {
	c := cfg()
	c.Actions = []Action{{
		Name: "reg", Class: ClassRare, PathPattern: `/realms/[a-z]+/registrations`,
		Fields:        map[string]string{"app": "web"},
		FieldPatterns: map[string]string{"flow": `sign(up|in)`},
	}}
	good := map[string]any{"app": "web", "flow": "signup"}
	cur := events(win, noise(),
		ev{key: c1, path: "/realms/main/registrations", method: "GET", n: 1, extra: good},
		ev{key: c1, path: "/realms/main/registrations/x", method: "GET", n: 4, extra: good}, // longer path
		ev{key: c1, path: "/realms/MAIN/registrations", method: "GET", n: 4, extra: good},   // pattern is case-sensitive
		ev{key: c1, path: "/realms/main/registrations", method: "GET", n: 4, extra: map[string]any{"app": "webx", "flow": "signup"}},
		ev{key: c1, path: "/realms/main/registrations", method: "GET", n: 4, extra: map[string]any{"app": "web", "flow": "xsignup"}},
		ev{key: c1, path: "/realms/main/registrations", method: "GET", n: 4, extra: map[string]any{"app": "web"}})
	fs, err := detect(t, c, cur, events(win.Previous(), noise()))
	if err != nil || len(fs) != 1 || fs[0].Detail["cur_events"] != 1 {
		t.Fatalf("fs %+v err %v", fs, err)
	}
}

func TestCommonActionRawCountAloneIsNeverAFinding(t *testing.T) {
	// Ten times the volume, same failure share.
	cur := events(win, tokenTraffic(900, 100)...)
	prev := events(win.Previous(), tokenTraffic(90, 10)...)
	fs, err := detect(t, cfg(), cur, prev)
	if err != nil || len(fs) != 0 {
		t.Fatalf("fs %+v err %v", fs, err)
	}
	// Ten times the volume, zero failures.
	fs, _ = detect(t, cfg(), events(win, tokenTraffic(1000, 0)...), events(win.Previous(), tokenTraffic(90, 0)...))
	if len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
}

func TestCommonActionFailureShareRiseRaised(t *testing.T) {
	cur := events(win, tokenTraffic(50, 450)...)
	prev := events(win.Previous(), tokenTraffic(90, 10)...)
	fs, err := detect(t, cfg(), cur, prev)
	if err != nil || len(fs) != 1 {
		t.Fatalf("fs %+v err %v", fs, err)
	}
	f := fs[0]
	if f.Tag != "behaviour:token" || f.Severity != core.SevHigh {
		t.Errorf("%s %v", f.Tag, f.Severity)
	}
	d := f.Detail
	if d["cur_events"] != 500 || d["cur_failures"] != 450 || d["prev_events"] != 100 || d["prev_failures"] != 10 || d["failing_keys_cur"] != 1 {
		t.Errorf("detail %+v", d)
	}
	if r := d["failure_share_rise"].(float64); r < 0.79 || r > 0.81 {
		t.Errorf("rise %v", r)
	}
}

func TestCommonActionThresholdsAndMinEvents(t *testing.T) {
	prev := events(win.Previous(), tokenTraffic(80, 20)...) // 20%
	// Exactly +20 points is raised (inclusive); +19 is not.
	fs, _ := detect(t, cfg(), events(win, tokenTraffic(60, 40)...), prev)
	if len(fs) != 1 {
		t.Errorf("exactly the rise: %+v", fs)
	}
	fs, _ = detect(t, cfg(), events(win, tokenTraffic(61, 39)...), prev)
	if len(fs) != 0 {
		t.Errorf("one point under: %+v", fs)
	}
	// Below min_events by one, even at 100% failures.
	fs, _ = detect(t, cfg(), events(win, tokenTraffic(0, 19)...), prev)
	if len(fs) != 0 {
		t.Errorf("below min: %+v", fs)
	}
}

func TestCommonActionNoPrecedingEventsNeedsMajorityAndDropsSeverity(t *testing.T) {
	prev := events(win.Previous(), noise()) // window has data, the action does not
	fs, _ := detect(t, cfg(), events(win, tokenTraffic(30, 20)...), prev)
	if len(fs) != 0 {
		t.Errorf("40%% with nothing to compare: %+v", fs)
	}
	fs, _ = detect(t, cfg(), events(win, tokenTraffic(10, 40)...), prev)
	if len(fs) != 1 || fs[0].Severity != core.SevActivity || fs[0].Detail["baseline_source"] != "none" || fs[0].Detail["baseline_empty"] != false {
		t.Fatalf("%+v", fs)
	}
}

func TestPerActionFailStatuses(t *testing.T) {
	c := cfg()
	c.Actions[2].FailStatuses = []int{500, 503}
	cur := events(win, ev{key: c1, path: "/oauth/token", method: "POST", status: 503, n: 40},
		ev{key: c1, path: "/oauth/token", method: "POST", n: 10})
	prev := events(win.Previous(), tokenTraffic(100, 0)...)
	fs, _ := detect(t, c, cur, prev)
	if len(fs) != 1 || fs[0].Detail["cur_failures"] != 40 {
		t.Fatalf("%+v", fs)
	}
}

func TestMemoryBoundKeepsCountsExact(t *testing.T) {
	c := cfg()
	c.MaxKeys = 3
	var es []ev
	for i := 0; i < 10; i++ {
		es = append(es, ev{key: fmt.Sprintf("198.51.100.%d", 100+i), path: "/oauth/device/code", method: "POST", n: 2})
	}
	cur := events(win, append([]ev{noise()}, es...)...)
	fs, err := detect(t, c, cur, events(win.Previous(), noise()))
	if err != nil || len(fs) != 1 {
		t.Fatalf("%+v %v", fs, err)
	}
	d := fs[0].Detail
	if d["cur_events"] != 20 || d["keys_cur"] != 3 || d["keys_truncated"] != true {
		t.Errorf("detail %+v", d)
	}
	if !strings.Contains(fs[0].Summary, "at least 3") {
		t.Errorf("summary must say lower bound: %s", fs[0].Summary)
	}
}

func TestUnkeyedEventsAreCountedAndReported(t *testing.T) {
	cur := events(win, noise(), ev{noKey: true, path: "/oauth/device/code", method: "POST", n: 2})
	fs, _ := detect(t, cfg(), cur, events(win.Previous(), noise()))
	if len(fs) != 1 || fs[0].Detail["unkeyed_cur"] != 2 || fs[0].Detail["keys_cur"] != 0 || fs[0].Detail["cur_events"] != 2 {
		t.Fatalf("%+v", fs)
	}
}

func TestReaderErrorsAreNotCleanResults(t *testing.T) {
	boom := errors.New("backend down")
	d := mustNew(t, cfg())
	cur := fakeReader{evs: events(win, noise(), ev{key: c1, path: "/oauth/device/code", method: "POST", n: 1})}
	if _, err := d.Detect(context.Background(), cur, fakeReader{err: boom}, win); !errors.Is(err, boom) {
		t.Errorf("preceding window error lost: %v", err)
	}
	if _, err := d.Detect(context.Background(), fakeReader{err: boom}, fakeReader{}, win); !errors.Is(err, boom) {
		t.Errorf("current window error lost: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Detect(ctx, cur, fakeReader{}, win); !errors.Is(err, context.Canceled) {
		t.Errorf("cancel: %v", err)
	}
	if _, err := d.Detect(context.Background(), nil, fakeReader{}, win); err == nil {
		t.Error("nil reader")
	}
}

func TestDeterministicTagsAndOrder(t *testing.T) {
	cur := events(win, append([]ev{
		{key: c1, path: "/signup", method: "POST", n: 1},
		{key: c1, path: "/oauth/device/code", method: "POST", n: 1}}, tokenTraffic(10, 40)...)...)
	prev := events(win.Previous(), tokenTraffic(100, 0)...)
	fs, _ := detect(t, cfg(), cur, prev)
	var tags []string
	for _, f := range fs {
		tags = append(tags, f.Tag)
	}
	if strings.Join(tags, ",") != "behaviour:device-code,behaviour:signup,behaviour:token" {
		t.Errorf("tags %v", tags)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	mut := func(f func(*Config)) Config { c := cfg(); f(&c); return c }
	bad := map[string]Config{
		"no key field":      mut(func(c *Config) { c.KeyField = "" }),
		"no path field":     mut(func(c *Config) { c.PathField = "" }),
		"no actions":        mut(func(c *Config) { c.Actions = nil }),
		"bad name":          mut(func(c *Config) { c.Name = "Bad Name" }),
		"bad class":         mut(func(c *Config) { c.Actions[0].Class = "sometimes" }),
		"no matcher":        mut(func(c *Config) { c.Actions[0].Path = "" }),
		"both matchers":     mut(func(c *Config) { c.Actions[0].PathPattern = "/x" }),
		"relative path":     mut(func(c *Config) { c.Actions[0].Path = "oauth" }),
		"bad regexp":        mut(func(c *Config) { c.Actions[0].Path, c.Actions[0].PathPattern = "", "(" }),
		"duplicate action":  mut(func(c *Config) { c.Actions[1].Name = "device-code" }),
		"methods no field":  mut(func(c *Config) { c.MethodField = "" }),
		"statuses no field": mut(func(c *Config) { c.StatusField = "" }),
		"bad status":        mut(func(c *Config) { c.Actions[1].Statuses = []int{42} }),
		"negative min":      mut(func(c *Config) { c.Actions[0].MinEvents = -1 }),
		"fail on rare":      mut(func(c *Config) { c.Actions[0].FailStatuses = []int{401} }),
		"bad fail status":   mut(func(c *Config) { c.FailStatuses = []int{7} }),
		"ua without field":  mut(func(c *Config) { c.UserAgentField = "" }),
		"blank ua":          mut(func(c *Config) { c.IgnoreUserAgents = []string{" "} }),
		"rise out of range": mut(func(c *Config) { c.MinFailureShareRise = 1.5 }),
		"negative max keys": mut(func(c *Config) { c.MaxKeys = -1 }),
		"field in both": mut(func(c *Config) {
			c.Actions[0].Fields = map[string]string{"a": "b"}
			c.Actions[0].FieldPatterns = map[string]string{"a": "b"}
		}),
		"bad field pattern": mut(func(c *Config) { c.Actions[0].FieldPatterns = map[string]string{"a": "["} }),
		"too many actions":  mut(func(c *Config) { c.Actions = manyActions(65) }),
	}
	for name, c := range bad {
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	noStatus := cfg()
	noStatus.StatusField = ""
	noStatus.Actions = []Action{{Name: "t", Class: ClassCommon, Path: "/t"}}
	if _, err := New(noStatus); err == nil {
		t.Error("common action without status_field accepted")
	}
}

func manyActions(n int) []Action {
	var as []Action
	for i := 0; i < n; i++ {
		as = append(as, Action{Name: fmt.Sprintf("a%d", i), Class: ClassRare, Path: "/p"})
	}
	return as
}
