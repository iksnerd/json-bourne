package fingerprint

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

// All data is synthetic: invented user agents, example.com, RFC 5737 addresses.
const (
	actorUA = "ExampleBrowser/9.1 (Plan9; Win64; x64) InventedKit/537.36 (like Gecko) Chrome/9.1.0.0 Safari/537.36"
	// nearMiss shares the build token (the substring a sloppy matcher would use) and the
	// same stale build family, but is a different client.
	nearMiss  = "ExampleBrowser/9.1 (X11; Linux x86_64) InventedKit/537.36 (like Gecko) Chrome/9.1.0.0 Safari/537.36"
	edgeIP    = "198.51.100.200" // a CDN edge: shared by every client behind it
	gatewayIP = "198.51.100.7"   // our own gateway
	clientIP  = "203.0.113.10"
	tokenPath = "/realms/example/protocol/openid-connect/token"
)

var (
	t0   = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	win  = core.Window{From: t0, To: t0.Add(time.Hour)}
	prev = win.Previous()
)

func actor() Actor {
	return Actor{
		ID:               "actor-a",
		Label:            "Example actor A",
		UserAgents:       []string{actorUA},
		NoisePaths:       []string{"/wp-", "/xmlrpc.php"},
		BareRoot4xxNoise: true,
		GrantPaths:       []string{tokenPath},
	}
}

func cfg() Config { return Config{Actors: []Actor{actor()}} }

type e struct {
	at     time.Duration // offset from the window start
	ua     string
	path   string
	status any
	ip     string
	drop   string // field to omit
}

func evs(w core.Window, es ...e) []core.Event {
	var out []core.Event
	for _, x := range es {
		f := map[string]any{"user_agent": x.ua, "path": x.path, "status": x.status, "client_ip": clientIP, "method": "GET"}
		if x.status == nil {
			f["status"] = 200
		}
		if x.ip != "" {
			f["client_ip"] = x.ip
		}
		if x.drop != "" {
			delete(f, x.drop)
		}
		out = append(out, core.Event{Time: w.From.Add(x.at), Source: "synthetic", Kind: "http", Fields: f})
	}
	return out
}

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

func mustNew(t *testing.T, c Config) *Detector {
	t.Helper()
	d, err := New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func detect(t *testing.T, c Config, cur, pre []core.Event) ([]core.Finding, error) {
	t.Helper()
	return mustNew(t, c).Detect(context.Background(), reader{evs: cur}, reader{evs: pre}, win)
}

func byTag(fs []core.Finding, tag string) *core.Finding {
	for i := range fs {
		if fs[i].Tag == tag {
			return &fs[i]
		}
	}
	return nil
}

// ordinary is traffic from real customers, so the window is not empty.
func ordinary(w core.Window) []core.Event {
	return evs(w, e{at: time.Minute, ua: "OtherClient/1.0", path: "/login", status: 200})
}

func TestExactUAMatchesAndNearMissDoesNot(t *testing.T) {
	cur := append(ordinary(win), evs(win,
		e{at: 5 * time.Minute, ua: actorUA, path: "/login", status: 200},
		e{at: 6 * time.Minute, ua: nearMiss, path: "/login", status: 200},
		e{at: 7 * time.Minute, ua: nearMiss, path: tokenPath, status: 200},     // a real customer's grant
		e{at: 8 * time.Minute, ua: actorUA + " ", path: "/login", status: 200}, // trailing space: not equal
		e{at: 9 * time.Minute, ua: strings.ToLower(actorUA), path: "/login", status: 200},
	)...)
	fs, err := detect(t, cfg(), cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	f := byTag(fs, "fingerprint:actor-a")
	if f == nil {
		t.Fatalf("no finding: %+v", fs)
	}
	if f.Detail["cur_genuine"] != 1 {
		t.Errorf("cur_genuine = %v, want exactly the one full-string match", f.Detail["cur_genuine"])
	}
	if f.Severity != core.SevActivity {
		t.Errorf("severity %v, want activity", f.Severity)
	}
	if byTag(fs, "fingerprint:actor-a:grant") != nil {
		t.Error("a near-miss UA with a 2xx on the grant path must not raise the tripwire")
	}
}

func TestScannerOnSameUAIsFiltered(t *testing.T) {
	cur := append(ordinary(win), evs(win,
		e{at: 5 * time.Minute, ua: actorUA, path: "/wp-login.php", status: 200},
		e{at: 6 * time.Minute, ua: actorUA, path: "/WP-JSON/v2/users", status: 200},
		e{at: 7 * time.Minute, ua: actorUA, path: "/xmlrpc.php", status: 405},
	)...)
	fs, err := detect(t, cfg(), cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	f := byTag(fs, "fingerprint:actor-a")
	if f == nil {
		t.Fatalf("want a finding that reports the filtered noise, got %+v", fs)
	}
	if f.Severity != core.SevInfo {
		t.Errorf("only noise matched: severity %v, want info", f.Severity)
	}
	if f.Detail["cur_genuine"] != 0 || f.Detail["cur_filtered"] != 3 {
		t.Errorf("genuine/filtered = %v/%v, want 0/3", f.Detail["cur_genuine"], f.Detail["cur_filtered"])
	}
	if !strings.Contains(f.Summary, "no genuine activity in window") {
		t.Errorf("summary must say so explicitly: %q", f.Summary)
	}
}

func TestQueryStringIsNotPartOfPath(t *testing.T) {
	cur := append(ordinary(win), evs(win,
		e{at: 5 * time.Minute, ua: actorUA, path: "/?x=1", status: 404},                 // bare root 404 with junk query: noise
		e{at: 6 * time.Minute, ua: actorUA, path: "/?x=1", status: 307},                 // the actor's own redirect: genuine
		e{at: 7 * time.Minute, ua: actorUA, path: "/login?next=/wp-admin", status: 200}, // marker only in the query: genuine
	)...)
	fs, err := detect(t, cfg(), cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	f := byTag(fs, "fingerprint:actor-a")
	if f == nil {
		t.Fatal("no finding")
	}
	if f.Detail["cur_genuine"] != 2 || f.Detail["cur_filtered"] != 1 {
		t.Errorf("genuine/filtered = %v/%v, want 2/1", f.Detail["cur_genuine"], f.Detail["cur_filtered"])
	}
	want := win.From.Add(7 * time.Minute)
	if got, _ := f.Detail["last_genuine"].(time.Time); !got.Equal(want) {
		t.Errorf("last_genuine = %v, want %v", f.Detail["last_genuine"], want)
	}
}

func TestLastSeenIgnoresTrailingNoise(t *testing.T) {
	cur := append(ordinary(win), evs(win,
		e{at: 5 * time.Minute, ua: actorUA, path: "/login", status: 200},
		e{at: 50 * time.Minute, ua: actorUA, path: "/?junk", status: 404}, // later, but a sweep
	)...)
	fs, _ := detect(t, cfg(), cur, ordinary(prev))
	f := byTag(fs, "fingerprint:actor-a")
	if f == nil {
		t.Fatal("no finding")
	}
	if got, _ := f.Detail["last_genuine"].(time.Time); !got.Equal(win.From.Add(5 * time.Minute)) {
		t.Errorf("last_genuine = %v, want the 5 minute event", f.Detail["last_genuine"])
	}
}

func TestBareRootRuleCanBeTurnedOff(t *testing.T) {
	c := cfg()
	c.Actors[0].BareRoot4xxNoise = false
	cur := append(ordinary(win), evs(win, e{at: time.Minute, ua: actorUA, path: "/?x=1", status: 404})...)
	fs, err := detect(t, c, cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	if f := byTag(fs, "fingerprint:actor-a"); f == nil || f.Detail["cur_genuine"] != 1 {
		t.Fatalf("with the rule off a 404 on / is genuine: %+v", fs)
	}
}

func TestGrantIsCriticalOnItsOwn(t *testing.T) {
	cur := append(ordinary(win), evs(win,
		e{at: 5 * time.Minute, ua: actorUA, path: tokenPath, status: 401},
		e{at: 6 * time.Minute, ua: actorUA, path: tokenPath + "?x=1", status: 200},
		e{at: 7 * time.Minute, ua: actorUA, path: "/login", status: 200},
	)...)
	fs, err := detect(t, cfg(), cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	g := byTag(fs, "fingerprint:actor-a:grant")
	if g == nil {
		t.Fatalf("no grant finding: %+v", fs)
	}
	if g.Severity != core.SevCritical {
		t.Errorf("severity %v, want critical", g.Severity)
	}
	if g.Detail["grants"] != 1 {
		t.Errorf("grants = %v, want 1 (the 401 is not a grant)", g.Detail["grants"])
	}
	if a := byTag(fs, "fingerprint:actor-a"); a == nil || a.Severity != core.SevActivity {
		t.Errorf("the activity finding stays activity-level: %+v", a)
	}
}

func TestGrantNeedsMatchingNonNoiseEvent(t *testing.T) {
	cur := append(ordinary(win), evs(win,
		e{at: 5 * time.Minute, ua: nearMiss, path: tokenPath, status: 200},
		e{at: 6 * time.Minute, ua: actorUA, path: tokenPath, status: 403},
		e{at: 7 * time.Minute, ua: actorUA, path: tokenPath, status: 302},
		e{at: 8 * time.Minute, ua: actorUA, path: "/other", status: 200},
	)...)
	fs, err := detect(t, cfg(), cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	if byTag(fs, "fingerprint:actor-a:grant") != nil {
		t.Errorf("no 2xx on the grant path by the actor: %+v", fs)
	}
}

func TestLastGenuineSurvivesEmptyWindow(t *testing.T) {
	pre := append(ordinary(prev), evs(prev,
		e{at: 10 * time.Minute, ua: actorUA, path: "/login", status: 200},
		e{at: 40 * time.Minute, ua: actorUA, path: "/login", status: 200},
	)...)
	fs, err := detect(t, cfg(), ordinary(win), pre)
	if err != nil {
		t.Fatal(err)
	}
	f := byTag(fs, "fingerprint:actor-a")
	if f == nil {
		t.Fatalf("an actor seen in the preceding window and gone now must be reported, got %+v", fs)
	}
	if f.Severity != core.SevInfo || f.Detail["cur_genuine"] != 0 || f.Detail["prev_genuine"] != 2 {
		t.Errorf("sev=%v cur=%v prev=%v", f.Severity, f.Detail["cur_genuine"], f.Detail["prev_genuine"])
	}
	want := prev.From.Add(40 * time.Minute)
	got, _ := f.Detail["last_genuine"].(time.Time)
	if !got.Equal(want) {
		t.Errorf("last_genuine = %v, want %v (the preceding window's last)", f.Detail["last_genuine"], want)
	}
	if f.Detail["last_genuine_in"] != "preceding window" {
		t.Errorf("last_genuine_in = %v", f.Detail["last_genuine_in"])
	}
	if !strings.Contains(f.Summary, "no genuine activity in window") || strings.Contains(f.Summary, "0001-01-01") {
		t.Errorf("summary %q", f.Summary)
	}
}

func TestNoActorTrafficAnywhereIsQuiet(t *testing.T) {
	fs, err := detect(t, cfg(), ordinary(win), ordinary(prev))
	if err != nil || len(fs) != 0 {
		t.Fatalf("findings %+v err %v: the data was there and the actor was not", fs, err)
	}
}

func TestEdgeIPIsNotAttribution(t *testing.T) {
	cur := append(ordinary(win), evs(win,
		// the actor reaches us through a CDN edge; the UA is the evidence, not the address
		e{at: 5 * time.Minute, ua: actorUA, path: "/login", status: 200, ip: edgeIP},
		// another customer behind the same edge, different UA: not the actor
		e{at: 6 * time.Minute, ua: "OtherClient/1.0", path: "/login", status: 200, ip: edgeIP},
	)...)
	fs, err := detect(t, cfg(), cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	f := byTag(fs, "fingerprint:actor-a")
	if f == nil || f.Detail["cur_genuine"] != 1 {
		t.Fatalf("want exactly the UA match, got %+v", fs)
	}
	for k, v := range f.Detail {
		if s := fmt.Sprint(v); strings.Contains(s, edgeIP) || strings.Contains(strings.ToLower(k), "ip") {
			t.Errorf("Detail[%q] = %v: an address must not appear as attribution", k, v)
		}
	}
	if strings.Contains(f.Summary, edgeIP) {
		t.Errorf("summary names the edge: %q", f.Summary)
	}
}

func TestIgnoredInfrastructureIsNeverASuspect(t *testing.T) {
	c := cfg()
	c.IgnoreIPs = []string{gatewayIP, "192.0.2.0/24"}
	cur := append(ordinary(win), evs(win,
		e{at: 5 * time.Minute, ua: actorUA, path: tokenPath, status: 200, ip: gatewayIP},
		e{at: 6 * time.Minute, ua: actorUA, path: "/login", status: 200, ip: "192.0.2.55"},
		e{at: 7 * time.Minute, ua: actorUA, path: "/login", status: 200, ip: clientIP},
	)...)
	fs, err := detect(t, c, cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	if byTag(fs, "fingerprint:actor-a:grant") != nil {
		t.Error("a request relayed by our own gateway raised the tripwire")
	}
	f := byTag(fs, "fingerprint:actor-a")
	if f == nil || f.Detail["cur_genuine"] != 1 || f.Detail["cur_ignored"] != 2 {
		t.Fatalf("genuine/ignored: %+v", f)
	}
}

func TestWindowComparison(t *testing.T) {
	pre := append(ordinary(prev), evs(prev, e{at: time.Minute, ua: actorUA, path: "/login", status: 200})...)
	cur := append(ordinary(win), evs(win,
		e{at: time.Minute, ua: actorUA, path: "/login", status: 200},
		e{at: 2 * time.Minute, ua: actorUA, path: "/login", status: 200},
		e{at: 3 * time.Minute, ua: actorUA, path: "/login", status: 200},
	)...)
	fs, _ := detect(t, cfg(), cur, pre)
	f := byTag(fs, "fingerprint:actor-a")
	if f == nil {
		t.Fatal("no finding")
	}
	if f.Detail["cur_genuine"] != 3 || f.Detail["prev_genuine"] != 1 || f.Detail["baseline_empty"] != false {
		t.Errorf("detail %+v", f.Detail)
	}
	if f.Baseline != prev || f.Window != win {
		t.Errorf("windows %v %v", f.Window, f.Baseline)
	}
}

func TestEmptyBaselineLowersActivityButNotGrant(t *testing.T) {
	cur := append(ordinary(win), evs(win,
		e{at: time.Minute, ua: actorUA, path: "/login", status: 200},
		e{at: 2 * time.Minute, ua: actorUA, path: tokenPath, status: 200},
	)...)
	fs, err := detect(t, cfg(), cur, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := byTag(fs, "fingerprint:actor-a")
	if a == nil || a.Severity != core.SevCheck || a.Detail["baseline_empty"] != true {
		t.Errorf("activity with no baseline: %+v", a)
	}
	if g := byTag(fs, "fingerprint:actor-a:grant"); g == nil || g.Severity != core.SevCritical {
		t.Errorf("a grant stays critical without a baseline: %+v", g)
	}
}

func TestNoRecords(t *testing.T) {
	cases := map[string][]core.Event{
		"empty":               nil,
		"missing user_agent":  evs(win, e{ua: actorUA, path: "/login", drop: "user_agent"}),
		"missing path":        evs(win, e{ua: actorUA, path: "/login", drop: "path"}),
		"missing status":      evs(win, e{ua: actorUA, path: "/login", drop: "status"}),
		"empty user_agent":    evs(win, e{ua: "", path: "/login"}),
		"empty path":          evs(win, e{ua: actorUA, path: ""}),
		"unparsable status":   evs(win, e{ua: actorUA, path: "/login", status: "n/a"}),
		"status out of range": evs(win, e{ua: actorUA, path: "/login", status: 99}),
		"non-string agent":    {{Time: win.From, Fields: map[string]any{"user_agent": 7, "path": "/", "status": 200}}},
		"zero time":           {{Fields: map[string]any{"user_agent": actorUA, "path": "/", "status": 200}}},
	}
	for name, cur := range cases {
		t.Run(name, func(t *testing.T) {
			fs, err := detect(t, cfg(), cur, ordinary(prev))
			if !errors.Is(err, core.ErrNoRecords) || fs != nil {
				t.Fatalf("got %v, %v; want ErrNoRecords", fs, err)
			}
		})
	}
}

func TestMissingClientIPAndMethodStillParse(t *testing.T) {
	cur := evs(win,
		e{at: time.Minute, ua: actorUA, path: "/login", drop: "client_ip"},
		e{at: 2 * time.Minute, ua: actorUA, path: "/login", drop: "method"},
	)
	fs, err := detect(t, cfg(), cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	if f := byTag(fs, "fingerprint:actor-a"); f == nil || f.Detail["cur_genuine"] != 2 {
		t.Fatalf("%+v", fs)
	}
}

func TestStatusForms(t *testing.T) {
	for _, st := range []any{200, int64(200), float64(200), "200", " 200 "} {
		cur := evs(win, e{ua: actorUA, path: tokenPath, status: st})
		fs, err := detect(t, cfg(), cur, ordinary(prev))
		if err != nil || byTag(fs, "fingerprint:actor-a:grant") == nil {
			t.Errorf("status %#v: %v %+v", st, err, fs)
		}
	}
}

func TestReadErrorsAreNotEmptyReads(t *testing.T) {
	d := mustNew(t, cfg())
	boom := errors.New("boom")
	if _, err := d.Detect(context.Background(), reader{evs: ordinary(win), err: boom}, reader{}, win); !errors.Is(err, boom) {
		t.Errorf("current: %v", err)
	}
	if _, err := d.Detect(context.Background(), reader{evs: ordinary(win)}, reader{err: boom}, win); !errors.Is(err, boom) {
		t.Errorf("preceding: a failed baseline read is not an empty baseline: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Detect(ctx, reader{evs: ordinary(win)}, reader{}, win); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestTwoActorsDoNotShareTags(t *testing.T) {
	b := Actor{ID: "actor-b", UserAgents: []string{nearMiss}, BareRoot4xxNoise: true}
	c := Config{Actors: []Actor{actor(), b}}
	cur := append(ordinary(win), evs(win,
		e{at: time.Minute, ua: actorUA, path: "/login"},
		e{at: 2 * time.Minute, ua: nearMiss, path: "/login"},
	)...)
	fs, err := detect(t, c, cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	if byTag(fs, "fingerprint:actor-a") == nil || byTag(fs, "fingerprint:actor-b") == nil {
		t.Fatalf("%+v", fs)
	}
}

func TestNewValidates(t *testing.T) {
	bad := map[string]func(*Config){
		"no actors":         func(c *Config) { c.Actors = nil },
		"no user agents":    func(c *Config) { c.Actors[0].UserAgents = nil },
		"empty ua":          func(c *Config) { c.Actors[0].UserAgents = []string{""} },
		"empty marker":      func(c *Config) { c.Actors[0].NoisePaths = []string{""} },
		"slash marker":      func(c *Config) { c.Actors[0].NoisePaths = []string{"/"} },
		"relative grant":    func(c *Config) { c.Actors[0].GrantPaths = []string{"token"} },
		"grant is noise":    func(c *Config) { c.Actors[0].GrantPaths = []string{"/wp-login.php"} },
		"bad ignore ip":     func(c *Config) { c.IgnoreIPs = []string{"not-an-ip"} },
		"duplicate actor":   func(c *Config) { c.Actors = append(c.Actors, c.Actors[0]) },
		"empty actor id":    func(c *Config) { c.Actors[0].ID = "" },
		"bad detector name": func(c *Config) { c.Name = "has space" },
	}
	for name, mut := range bad {
		t.Run(name, func(t *testing.T) {
			c := Config{Actors: []Actor{actor()}}
			mut(&c)
			if _, err := New(c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// With EmptyIsQuiet the source has already proved its index alive, so an empty current
// window means the actor was not seen. It must not turn into ErrNoRecords, and it must
// not hide a window that has events the detector cannot read.
func TestEmptyIsQuietAcceptsAnEmptyCurrentWindow(t *testing.T) {
	c := cfg()
	c.EmptyIsQuiet = true
	fs, err := detect(t, c, nil, ordinary(prev))
	if err != nil {
		t.Fatalf("empty window with EmptyIsQuiet: %v", err)
	}
	for _, f := range fs {
		if f.Severity == core.SevCritical {
			t.Fatalf("an empty window raised a critical finding: %v", f)
		}
	}
	// Default behaviour is unchanged.
	if _, err := detect(t, cfg(), nil, ordinary(prev)); !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("default: got %v, want ErrNoRecords", err)
	}
}

// Events that exist but lack the fields the detector needs are a mapper problem, not a
// quiet window; EmptyIsQuiet does not change that for a window with a readable event.
func TestEmptyIsQuietStillReportsTheActorWhenSeen(t *testing.T) {
	c := cfg()
	c.EmptyIsQuiet = true
	cur := evs(win, e{ua: actorUA, path: "/login", status: 200})
	fs, err := detect(t, c, cur, ordinary(prev))
	if err != nil || len(fs) == 0 {
		t.Fatalf("actor seen in the window: findings=%v err=%v, want a finding", fs, err)
	}
}
