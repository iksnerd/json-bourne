package newkey

import (
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

func uaCfg() Config {
	c := baseCfg()
	c.UserAgentField = "user_agent"
	c.UserAgentMatches = []string{"curl/*", "python-requests/*", "example-bot"}
	return c
}

// withUA returns n sensitive requests from key carrying the given agent.
func withUA(key, ua string, n int) []core.Event {
	out := evs(sens(key, n))
	for i := range out {
		out[i].Fields["user_agent"] = ua
	}
	return out
}

func TestScriptedFilterRaisesANewScriptedKey(t *testing.T) {
	cur := append(withUA(newcomer, "curl/8.4.0", 4), evs(plain(regular, 30))...)
	fs, err := detect(t, uaCfg(), cur, history())
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings %+v, err %v", fs, err)
	}
	d := fs[0].Detail
	if d["key_cur_sensitive_hits"] != 4 || d["user_agent_filter"] != true || d["key_cur_sensitive_any_agent"] != 4 {
		t.Errorf("detail %v", d)
	}
	// The agent string itself is not in the finding.
	if s := fs[0].Summary + "|" + fs[0].Tag; strings.Contains(s, "curl") {
		t.Errorf("finding repeats the user agent: %s", s)
	}
}

func TestScriptedFilterIgnoresANewBrowserKey(t *testing.T) {
	cur := withUA(newcomer, "Mozilla/5.0 (X11; Fake) Browser/1", 9)
	fs, err := detect(t, uaCfg(), cur, history())
	if err != nil || len(fs) != 0 {
		t.Fatalf("a new key with an ordinary agent must not be raised: %+v, %v", fs, err)
	}
}

func TestScriptedFilterCountsOnlyScriptedHits(t *testing.T) {
	cur := append(withUA(newcomer, "curl/8.4.0", 2), withUA(newcomer, "Mozilla/5.0 Browser", 5)...)
	if fs, err := detect(t, uaCfg(), cur, history()); err != nil || len(fs) != 0 {
		t.Fatalf("2 scripted + 5 other hits must stay under min_hits 3: %+v, %v", fs, err)
	}
	cur = append(withUA(newcomer, "curl/8.4.0", 3), withUA(newcomer, "Mozilla/5.0 Browser", 5)...)
	fs, err := detect(t, uaCfg(), cur, history())
	if err != nil || len(fs) != 1 || fs[0].Detail["key_cur_sensitive_hits"] != 3 || fs[0].Detail["key_cur_sensitive_any_agent"] != 8 {
		t.Fatalf("findings %+v, err %v", fs, err)
	}
}

// History is any event of the key, whatever its agent: a scripted client that was
// already here is not new.
func TestScriptedFilterKeepsHistoryRule(t *testing.T) {
	prev := append(history(), withUA(newcomer, "Mozilla/5.0 Browser", 1)...)
	if fs, err := detect(t, uaCfg(), withUA(newcomer, "curl/8.4.0", 9), prev); err != nil || len(fs) != 0 {
		t.Fatalf("a key with history was raised: %+v, %v", fs, err)
	}
}

func TestScriptedFilterEmptyBaselineStillLowersSeverity(t *testing.T) {
	fs, err := detect(t, uaCfg(), withUA(newcomer, "curl/8.4.0", 4), nil)
	if err != nil || len(fs) != 1 || fs[0].Severity != core.SevHigh-1 || fs[0].Detail["baseline_empty"] != true {
		t.Fatalf("findings %+v, err %v", fs, err)
	}
}

// The match is the whole value, never a substring, and ignores case.
func TestUserAgentPatternsAreAnchoredNotSubstrings(t *testing.T) {
	d := mustNew(t, uaCfg())
	match := func(ua string) bool {
		return d.scripted(core.Event{Fields: map[string]any{"user_agent": ua}})
	}
	for ua, want := range map[string]bool{
		"curl/8.4.0":             true,
		"CURL/8.4.0":             true,
		"curl/":                  true,
		"python-requests/2.31":   true,
		"example-bot":            true,
		"example-bot/1":          false, // no wildcard: exact
		"mycurl/8":               false, // substring of a longer name
		"Mozilla/5.0 curl/8.4.0": false, // the pattern is not found inside a longer string
		"curl":                   false,
		"":                       false,
		"curl/" + strings.Repeat("9", maxUABytes): false, // over the length cap: not matched, not partly matched
	} {
		if got := match(ua); got != want {
			t.Errorf("match(%.40q) = %v, want %v", ua, got, want)
		}
	}
	if d.scripted(core.Event{Fields: map[string]any{"user_agent": 17}}) || d.scripted(core.Event{Fields: map[string]any{}}) {
		t.Error("a missing or non-text agent matched")
	}
	// Regexp syntax in a pattern is literal text.
	c := baseCfg()
	c.UserAgentField, c.UserAgentMatches = "user_agent", []string{"a.b+c"}
	d = mustNew(t, c)
	if match("axb+c") || !match("a.b+c") {
		t.Error("pattern metacharacters were not taken literally")
	}
}

func TestUserAgentFilterConfigIsStrict(t *testing.T) {
	over := make([]string, maxUAPatterns+1)
	for i := range over {
		over[i] = "a/*"
	}
	for name, mod := range map[string]func(*Config){
		"field alone":    func(c *Config) { c.UserAgentMatches = nil },
		"patterns alone": func(c *Config) { c.UserAgentField = "" },
		"star only":      func(c *Config) { c.UserAgentMatches = []string{"*"} },
		"stars only":     func(c *Config) { c.UserAgentMatches = []string{"**"} },
		"blank entry":    func(c *Config) { c.UserAgentMatches = []string{"curl/*", "  "} },
		"too long":       func(c *Config) { c.UserAgentMatches = []string{strings.Repeat("a", maxUAPatternBytes+1)} },
		"too many":       func(c *Config) { c.UserAgentMatches = over },
	} {
		c := uaCfg()
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := New(uaCfg()); err != nil {
		t.Fatal(err)
	}
}

// Without the filter the detector is what it was: every sensitive hit counts.
func TestNoFilterCountsEveryAgent(t *testing.T) {
	fs, err := detect(t, baseCfg(), withUA(newcomer, "Mozilla/5.0 Browser", 3), history())
	if err != nil || len(fs) != 1 {
		t.Fatalf("%+v, %v", fs, err)
	}
	if _, has := fs[0].Detail["user_agent_filter"]; has {
		t.Errorf("detail mentions a filter that is not configured: %v", fs[0].Detail)
	}
}
