package newkey

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// fakeHistory answers Counts from a table and records what it was asked.
type fakeHistory struct {
	mu     sync.Mutex
	counts map[string]int64
	err    error
	mode   string
	asked  [][]string
	wins   []core.Window
}

func (f *fakeHistory) Counts(_ context.Context, keys []string, w core.Window) (map[string]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, slices.Clone(keys))
	f.wins = append(f.wins, w)
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]int64{}
	for _, k := range keys {
		out[k] = f.counts[k]
	}
	return out, nil
}

func (f *fakeHistory) MatchMode() string { return f.mode }

func (f *fakeHistory) askedKeys() []string {
	var all []string
	for _, a := range f.asked {
		all = append(all, a...)
	}
	slices.Sort(all)
	return all
}

const lookback = 168 * time.Hour

func histCfg() Config {
	c := baseCfg()
	c.History = &HistoryConfig{Lookback: lookback, MinEvents: 50, MaxCandidates: 50}
	return c
}

func detectH(t *testing.T, c Config, cur, prev []core.Event, h core.KeyHistory) ([]core.Finding, error) {
	t.Helper()
	d := mustNew(t, c)
	return d.DetectWithHistory(context.Background(), fakeReader{evs: cur}, fakeReader{evs: prev}, win, h)
}

func TestHistoryKnownKeyGivesNoFinding(t *testing.T) {
	h := &fakeHistory{counts: map[string]int64{newcomer: 50}, mode: "phrase"}
	fs, err := detectH(t, histCfg(), evs(sens(newcomer, 3)), nil, h)
	if err != nil || len(fs) != 0 {
		t.Fatalf("findings %+v err %v, want none", fs, err)
	}
}

func TestHistoryBelowMinEventsIsAFindingWithTheHistoryDetail(t *testing.T) {
	h := &fakeHistory{counts: map[string]int64{newcomer: 49}, mode: "phrase"}
	fs, err := detectH(t, histCfg(), evs(sens(newcomer, 3)), nil, h)
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings %+v err %v", fs, err)
	}
	f := fs[0]
	if f.Severity != core.SevHigh || f.Tag != "newkey:"+newcomer {
		t.Errorf("severity %v tag %q", f.Severity, f.Tag)
	}
	wantBase := core.Window{From: win.From.Add(-lookback), To: win.From}
	if f.Baseline != wantBase {
		t.Errorf("baseline %v, want the lookback interval %v", f.Baseline, wantBase)
	}
	if len(h.wins) != 1 || h.wins[0] != wantBase {
		t.Errorf("asked window %v, want %v", h.wins, wantBase)
	}
	for k, want := range map[string]any{
		"history_lookback": lookback.String(), "history_count": int64(49), "history_min_events": 50, "history_mode": "phrase",
	} {
		if f.Detail[k] != want {
			t.Errorf("detail[%s] = %#v, want %#v", k, f.Detail[k], want)
		}
	}
	if _, has := f.Detail["baseline_empty"]; has {
		t.Error("baseline_empty is a preceding-window notion; history replaces it")
	}
}

func TestHistoryFloorStillApplies(t *testing.T) {
	c := histCfg()
	c.MinSeverity = "critical"
	c.Note = "downstream rule"
	fs, err := detectH(t, c, evs(sens(newcomer, 3)), nil, &fakeHistory{})
	if err != nil || len(fs) != 1 || fs[0].Severity != core.SevCritical || fs[0].Detail["note"] != "downstream rule" {
		t.Fatalf("findings %+v err %v", fs, err)
	}
}

func TestHistoryProbeErrorIsIncompleteAndNamesNotJudged(t *testing.T) {
	boom := fmt.Errorf("%w: probe down", core.ErrSourceUnavailable)
	h := &fakeHistory{err: boom}
	fs, err := detectH(t, histCfg(), evs(sens(newcomer, 3), sens(other, 4)), nil, h)
	if err == nil {
		t.Fatal("a failed probe returned no error: that reads as quiet")
	}
	if len(fs) != 0 {
		t.Errorf("findings %+v: none depends on a count that was not read", fs)
	}
	if !strings.Contains(err.Error(), "2 candidate(s) not judged") || !strings.Contains(err.Error(), "probe down") || !errors.Is(err, core.ErrSourceUnavailable) {
		t.Errorf("error %q must name the number not judged and the first cause", err)
	}
}

func TestHistoryMoreCandidatesThanMaxIsIncompleteAndJudgesTheHighest(t *testing.T) {
	c := histCfg()
	c.History.MaxCandidates = 2
	h := &fakeHistory{}
	cur := evs(sens("192.0.2.30", 3), sens("192.0.2.31", 9), sens("192.0.2.32", 5), sens("192.0.2.33", 5))
	fs, err := detectH(t, c, cur, nil, h)
	if got, want := h.askedKeys(), []string{"192.0.2.31", "192.0.2.32"}; !slices.Equal(got, want) {
		t.Errorf("asked %v, want the two highest-hit keys (ties by key) %v", got, want)
	}
	if err == nil || !strings.Contains(err.Error(), "2 candidate(s) not judged") {
		t.Fatalf("err = %v, want incomplete naming 2 not judged", err)
	}
	if len(fs) != 2 {
		t.Errorf("findings %d, want the two judged candidates kept beside the error", len(fs))
	}
}

func TestHistoryDecoysCannotPushTheRealKeyOutSilently(t *testing.T) {
	cur := evs(sens("192.0.2.40", 10), sens("192.0.2.41", 10), sens(newcomer, 3))
	fit := histCfg()
	fit.History.MaxCandidates = 3
	h := &fakeHistory{}
	fs, err := detectH(t, fit, cur, nil, h)
	if err != nil || len(fs) != 3 || !slices.Contains(h.askedKeys(), newcomer) {
		t.Fatalf("fits: findings %d err %v asked %v", len(fs), err, h.askedKeys())
	}
	over := histCfg()
	over.History.MaxCandidates = 2
	h = &fakeHistory{}
	fs, err = detectH(t, over, cur, nil, h)
	if slices.Contains(h.askedKeys(), newcomer) {
		t.Error("the real key was counted though it did not fit")
	}
	if err == nil || !strings.Contains(err.Error(), "1 candidate(s) not judged") {
		t.Fatalf("err = %v, want incomplete: never quiet", err)
	}
	for _, f := range fs {
		if f.Detail["key"] == newcomer {
			t.Error("a finding was raised for a key that was not judged")
		}
	}
}

func TestHistoryAKeyUnderMinEventsIsStillNewEvenIfSeenInThePrecedingWindow(t *testing.T) {
	h := &fakeHistory{counts: map[string]int64{newcomer: 1}}
	fs, err := detectH(t, histCfg(), evs(sens(newcomer, 3)), evs(plain(newcomer, 1), plain(regular, 40)), h)
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings %+v err %v: history replaces the preceding-window baseline", fs, err)
	}
}

func TestHistoryFindingsStaySortedByKey(t *testing.T) {
	fs, err := detectH(t, histCfg(), evs(sens("192.0.2.9", 3), sens("192.0.2.2", 8), sens("192.0.2.5", 4)), nil, &fakeHistory{})
	if err != nil || len(fs) != 3 {
		t.Fatalf("findings %d err %v", len(fs), err)
	}
	var got []string
	for _, f := range fs {
		got = append(got, f.Detail["key"].(string))
	}
	if !slices.IsSorted(got) {
		t.Errorf("keys %v not sorted", got)
	}
}

func TestHistoryHashKeysNeverShowThePlainKey(t *testing.T) {
	c := Config{KeyField: "email", PathField: "path", SensitivePaths: []string{"/secret/"}, HashKeys: true,
		History: &HistoryConfig{Lookback: lookback, MinEvents: 5}}
	h := &fakeHistory{}
	cur := evsKey("email", hit{key: sentinelEmail, path: "/v1/secret/ops", n: 4})
	fs, err := detectH(t, c, cur, nil, h)
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings %+v err %v", fs, err)
	}
	if !slices.Equal(h.askedKeys(), []string{sentinelEmail}) {
		t.Errorf("the probe asked %v, want the plain key", h.askedKeys())
	}
	if s := fmt.Sprint(fs[0].Tag, fs[0].Summary, fs[0].Detail); strings.Contains(s, "sentinel") {
		t.Errorf("finding leaks the plain key: %s", s)
	}
	_, err = detectH(t, c, cur, nil, &fakeHistory{err: errors.New("probe down")})
	if err == nil || strings.Contains(err.Error(), "sentinel") {
		t.Errorf("error %v leaks the plain key or is missing", err)
	}
	c.History.MaxCandidates = 1
	cur = evsKey("email", hit{key: sentinelEmail, path: "/v1/secret/ops", n: 4}, hit{key: "b@example.com", path: "/v1/secret/ops", n: 5})
	_, err = detectH(t, c, cur, nil, &fakeHistory{})
	if err == nil || strings.Contains(err.Error(), "sentinel") || strings.Contains(err.Error(), "@") {
		t.Errorf("error %v leaks a key or is missing", err)
	}
}

func TestDetectWithoutHistoryOnAHistoryDetectorIsAnErrorAndNeverFallsBack(t *testing.T) {
	d := mustNew(t, histCfg())
	fs, err := d.Detect(context.Background(), fakeReader{evs: evs(sens(newcomer, 3))}, fakeReader{evs: history()}, win)
	if err == nil || !strings.Contains(err.Error(), "history") || len(fs) != 0 {
		t.Fatalf("findings %v err %v, want a missing-history error and no fallback finding", fs, err)
	}
	var _ core.HistoryDetector = d
}

func TestHistoryLookbackNotLongerThanTheWindowIsAUsageError(t *testing.T) {
	c := histCfg()
	c.History.Lookback = win.Duration()
	_, err := detectH(t, c, evs(sens(newcomer, 3)), nil, &fakeHistory{})
	if err == nil || !core.IsUsage(err) {
		t.Fatalf("err = %v, want a usage error", err)
	}
	_, err = mustNew(t, c).Detect(context.Background(), fakeReader{}, fakeReader{}, win)
	if err == nil {
		t.Fatal("Detect: want an error")
	}
}

func TestHistoryUserAgentCandidatesCountOnlyMatchingHits(t *testing.T) {
	c := histCfg()
	c.UserAgentField, c.UserAgentMatches = "ua", []string{"curl/*"}
	var cur []core.Event
	for _, e := range evs(sens(newcomer, 3)) {
		e.Fields["ua"] = "curl/8.4.0"
		cur = append(cur, e)
	}
	for _, e := range evs(sens(other, 5)) { // a browser: not a candidate
		e.Fields["ua"] = "Mozilla/5.0"
		cur = append(cur, e)
	}
	h := &fakeHistory{}
	fs, err := detectH(t, c, cur, nil, h)
	if err != nil || len(fs) != 1 || !slices.Equal(h.askedKeys(), []string{newcomer}) {
		t.Fatalf("findings %d err %v asked %v", len(fs), err, h.askedKeys())
	}
}

func TestHistoryIgnoreKeysAreNeverCandidates(t *testing.T) {
	c := histCfg()
	c.IgnoreKeys = []string{newcomer}
	h := &fakeHistory{}
	fs, err := detectH(t, c, evs(sens(newcomer, 9), plain(regular, 5)), nil, h)
	if err != nil || len(fs) != 0 || len(h.asked) != 0 {
		t.Fatalf("findings %d err %v asked %v", len(fs), err, h.asked)
	}
}

func TestHistoryNoCandidatesAsksNothing(t *testing.T) {
	h := &fakeHistory{}
	fs, err := detectH(t, histCfg(), evs(sens(newcomer, 2), plain(regular, 5)), nil, h)
	if err != nil || len(fs) != 0 || len(h.asked) != 0 {
		t.Fatalf("findings %d err %v asked %v", len(fs), err, h.asked)
	}
}

type emptyHistory struct{}

func (emptyHistory) Counts(context.Context, []string, core.Window) (map[string]int64, error) {
	return map[string]int64{}, nil
}

func TestHistoryAMissingCountIsNotJudged(t *testing.T) {
	fs, err := detectH(t, histCfg(), evs(sens(newcomer, 3)), nil, emptyHistory{})
	if err == nil || len(fs) != 0 || !strings.Contains(err.Error(), "1 candidate(s) not judged") {
		t.Fatalf("findings %v err %v", fs, err)
	}
}

func TestWithoutAHistoryBlockDetectWithHistoryIsDetect(t *testing.T) {
	cur := evs(sens(newcomer, 3), plain(regular, 30))
	h := &fakeHistory{}
	fs, err := detectH(t, baseCfg(), cur, history(), h)
	if err != nil || len(fs) != 1 || len(h.asked) != 0 {
		t.Fatalf("findings %v err %v asked %v", fs, err, h.asked)
	}
	if _, has := fs[0].Detail["history_count"]; has {
		t.Error("a detector without a history block grew history detail")
	}
}

func TestHistoryConfigIsValidated(t *testing.T) {
	cases := map[string]*HistoryConfig{
		"no lookback":        {MinEvents: 5},
		"negative lookback":  {Lookback: -time.Hour, MinEvents: 5},
		"lookback over 31d":  {Lookback: 31*24*time.Hour + time.Second, MinEvents: 5},
		"no min_events":      {Lookback: lookback},
		"min_events -1":      {Lookback: lookback, MinEvents: -1},
		"negative max":       {Lookback: lookback, MinEvents: 5, MaxCandidates: -1},
		"max_candidates 101": {Lookback: lookback, MinEvents: 5, MaxCandidates: 101},
	}
	for name, h := range cases {
		c := baseCfg()
		c.History = h
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := baseCfg()
	c.History = &HistoryConfig{Lookback: 31 * 24 * time.Hour, MinEvents: 1, MaxCandidates: 100}
	if _, err := New(c); err != nil {
		t.Errorf("the limits themselves must pass: %v", err)
	}
}
