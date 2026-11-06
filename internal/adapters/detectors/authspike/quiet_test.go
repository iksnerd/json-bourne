package authspike

import (
	"context"
	"errors"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

func quietCfg() Config {
	c := baseCfg()
	c.EmptyIsQuiet = true
	return c
}

func detectWith(t *testing.T, c Config, cur, prev []core.Event) ([]core.Finding, error) {
	t.Helper()
	return mustNew(t, c).Detect(context.Background(), fakeReader{evs: cur}, fakeReader{evs: prev}, win)
}

func TestEmptyIsQuietAcceptsAWindowWithNoOnPathEvent(t *testing.T) {
	prev := events(win.Previous(), quiet()...)
	for name, cur := range map[string][]core.Event{
		"no events":     nil,
		"only off-path": events(win, group{key: attacker, path: "/api/data", fail: 90}),
	} {
		fs, err := detectWith(t, quietCfg(), cur, prev)
		if err != nil || len(fs) != 0 {
			t.Errorf("%s: findings %+v, err %v; want quiet", name, fs, err)
		}
	}
}

func TestEmptyWindowIsStillNoRecordsWhenNotEnabled(t *testing.T) {
	prev := events(win.Previous(), quiet()...)
	for name, cur := range map[string][]core.Event{
		"no events":     nil,
		"only off-path": events(win, group{key: attacker, path: "/api/data", fail: 90}),
	} {
		if _, err := detectWith(t, baseCfg(), cur, prev); !errors.Is(err, core.ErrNoRecords) {
			t.Errorf("%s: err = %v, want core.ErrNoRecords", name, err)
		}
	}
}

func TestEmptyIsQuietStillErrorsWhenEventsExistButNoneParse(t *testing.T) {
	cur := events(win, group{key: attacker, unparsable: 90})
	_, err := detectWith(t, quietCfg(), cur, events(win.Previous(), quiet()...))
	if !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want core.ErrNoRecords", err)
	}
}

func TestEmptyIsQuietDoesNotHideASpray(t *testing.T) {
	fs, err := detectWith(t, quietCfg(), events(win, with(group{key: attacker, ok: 10, fail: 90})...), events(win.Previous(), quiet()...))
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings %+v, err %v; want the sprayer", fs, err)
	}
}
