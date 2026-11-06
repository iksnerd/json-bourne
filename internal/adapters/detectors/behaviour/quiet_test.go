package behaviour

import (
	"errors"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

func quietCfg() Config {
	c := cfg()
	c.EmptyIsQuiet = true
	return c
}

func TestEmptyIsQuietAcceptsAWindowWithNothingToJudge(t *testing.T) {
	prev := events(win.Previous(), noise())
	for name, cur := range map[string][]core.Event{
		"no events":    nil,
		"only ignored": events(win, ev{key: gateway, path: "/oauth/device/code", method: "POST", n: 5}),
	} {
		fs, err := detect(t, quietCfg(), cur, prev)
		if err != nil || len(fs) != 0 {
			t.Errorf("%s: findings %+v, err %v; want quiet", name, fs, err)
		}
	}
	// Activity answers from the same analysis: quiet, with every action at zero.
	rep, err := mustNew(t, quietCfg()).Activity(t.Context(), fakeReader{}, fakeReader{evs: prev}, win)
	if err != nil {
		t.Fatalf("Activity: %v", err)
	}
	for _, s := range rep.Subjects {
		if s.Active || s.Current != 0 {
			t.Errorf("subject %+v active on an empty window", s)
		}
	}
}

func TestEmptyWindowIsStillNoRecordsWhenNotEnabled(t *testing.T) {
	if _, err := detect(t, cfg(), nil, events(win.Previous(), noise())); !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want core.ErrNoRecords", err)
	}
}

func TestEmptyIsQuietStillErrorsWhenEventsExistButNoneParse(t *testing.T) {
	cur := events(win, ev{key: c1, path: "", n: 3}) // events with no path
	if _, err := detect(t, quietCfg(), cur, events(win.Previous(), noise())); !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want core.ErrNoRecords", err)
	}
}

func TestEmptyIsQuietDoesNotHideARareAction(t *testing.T) {
	cur := events(win, ev{key: c1, path: "/oauth/device/code", method: "POST", n: 5})
	fs, err := detect(t, quietCfg(), cur, events(win.Previous(), noise()))
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings %+v, err %v; want the rare action", fs, err)
	}
}
