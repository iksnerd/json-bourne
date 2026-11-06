package signup

import (
	"errors"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

func quietCfg() Config {
	c := baseCfg()
	c.EmptyIsQuiet = true
	return c
}

// With EmptyIsQuiet, a current window without an attempt to create an account is a
// quiet answer: no findings and no error.
func TestEmptyIsQuietAcceptsAWindowWithoutAttempts(t *testing.T) {
	prev := evs(created(3))
	for name, cur := range map[string][]core.Event{
		"no events":             nil,
		"only a different path": evs(otherForm(20)),
		"only form renders":     evs(formRender(20)),
	} {
		fs, err := detect(t, quietCfg(), cur, prev)
		if err != nil || len(fs) != 0 {
			t.Errorf("%s: findings %+v, err %v; want quiet", name, fs, err)
		}
	}
}

// Without the option the same windows stay core.ErrNoRecords.
func TestEmptyWindowIsStillNoRecordsWhenNotEnabled(t *testing.T) {
	for name, cur := range map[string][]core.Event{
		"no events":    nil,
		"other path":   evs(otherForm(20)),
		"form renders": evs(formRender(20)),
	} {
		_, err := detect(t, baseCfg(), cur, evs(created(3)))
		if !errors.Is(err, core.ErrNoRecords) {
			t.Errorf("%s: err = %v, want core.ErrNoRecords", name, err)
		}
	}
}

// Events that exist on the creating path but cannot be read are a blind detector. The
// option must not turn them into a quiet answer.
func TestEmptyIsQuietStillErrorsWhenEventsExistButNoneParse(t *testing.T) {
	cur := evs(req{path: createPath, method: "POST", status: "n/a", n: 30})
	_, err := detect(t, quietCfg(), cur, evs(created(3)))
	if !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want core.ErrNoRecords", err)
	}
	// A method that is missing on the path counts the same way.
	cur = evs(req{path: createPath, method: "", status: 302, n: 30})
	if _, err = detect(t, quietCfg(), cur, nil); !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("missing method: err = %v, want core.ErrNoRecords", err)
	}
}

// Quiet is only for a window with nothing to judge. A burst is still flagged, and the
// empty preceding window still takes the severity step.
func TestEmptyIsQuietDoesNotHideABurst(t *testing.T) {
	c := quietCfg()
	c.MinCreations, c.Factor = 5, 2
	fs, err := detect(t, c, evs(created(30)), nil)
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings %+v, err %v; want the burst", fs, err)
	}
	if fs[0].Detail["baseline_empty"] != true {
		t.Errorf("baseline_empty = %v, want true", fs[0].Detail["baseline_empty"])
	}
}

func TestEmptyIsQuietEventMode(t *testing.T) {
	c := evCfg()
	c.EmptyIsQuiet = true
	fs, err := detect(t, c, ev("LOGIN", 50, ""), nil)
	if err != nil || len(fs) != 0 {
		t.Fatalf("only LOGIN events: %+v, %v; want quiet", fs, err)
	}
	// An event with no type is unreadable.
	bad := []core.Event{{Fields: map[string]any{"other": "x"}}}
	if _, err = detect(t, c, bad, nil); !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("typeless events: err = %v, want core.ErrNoRecords", err)
	}
}
