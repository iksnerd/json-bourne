package newkey

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

func TestEmptyIsQuietAcceptsAWindowWithNoEvent(t *testing.T) {
	fs, err := detect(t, quietCfg(), nil, history())
	if err != nil || len(fs) != 0 {
		t.Fatalf("findings %+v, err %v; want quiet", fs, err)
	}
	// Only keys on the ignore list: our own infrastructure, nothing unreadable.
	c := quietCfg()
	c.IgnoreKeys = []string{newcomer}
	fs, err = detect(t, c, evs(sens(newcomer, 9)), history())
	if err != nil || len(fs) != 0 {
		t.Fatalf("ignored-only window: %+v, %v; want quiet", fs, err)
	}
}

func TestEmptyWindowIsStillNoRecordsWhenNotEnabled(t *testing.T) {
	if _, err := detect(t, baseCfg(), nil, history()); !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want core.ErrNoRecords", err)
	}
}

func TestEmptyIsQuietStillErrorsWhenEventsExistButNoneParse(t *testing.T) {
	cur := evs(hit{noKey: true, path: "/v1/secret/ops", n: 10})
	if _, err := detect(t, quietCfg(), cur, history()); !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want core.ErrNoRecords", err)
	}
}

func TestEmptyIsQuietDoesNotHideANewKey(t *testing.T) {
	fs, err := detect(t, quietCfg(), evs(sens(newcomer, 9)), history())
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings %+v, err %v; want the new key", fs, err)
	}
}
