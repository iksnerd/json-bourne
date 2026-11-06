package newkey

import (
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

const floorNote = "the export endpoint is never used from a new address"

func floorCfg(sev, note string) Config {
	c := baseCfg()
	c.MinSeverity, c.Note = sev, note
	return c
}

func TestFloorCriticalRaisesAndCarriesNote(t *testing.T) {
	fs, err := detect(t, floorCfg("critical", floorNote), evs(sens(newcomer, 3), plain(regular, 30)), history())
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
	f := fs[0]
	if f.Severity != core.SevCritical || f.Detail["min_severity"] != "critical" || f.Detail["note"] != floorNote {
		t.Errorf("severity %v detail %v", f.Severity, f.Detail)
	}
	if f.Tag != "newkey:"+newcomer {
		t.Errorf("tag changed: %q", f.Tag)
	}
}

func TestFloorIsAppliedAfterEmptyBaselineDrop(t *testing.T) {
	// Empty preceding window: computed severity drops one step below high.
	fs, err := detect(t, floorCfg("high", ""), evs(sens(newcomer, 3)), nil)
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
	f := fs[0]
	if f.Severity != core.SevHigh || f.Detail["baseline_empty"] != true || f.Detail["min_severity"] != "high" {
		t.Errorf("want high raised from the drop, baseline_empty kept: %v %v", f.Severity, f.Detail)
	}
	// Without a floor the same case stays one step down.
	fs, _ = detect(t, baseCfg(), evs(sens(newcomer, 3)), nil)
	if len(fs) != 1 || fs[0].Severity != core.SevHigh-1 {
		t.Fatalf("control: %+v", fs)
	}
}

func TestFloorNeverLowersAndIsNotShownWhenItDidNotRaise(t *testing.T) {
	fs, err := detect(t, floorCfg("high", ""), evs(sens(newcomer, 3), plain(regular, 30)), history())
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
	if fs[0].Severity != core.SevHigh {
		t.Errorf("severity %v", fs[0].Severity)
	}
	if _, ok := fs[0].Detail["min_severity"]; ok {
		t.Errorf("min_severity present though the floor did not raise: %v", fs[0].Detail)
	}
}

func TestFloorRefusals(t *testing.T) {
	cases := []struct {
		name, sev, note, want string
	}{
		{"info", "info", "", "min_severity"},
		{"check", "check", "", "min_severity"},
		{"activity", "activity", "", "min_severity"},
		{"unknown", "urgent", "", "min_severity"},
		{"critical needs note", "critical", "", "note"},
		{"critical blank note", "critical", "  ", "note"},
		{"note without floor", "", "why", "min_severity"},
	}
	for _, tc := range cases {
		_, err := New(floorCfg(tc.sev, tc.note))
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.HasPrefix(err.Error(), "newkey: ") {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
	if _, err := New(floorCfg("urgent", "")); err == nil || !strings.Contains(err.Error(), "high") || !strings.Contains(err.Error(), "critical") {
		t.Errorf("unknown name should list the valid ones: %v", err)
	}
	// A note is allowed with a floor below critical.
	if _, err := New(floorCfg("high", "why")); err != nil {
		t.Errorf("high with note: %v", err)
	}
}
