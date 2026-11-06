package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

type fakeOverlaps struct {
	ov  []core.SourceOverlap
	err error
}

func (f fakeOverlaps) SourceOverlaps(context.Context, core.Window, int) ([]core.SourceOverlap, error) {
	return f.ov, f.err
}

func TestSourceOverlapWarningNamesLabelsCountAndTheExactFix(t *testing.T) {
	w := SourceOverlapWarning([]core.SourceOverlap{{A: "ingress", B: "kibana:logs-ingress-*", Docs: 77}}, "--case docs/case")
	for _, want := range []string{
		"WARNING", "77 document(s)", `"ingress"`, `"kibana:logs-ingress-*"`,
		"jb db rename-source --case docs/case 'kibana:logs-ingress-*' ingress --merge",
		"dry run", "--apply",
	} {
		if !strings.Contains(w, want) {
			t.Errorf("warning lacks %q:\n%s", want, w)
		}
	}
	if strings.Contains(w, "swap") {
		t.Errorf("a default-label pair has an obvious direction, no swap hint wanted:\n%s", w)
	}
	// Two explicit names: no way to know which is stale, so say so.
	w = SourceOverlapWarning([]core.SourceOverlap{{A: "edge", B: "ingress", Docs: 3}}, "--config c.yaml")
	if !strings.Contains(w, "rename-source --config c.yaml edge ingress --merge") || !strings.Contains(w, "swap") {
		t.Errorf("ambiguous pair:\n%s", w)
	}
	if SourceOverlapWarning(nil, "--config c.yaml") != "" {
		t.Error("a warning without an overlap")
	}
}

func TestSourceOverlapsAdviceNeverFailsTheCaller(t *testing.T) {
	if ov, err := SourceOverlaps(context.Background(), nil, core.Window{}); ov != nil || err != nil {
		t.Errorf("nil reader: %v %v", ov, err)
	}
	if _, err := SourceOverlaps(context.Background(), fakeOverlaps{err: errors.New("boom")}, core.Window{}); err == nil {
		t.Error("the reader's error is returned for the caller to note")
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"ingress":     "ingress",
		"kibana:a-b":  "kibana:a-b",
		"kibana:a-*":  "'kibana:a-*'",
		"it's":        `'it'\''s'`,
		"":            "''",
		"docs/case":   "docs/case",
		"with space":  "'with space'",
		"$(rm -rf /)": "'$(rm -rf /)'",
	} {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDoctorSourceLabelOverlapIsAWarningNotAFailure(t *testing.T) {
	d := baseDeps()
	s := goodStore
	s.Overlaps = []core.SourceOverlap{{A: "ingress", B: "kibana:x-*", Docs: 5}}
	d.Stores = fakeStores{"/ev/jb.duckdb": s}
	r := Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
	c := one(t, r, "store", "(source labels)")
	if c.Status != CheckWarn || !strings.Contains(c.Detail, "jb db rename-source --config hunt.yaml") {
		t.Fatalf("%+v", c)
	}
	if !r.OK() {
		t.Error("an overlap warning failed the doctor run")
	}
	// None: no line at all.
	d.Stores = fakeStores{"/ev/jb.duckdb": goodStore}
	r = Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
	if got := find(r, "store", "(source labels)"); len(got) != 0 {
		t.Errorf("a line without an overlap: %+v", got)
	}
}

func TestDoctorHeldLockIsAFailure(t *testing.T) {
	d := baseDeps()
	d.Stores = fakeStores{"/ev/jb.duckdb": DoctorStore{Exists: true, OpenKind: "locked", OpenErr: "evidence database /ev/jb.duckdb is held by another process (jb, PID 4242)"}}
	r := Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
	c := one(t, r, "store", "(open)")
	if c.Status != CheckFail || !strings.Contains(c.Detail, "PID 4242") || r.OK() {
		t.Fatalf("%+v ok=%v", c, r.OK())
	}
}
