package duckdb

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

var tlBase = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// timelineFixture writes findings under runs whose created_at it then sets, because
// SaveFindings stamps now(). The write handle is closed before the read-only open.
func timelineFixture(t *testing.T) *Dashboard {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t.duckdb")
	rw, err := Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rw.Migrate(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	save := func(run string, at time.Time, fs ...core.Finding) {
		t.Helper()
		if err := rw.SaveFindings(ctx, run, fs); err != nil {
			t.Fatal(err)
		}
		if _, err := rw.db.Exec(`UPDATE runs SET created_at = CAST(? AS TIMESTAMPTZ) WHERE run_id = ?`, at.Format(time.RFC3339), run); err != nil {
			t.Fatal(err)
		}
	}
	f := func(tag string, sev core.Severity) core.Finding {
		return core.Finding{Detector: "authspike", Tag: tag, Severity: sev, Summary: "s " + tag,
			Detail: map[string]any{"secret": "never selected"}}
	}
	save("watch-20261105T110000Z", tlBase.Add(-time.Hour), f("a1", core.SevHigh), f("a2", core.SevInfo))
	save("watch-a-20261105T113000Z", tlBase.Add(-30*time.Minute), f("b1", core.SevCritical))
	save("watch-ab-20261105T114000Z", tlBase.Add(-20*time.Minute), f("c1", core.SevCheck))
	save("hunt-9", tlBase.Add(-10*time.Minute), f("h1", core.SevHigh))
	save("watch-20261105T120000Z", tlBase, f("edge", core.SevHigh)) // at To: excluded
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}
	d, err := OpenDashboard(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func tags(p core.FindingsPage) []string {
	var out []string
	for _, r := range p.Rows {
		out = append(out, r.Tag)
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestFindingsBetweenWindowIsHalfOpenAndNewestFirst(t *testing.T) {
	d := timelineFixture(t)
	q := core.FindingsQuery{From: tlBase.Add(-time.Hour), To: tlBase, Limit: 50}
	p, err := d.FindingsBetween(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	// From is inclusive, To exclusive; newest run first, most severe first within a run.
	if want := []string{"h1", "c1", "b1", "a1", "a2"}; !eq(tags(p), want) || p.More {
		t.Errorf("tags = %v more=%v, want %v", tags(p), p.More, want)
	}
	if !p.Rows[0].Created.Equal(tlBase.Add(-10 * time.Minute)) {
		t.Errorf("created = %v", p.Rows[0].Created)
	}
	if p.Rows[3].Run != "watch-20261105T110000Z" || p.Rows[3].Detector != "authspike" || p.Rows[3].Severity != core.SevHigh {
		t.Errorf("row = %+v", p.Rows[3])
	}
	if p.Rows[3].Detail != nil {
		t.Errorf("detail was read: %v", p.Rows[3].Detail)
	}
}

func TestFindingsBetweenLimitAndMore(t *testing.T) {
	d := timelineFixture(t)
	q := core.FindingsQuery{From: tlBase.Add(-time.Hour), To: tlBase, Limit: 5}
	if p, _ := d.FindingsBetween(context.Background(), q); len(p.Rows) != 5 || p.More {
		t.Errorf("limit = rows %d more %v, want 5 and not more (exactly Limit matched)", len(p.Rows), p.More)
	}
	q.Limit = 4
	p, err := d.FindingsBetween(context.Background(), q)
	if err != nil || len(p.Rows) != 4 || !p.More {
		t.Errorf("limit 4 = rows %d more %v err %v, want 4 and more", len(p.Rows), p.More, err)
	}
	q.Limit = 0
	if _, err := d.FindingsBetween(context.Background(), q); err == nil {
		t.Error("a zero limit must be refused")
	}
}

func TestFindingsBetweenSeverityAndPrefixFilters(t *testing.T) {
	d := timelineFixture(t)
	q := core.FindingsQuery{From: tlBase.Add(-time.Hour), To: tlBase, Limit: 50, Severities: []core.Severity{core.SevHigh, core.SevCritical}}
	p, _ := d.FindingsBetween(context.Background(), q)
	if want := []string{"h1", "b1", "a1"}; !eq(tags(p), want) {
		t.Errorf("severity filter = %v, want %v", tags(p), want)
	}
	// "watch-a-" must not reach "watch-ab-", and "watch-" must not reach a named watcher.
	q = core.FindingsQuery{From: tlBase.Add(-time.Hour), To: tlBase, Limit: 50, RunPrefixes: []string{"watch-a-"}}
	if p, _ = d.FindingsBetween(context.Background(), q); !eq(tags(p), []string{"b1"}) {
		t.Errorf("prefix watch-a- = %v", tags(p))
	}
	q.RunPrefixes = []string{"watch-"}
	if p, _ = d.FindingsBetween(context.Background(), q); !eq(tags(p), []string{"a1", "a2"}) {
		t.Errorf("prefix watch- = %v (named watchers and hunts must not match)", tags(p))
	}
	q.RunPrefixes = []string{"watch-", "watch-ab-"}
	if p, _ = d.FindingsBetween(context.Background(), q); !eq(tags(p), []string{"c1", "a1", "a2"}) {
		t.Errorf("two prefixes = %v", tags(p))
	}
}

func TestFindingsBetweenHostileValuesAreOnlyData(t *testing.T) {
	d := timelineFixture(t)
	q := core.FindingsQuery{From: tlBase.Add(-time.Hour), To: tlBase, Limit: 50, RunPrefixes: []string{`') OR 1=1 --`, `.*`, `watch-.*`}}
	p, err := d.FindingsBetween(context.Background(), q)
	if err != nil || len(p.Rows) != 0 {
		t.Errorf("hostile prefixes matched %v, err %v", tags(p), err)
	}
}

func TestFindingsBetweenIsReadOnlyHandle(t *testing.T) {
	d := timelineFixture(t)
	if _, err := d.s.db.Exec(`DELETE FROM findings`); err == nil {
		t.Fatal("the handle accepted a delete")
	}
}
