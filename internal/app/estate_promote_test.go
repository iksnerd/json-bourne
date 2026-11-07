package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/casefile"
)

const promoteBaselineYAML = `apiVersion: jb.estate/v2
id: estate
caveat: A synthetic map for a promotion test, not a statement about anyone.
nodes:
  - id: ip:192.0.2.10
    kind: ip
    label: 192.0.2.10
    source: rdns
    method: "PTR 10.2.0.192.in-addr.arpa via system resolver"
    observed: 2026-11-06T10:00:00Z
`

type promoteWorld struct {
	c        *casefile.Case
	estate   string // the estate directory
	baseline string // the baseline file
	snap     string // the snapshot id
}

func newPromoteWorld(t *testing.T, services []casefile.SnapshotService, complete bool) *promoteWorld {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "case.yaml"),
		[]byte("apiVersion: jb.case/v1\nid: t\ntitle: t\nstatus: open\nopened: 2026-11-01\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	c, err := casefile.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	w := &promoteWorld{c: c, estate: filepath.Join(dir, "estate")}
	w.baseline = filepath.Join(w.estate, "estate.yaml")
	if err := os.MkdirAll(w.estate, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.baseline, []byte(promoteBaselineYAML), 0o640); err != nil {
		t.Fatal(err)
	}
	body, err := casefile.ParseEstate([]byte(strings.Replace(promoteBaselineYAML, "2026-11-06T10:00:00Z", "2026-11-06T11:00:00Z", 1)))
	if err != nil {
		t.Fatal(err)
	}
	taken := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	s := &casefile.EstateSnapshot{
		APIVersion: casefile.EstateSnapshotAPIVersion, ID: casefile.SnapshotID(taken), Taken: taken.Format(time.RFC3339),
		Complete: complete, Targets: casefile.SnapshotTargets{Addresses: []string{"192.0.2.10"}},
		Services: services, Estate: *body,
	}
	if !complete {
		s.Failures = []casefile.SnapshotFailure{{Target: "192.0.2.10", Lookup: "rdap", Reason: "timeout"}}
	}
	if _, err := casefile.WriteEstateSnapshot(c, s); err != nil {
		t.Fatal(err)
	}
	w.snap = s.ID
	return w
}

func okServices() []casefile.SnapshotService {
	return []casefile.SnapshotService{{Name: "rdap", State: casefile.ServiceRan, Targets: 1}}
}

func (w *promoteWorld) read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (w *promoteWorld) archives(t *testing.T) []string {
	t.Helper()
	es, err := os.ReadDir(filepath.Join(w.estate, casefile.EstateArchiveDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// noTemp fails if a temporary publication file was left in a directory.
func noTemp(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		es, _ := os.ReadDir(d)
		for _, e := range es {
			if strings.HasSuffix(e.Name(), ".tmp") {
				t.Errorf("temporary file left behind in %s: %s", d, e.Name())
			}
		}
	}
}

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission failures cannot be injected as root")
	}
}

func TestPromoteRefusesIncompleteAndSkippedWithoutTouchingFiles(t *testing.T) {
	for name, w := range map[string]*promoteWorld{
		"incomplete": newPromoteWorld(t, okServices(), false),
		"skipped": newPromoteWorld(t, []casefile.SnapshotService{
			{Name: "rdap", State: casefile.ServiceRan, Targets: 1},
			{Name: "dns", State: casefile.ServiceSkipped, Targets: 1, Reason: "off"}}, true),
	} {
		_, err := PromoteSnapshot(w.c, w.snap, "estate.yaml", time.Now())
		if !errors.Is(err, ErrNotPromotable) {
			t.Errorf("%s: want ErrNotPromotable, got %v", name, err)
		}
		if w.read(t, w.baseline) != promoteBaselineYAML || len(w.archives(t)) != 0 {
			t.Errorf("%s: a refused promotion changed files", name)
		}
	}
}

// Failure after the archive was written: the baseline is the old one, byte for byte, the
// caller is told the archive exists, and promoting again converges on one archive.
func TestPromoteReplaceFailureIsReportedAndRerunConverges(t *testing.T) {
	skipIfRoot(t)
	w := newPromoteWorld(t, okServices(), true)
	if err := os.MkdirAll(filepath.Join(w.estate, casefile.EstateArchiveDir), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(w.estate, 0o500); err != nil { // archive dir stays writable, the estate dir does not
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if !restored {
			restored = true
			_ = os.Chmod(w.estate, 0o750)
		}
	}
	defer restore()

	now := time.Now().UTC()
	archived, err := PromoteSnapshot(w.c, w.snap, "estate.yaml", now)
	if err == nil {
		t.Fatal("the replace should have failed")
	}
	if archived == "" {
		t.Fatal("the archive that was written must be returned")
	}
	var pe *PromotionError
	if !errors.As(err, &pe) || pe.Archived != archived {
		t.Fatalf("the error must be a *PromotionError naming the archive: %T %v", err, err)
	}
	if !strings.Contains(err.Error(), archived) || !strings.Contains(err.Error(), "not replaced") {
		t.Errorf("the text must say the archive exists and the baseline is unchanged: %v", err)
	}
	restore()
	if w.read(t, w.baseline) != promoteBaselineYAML {
		t.Error("the baseline changed although the replace failed")
	}
	noTemp(t, w.estate)

	// Re-run later: converges, one archive, baseline now the snapshot's body.
	if _, err := PromoteSnapshot(w.c, w.snap, "estate.yaml", now.Add(5*time.Second)); err != nil {
		t.Fatalf("the re-run must succeed: %v", err)
	}
	if n := len(w.archives(t)); n != 1 {
		t.Errorf("a re-run after a partial failure must not add a second archive of the same baseline: %v", w.archives(t))
	}
	if !strings.Contains(w.read(t, w.baseline), "2026-11-06T11:00:00Z") {
		t.Error("the baseline is not the snapshot's body")
	}
	noTemp(t, w.estate)
}

// The same second is the same archive name: the identical copy is reused, not refused.
func TestPromoteRerunInTheSameSecondConverges(t *testing.T) {
	skipIfRoot(t)
	w := newPromoteWorld(t, okServices(), true)
	if err := os.MkdirAll(filepath.Join(w.estate, casefile.EstateArchiveDir), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(w.estate, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(w.estate, 0o750)
	now := time.Now().UTC()
	if _, err := PromoteSnapshot(w.c, w.snap, "estate.yaml", now); err == nil {
		t.Fatal("the replace should have failed")
	}
	if err := os.Chmod(w.estate, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := PromoteSnapshot(w.c, w.snap, "estate.yaml", now); err != nil {
		t.Fatalf("same-second re-run: %v", err)
	}
	if len(w.archives(t)) != 1 {
		t.Errorf("%v", w.archives(t))
	}
}

// Archive fails (the name is taken by different content): nothing is replaced, nothing
// is overwritten, and the error says the baseline was not replaced.
func TestPromoteArchiveFailureReplacesNothingAndOverwritesNothing(t *testing.T) {
	w := newPromoteWorld(t, okServices(), true)
	now := time.Now().UTC()
	dir := filepath.Join(w.estate, casefile.EstateArchiveDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	taken := filepath.Join(dir, "estate-"+casefile.SnapshotID(now)+".yaml")
	if err := os.WriteFile(taken, []byte("someone else's bytes\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	archived, err := PromoteSnapshot(w.c, w.snap, "estate.yaml", now)
	if err == nil || archived != "" {
		t.Fatalf("want an archive error and no archive path: %q %v", archived, err)
	}
	var pe *PromotionError
	if errors.As(err, &pe) {
		t.Error("nothing was archived, so this is not the in-between outcome")
	}
	if !strings.Contains(err.Error(), "not replaced") {
		t.Errorf("the text must say the baseline was not replaced: %v", err)
	}
	if w.read(t, w.baseline) != promoteBaselineYAML {
		t.Error("the baseline changed")
	}
	if w.read(t, taken) != "someone else's bytes\n" {
		t.Error("an existing archive was overwritten")
	}
	noTemp(t, w.estate, dir)
}

// Archive directory not writable: nothing changes, no temp file.
func TestPromoteArchiveDirReadOnly(t *testing.T) {
	skipIfRoot(t)
	w := newPromoteWorld(t, okServices(), true)
	dir := filepath.Join(w.estate, casefile.EstateArchiveDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o750)
	if _, err := PromoteSnapshot(w.c, w.snap, "estate.yaml", time.Now()); err == nil {
		t.Fatal("want an error")
	}
	if w.read(t, w.baseline) != promoteBaselineYAML {
		t.Error("the baseline changed")
	}
	noTemp(t, w.estate, dir)
}
