package casefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validSnapshot(t *testing.T) *EstateSnapshot {
	t.Helper()
	e := mustEstate(t, validEstate)
	taken := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	return &EstateSnapshot{
		APIVersion: EstateSnapshotAPIVersion, ID: SnapshotID(taken), Taken: taken.Format(time.RFC3339), Complete: true,
		BasedOn:  "estate/estate.yaml",
		Targets:  SnapshotTargets{Domains: []string{"example.com"}},
		Services: []SnapshotService{{Name: "dns", State: ServiceRan, Targets: 1}},
		Estate:   *e,
	}
}

func TestSnapshotRoundTripAndLayout(t *testing.T) {
	c := newCase(t)
	s := validSnapshot(t)
	rel, err := WriteEstateSnapshot(c, s)
	if err != nil || rel != "estate/snapshots/20261106T100000Z.yaml" {
		t.Fatalf("%q %v", rel, err)
	}
	got, err := LoadEstateSnapshot(c, s.ID)
	if err != nil || got.ID != s.ID || !got.Complete || len(got.Estate.Nodes) != len(s.Estate.Nodes) {
		t.Fatalf("%v %+v", err, got)
	}
	// Snapshots are not estate files: the estate loader and `jb case check` never see them.
	if es, err := LoadEstates(c); err != nil || len(es) != 0 {
		t.Errorf("a snapshot must not load as an estate map: %v %v", es, err)
	}
	ents, _ := os.ReadDir(filepath.Join(c.Dir, "estate", "snapshots"))
	if len(ents) != 1 {
		t.Errorf("a temporary file was left behind: %v", ents)
	}
	st, err := LoadEstateState(c, s.ID)
	if err != nil || st.Snapshot == nil || st.Path != rel {
		t.Errorf("by id: %v %+v", err, st)
	}
	if st, err = LoadEstateState(c, "snapshots/"+s.ID+".yaml"); err != nil || st.Snapshot == nil {
		t.Errorf("by path: %v", err)
	}
}

// A snapshot is evidence of a run. Overwriting one would rewrite history.
func TestWriteEstateSnapshotNeverOverwrites(t *testing.T) {
	c := newCase(t)
	s := validSnapshot(t)
	if _, err := WriteEstateSnapshot(c, s); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(c.Dir, "estate", "snapshots", s.ID+".yaml"))
	again := validSnapshot(t)
	again.Note = "second run in the same second"
	if _, err := WriteEstateSnapshot(c, again); !errors.Is(err, ErrSnapshotExists) {
		t.Fatalf("want ErrSnapshotExists, got %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(c.Dir, "estate", "snapshots", s.ID+".yaml"))
	if string(before) != string(after) {
		t.Error("the existing snapshot was changed")
	}
	if ents, _ := os.ReadDir(filepath.Join(c.Dir, "estate", "snapshots")); len(ents) != 1 {
		t.Errorf("a temporary file was left behind: %v", ents)
	}
}

func TestSnapshotLoaderIsStrict(t *testing.T) {
	good, err := MarshalEstateSnapshot(validSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	s := string(good)
	for name, mut := range map[string]func(string) string{
		"unknown key":        func(x string) string { return x + "surprise: 1\n" },
		"unknown nested key": func(x string) string { return strings.Replace(x, "  - name: dns", "  - colour: red\n    name: dns", 1) },
		"wrong apiVersion":   func(x string) string { return strings.Replace(x, EstateSnapshotAPIVersion, "jb.estate-snapshot/v3", 1) },
		"complete missing":   func(x string) string { return strings.Replace(x, "complete: true\n", "", 1) },
		"complete but failed": func(x string) string {
			return strings.Replace(x, "services:", "failures:\n  - target: a\n    lookup: b\n    reason: c\nservices:", 1)
		},
		"incomplete no reason": func(x string) string { return strings.Replace(x, "complete: true", "complete: false", 1) },
		"id not taken":         func(x string) string { return strings.Replace(x, "id: 20261106T100000Z", "id: 20261107T100000Z", 1) },
		"bad service state":    func(x string) string { return strings.Replace(x, "state: ran", "state: maybe", 1) },
		"estate broken":        func(x string) string { return strings.Replace(x, "source: rdap", "source: nmap", 1) },
		"two documents":        func(x string) string { return x + "---\nx: 1\n" },
		"empty":                func(string) string { return "" },
	} {
		if _, err := ParseEstateSnapshot([]byte(mut(s))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseEstateSnapshot(good); err != nil {
		t.Errorf("control: %v", err)
	}
}

func TestCorruptSnapshotIsAnErrorNotAnEmptyBaseline(t *testing.T) {
	c := newCase(t)
	older := validSnapshot(t)
	older.ID, older.Taken = "20261101T100000Z", "2026-11-01T10:00:00Z"
	if _, err := WriteEstateSnapshot(c, older); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(c.Dir, "estate", "snapshots")
	if err := os.WriteFile(filepath.Join(dir, "20261106T100000Z.yaml"), []byte("apiVersion: jb.estate-snapshot/v2\ngarbage: [\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LatestEstateSnapshot(c); err == nil || !strings.Contains(err.Error(), "20261106T100000Z") {
		t.Fatalf("a corrupt newest snapshot must be an error naming it, not a silent fall back to the older one: %v", err)
	}
	if _, err := LoadEstateSnapshot(c, "20261106T100000Z"); err == nil {
		t.Error("corrupt snapshot loaded")
	}
	// A stray file in the directory is reported too.
	os.Remove(filepath.Join(dir, "20261106T100000Z.yaml"))
	if err := os.WriteFile(filepath.Join(dir, "notes.yaml"), []byte("x: 1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ListEstateSnapshots(c); err == nil {
		t.Error("a file that is not a snapshot must be reported")
	}
}

func TestSnapshotNamedForItsIDAndConfined(t *testing.T) {
	c := newCase(t)
	s := validSnapshot(t)
	data, _ := MarshalEstateSnapshot(s)
	dir := filepath.Join(c.Dir, "estate", "snapshots")
	os.MkdirAll(dir, 0o750)
	if err := os.WriteFile(filepath.Join(dir, "20261105T100000Z.yaml"), data, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEstateSnapshot(c, "20261105T100000Z"); err == nil {
		t.Error("a snapshot file whose id differs from its name was accepted")
	}
	for _, bad := range []string{"../x", "20261106T100000Z/../../x", "latest", ""} {
		if _, err := LoadEstateState(c, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	outside := t.TempDir()
	os.Remove(filepath.Join(dir, "20261105T100000Z.yaml"))
	os.Remove(dir)
	if err := os.Symlink(outside, dir); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := WriteEstateSnapshot(c, s); err == nil {
		t.Error("wrote through a symlinked snapshot directory")
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("something was written outside the case: %v", ents)
	}
}

func TestIncompleteSnapshotMayBeEmptyButMustSayWhy(t *testing.T) {
	c := newCase(t)
	s := validSnapshot(t)
	s.Complete = false
	s.Estate = Estate{APIVersion: EstateAPIVersion, ID: "estate", Caveat: DefaultEstateCaveat}
	s.Failures = []SnapshotFailure{{Target: "example.com", Lookup: "dns/NS", Reason: "timeout"}}
	if _, err := WriteEstateSnapshot(c, s); err != nil {
		t.Fatalf("a run where every lookup failed must still leave a record: %v", err)
	}
	got, err := LoadEstateSnapshot(c, s.ID)
	if err != nil || got.Complete || len(got.Failures) != 1 {
		t.Errorf("%v %+v", err, got)
	}
	s.Complete = true
	s.Failures = nil
	s.ID, s.Taken = "20261107T100000Z", "2026-11-07T10:00:00Z"
	if _, err := WriteEstateSnapshot(c, s); err == nil {
		t.Error("a complete snapshot with no nodes was accepted")
	}
}

func TestArchiveEstateFileKeepsTheBaselineAndNeverOverwrites(t *testing.T) {
	c := newCase(t)
	writeEstate(t, c.Dir, "estate.yaml", validEstate)
	rel, err := ArchiveEstateFile(c, "estate.yaml", "20261106T100000Z")
	if err != nil || rel != "estate/archive/estate-20261106T100000Z.yaml" {
		t.Fatalf("%q %v", rel, err)
	}
	// The same bytes under the same name are the same archive, reused (see
	// TestArchiveEstateFileReusesIdenticalCopyAndRefusesDifferentBytes for the refusal).
	if again, err := ArchiveEstateFile(c, "estate.yaml", "20261106T100000Z"); err != nil || again != rel {
		t.Errorf("%q %v", again, err)
	}
	if es, err := LoadEstates(c); err != nil || len(es) != 1 {
		t.Errorf("the archive must not load as a second map: %v %v", es, err)
	}
}

func TestSnapshotDigestFieldIsValidatedAndOptional(t *testing.T) {
	s := validSnapshot(t)
	if _, err := MarshalEstateSnapshot(s); err != nil {
		t.Fatalf("a snapshot without the digest still loads (it only cannot be promoted): %v", err)
	}
	s.BasedOnSHA256 = DigestHex([]byte("baseline"))
	data, err := MarshalEstateSnapshot(s)
	if err != nil {
		t.Fatalf("a 64-hex digest must not trip the credential scan: %v", err)
	}
	got, err := ParseEstateSnapshot(data)
	if err != nil || got.BasedOnSHA256 != s.BasedOnSHA256 {
		t.Fatalf("round trip: %v %+v", err, got)
	}
	for _, bad := range []string{"none", strings.ToUpper(s.BasedOnSHA256), s.BasedOnSHA256[:63], s.BasedOnSHA256 + "0"} {
		s.BasedOnSHA256 = bad
		if _, err := MarshalEstateSnapshot(s); err == nil {
			t.Errorf("digest %q must be refused", bad)
		}
	}
}

// The exemption is for the one key. The same 64 hex digits elsewhere is still refused.
func TestDigestExemptionDoesNotCoverOtherFields(t *testing.T) {
	s := validSnapshot(t)
	s.Note = DigestHex([]byte("x"))
	if _, err := MarshalEstateSnapshot(s); err == nil {
		t.Error("a long hex note must still be refused as credential-shaped")
	}
}
