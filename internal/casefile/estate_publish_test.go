package casefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func noTempIn(t *testing.T, dir string) {
	t.Helper()
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temporary file left in %s: %s", dir, e.Name())
		}
	}
}

// A rename that cannot happen (the target name is a directory) leaves no temporary file.
func TestSaveEstateFileCleansTheTempFileWhenTheRenameFails(t *testing.T) {
	c := newCase(t)
	if err := os.MkdirAll(filepath.Join(c.Dir, "estate", "estate.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := SaveEstateFile(c, "estate.yaml", mustEstate(t, validEstate)); err == nil {
		t.Fatal("want an error")
	}
	noTempIn(t, filepath.Join(c.Dir, "estate"))
}

// A refused (invalid) save writes nothing and leaves the old file intact.
func TestSaveEstateFileRefusedLeavesTheOldFile(t *testing.T) {
	c := newCase(t)
	writeEstate(t, c.Dir, "estate.yaml", validEstate)
	bad := mustEstate(t, validEstate)
	bad.ID = "NOT VALID"
	if err := SaveEstateFile(c, "estate.yaml", bad); err == nil {
		t.Fatal("want an error")
	}
	got, _ := os.ReadFile(filepath.Join(c.Dir, "estate", "estate.yaml"))
	if string(got) != validEstate {
		t.Error("the old file changed")
	}
	noTempIn(t, filepath.Join(c.Dir, "estate"))
}

// A snapshot that already exists is not replaced and the failed attempt leaves no temp file.
func TestWriteEstateSnapshotExistingLeavesBytesAndNoTemp(t *testing.T) {
	c := newCase(t)
	s := validSnapshot(t)
	if _, err := WriteEstateSnapshot(c, s); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(c.Dir, "estate", EstateSnapshotDir, s.ID+".yaml")
	before, _ := os.ReadFile(p)
	s2 := validSnapshot(t)
	s2.BasedOn = "estate/other.yaml"
	if _, err := WriteEstateSnapshot(c, s2); !errors.Is(err, ErrSnapshotExists) {
		t.Fatalf("%v", err)
	}
	after, _ := os.ReadFile(p)
	if string(after) != string(before) {
		t.Error("an existing snapshot was overwritten")
	}
	noTempIn(t, filepath.Dir(p))
}

// An archive of the same bytes is reused under another id; a different baseline is a new file.
func TestArchiveEstateFileReusesIdenticalCopyAndRefusesDifferentBytes(t *testing.T) {
	c := newCase(t)
	writeEstate(t, c.Dir, "estate.yaml", validEstate)
	first, err := ArchiveEstateFile(c, "estate.yaml", "20261106T100000Z")
	if err != nil {
		t.Fatal(err)
	}
	again, err := ArchiveEstateFile(c, "estate.yaml", "20261106T100009Z")
	if err != nil || again != first {
		t.Fatalf("an unchanged baseline must reuse its archive: %q %q %v", first, again, err)
	}
	// Same name, different bytes: refused, untouched.
	name := filepath.Join(c.Dir, "estate", EstateArchiveDir, "estate-20261106T100005Z.yaml")
	if err := os.WriteFile(name, []byte("other\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(validEstate, "Example Network Operator", "Changed Operator", 1)
	writeEstate(t, c.Dir, "estate.yaml", changed)
	if _, err := ArchiveEstateFile(c, "estate.yaml", "20261106T100005Z"); !errors.Is(err, os.ErrExist) {
		t.Errorf("want ErrExist, got %v", err)
	}
	if b, _ := os.ReadFile(name); string(b) != "other\n" {
		t.Error("an archive was overwritten")
	}
	// A changed baseline under a free name is a second, distinct archive.
	if rel, err := ArchiveEstateFile(c, "estate.yaml", "20261106T100010Z"); err != nil || rel == first {
		t.Errorf("%q %v", rel, err)
	}
	noTempIn(t, filepath.Join(c.Dir, "estate", EstateArchiveDir))
}
