package casefile

import (
	"os"
	"path/filepath"
	"testing"
)

// A successful save leaves exactly the marshalled bytes and no temporary file.
func TestSaveEstateFileLeavesExactlyTheNewBytes(t *testing.T) {
	c := newCase(t)
	writeEstate(t, c.Dir, "estate.yaml", validEstate)
	e := mustEstate(t, validEstate)
	e.Caveat = "synthetic caveat " + t.Name()
	want, err := MarshalEstate(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveEstateFile(c, "estate.yaml", e); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(c.Dir, "estate")
	got, _ := os.ReadFile(filepath.Join(dir, "estate.yaml"))
	if string(got) != string(want) {
		t.Error("saved bytes differ from the marshalled estate")
	}
	ents, _ := os.ReadDir(dir)
	for _, en := range ents {
		if en.Name() != "estate.yaml" && !en.IsDir() {
			t.Errorf("unexpected file %s", en.Name())
		}
	}
}

// An unwritable directory fails the save, keeps the old bytes and leaves no temp file.
// fsync itself cannot be observed from a test; this pins the failure path around it.
func TestSaveEstateFileReadOnlyDirKeepsOldFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	c := newCase(t)
	writeEstate(t, c.Dir, "estate.yaml", validEstate)
	dir := filepath.Join(c.Dir, "estate")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o750) })
	e := mustEstate(t, validEstate)
	e.Caveat = "synthetic caveat " + t.Name()
	if err := SaveEstateFile(c, "estate.yaml", e); err == nil {
		t.Fatal("want an error")
	}
	got, _ := os.ReadFile(filepath.Join(dir, "estate.yaml"))
	if string(got) != validEstate {
		t.Error("the old file changed")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("directory holds %d entries, want only the old file", len(ents))
	}
}
