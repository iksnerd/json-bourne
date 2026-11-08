package jb

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/casefile"
)

func factsLines(n int) string {
	var b strings.Builder
	b.WriteString(`{"apiVersion":"jb.estate-facts/v1","method":"m","source_note":"s","observed":"2026-11-05T08:00:00Z"}` + "\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `{"node":"ip:192.0.2.10","key":"k%d","values":["v"]}`+"\n", i)
	}
	return b.String()
}

func leftTemp(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}

// The fact cap holds for the file and for standard input in JSON lines, and a refused
// import writes nothing.
func TestEstateFactsImportFactCapHoldsForEveryInputShape(t *testing.T) {
	over := factsLines(casefile.MaxFactsImportFacts + 1)
	dir := copyCase(t)
	file := "example-estate.yaml"
	have := estateFacts(t, dir, file)
	opts := EstateFactsImportOptions{EstateOptions: EstateOptions{File: file}, Apply: true}
	if _, err := EstateFactsImport(dir, writeImport(t, over), opts); !IsUsage(err) {
		t.Errorf("file, json lines: %v", err)
	}
	o := opts
	o.Input = strings.NewReader(over)
	if _, err := EstateFactsImport(dir, "", o); !IsUsage(err) {
		t.Errorf("stdin, json lines: %v", err)
	}
	if got := estateFacts(t, dir, file); got != have {
		t.Errorf("a refused import wrote: %d, had %d", got, have)
	}
}

// A bad entry after good ones refuses the whole import; nothing is written.
func TestEstateFactsImportFailureMidMergeWritesNothing(t *testing.T) {
	dir := copyCase(t)
	file := "example-estate.yaml"
	before, _ := os.ReadFile(filepath.Join(dir, "estate", file))
	body := factsImportLines + `{"node":"ip:203.0.113.99","key":"os","values":["linux"]}` + "\n"
	_, err := EstateFactsImport(dir, "", EstateFactsImportOptions{EstateOptions: EstateOptions{File: file}, Input: strings.NewReader(body), Apply: true})
	if !IsUsage(err) {
		t.Fatalf("%v", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "estate", file))
	if string(after) != string(before) {
		t.Error("the estate file changed")
	}
	leftTemp(t, filepath.Join(dir, "estate"))
}

// Applied is true only after the save succeeded: a save that fails returns an error and
// no result, and leaves the file as it was.
func TestEstateFactsImportAppliedOnlyAfterASuccessfulSave(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("cannot inject a permission failure as root")
	}
	dir := copyCase(t)
	file := "example-estate.yaml"
	estateDir := filepath.Join(dir, "estate")
	before, _ := os.ReadFile(filepath.Join(estateDir, file))
	if err := os.Chmod(estateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(estateDir, 0o750)
	res, err := EstateFactsImport(dir, writeImport(t, factsImportDoc), EstateFactsImportOptions{EstateOptions: EstateOptions{File: file}, Apply: true})
	if err == nil || res != nil {
		t.Fatalf("want an error and no result, got %v %+v", err, res)
	}
	os.Chmod(estateDir, 0o750)
	after, _ := os.ReadFile(filepath.Join(estateDir, file))
	if string(after) != string(before) {
		t.Error("the estate file changed")
	}
	leftTemp(t, estateDir)
}
