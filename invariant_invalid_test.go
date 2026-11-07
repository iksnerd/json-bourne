package jb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hostileFiles are inputs no loader behind the public API may crash on or hang over.
func hostileFiles() map[string]string {
	return map[string]string{
		"empty":            "",
		"null":             "null",
		"scalar":           "42",
		"tab indent":       "a:\n\tb: 1\n",
		"unclosed flow":    "a: [1, 2",
		"unclosed quote":   "a: \"unterminated",
		"bad utf8":         "a: \xff\xfe\xfd\n",
		"nul bytes":        "a: b\x00c\n",
		"huge int":         "a: 99999999999999999999999999999999999999999999\n",
		"huge exp":         "a: 1e99999999\n",
		"deep yaml":        "a: " + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + "\n",
		"self alias":       "loop: &x [*x]\n",
		"alias cycle":      "a: &a [*b]\nb: &b [*a]\n",
		"undefined alias":  "a: *nope\n",
		"alias fan-out":    "a: &a [1,1,1,1,1,1,1,1,1,1]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]\n",
		"long scalar":      "a: " + strings.Repeat("x", 1<<16) + "\n",
		"truncated json":   `{"apiVersion":"jb.estate-facts/v1","method":"m","facts":[{"node":"ip:192.0.2.1"`,
		"json deep array":  strings.Repeat("[", 20000) + strings.Repeat("]", 20000),
		"json deep object": strings.Repeat(`{"a":`, 5000) + "1" + strings.Repeat("}", 5000),
		"json huge number": `{"a": ` + strings.Repeat("9", 5000) + `}`,
		"json two values":  `{"a":1}{"a":2}`,
		"json lines junk":  "{}\n{\"node\":}\n\xff\n",
		"yaml tag":         "a: !!python/object:os.system x\n",
	}
}

func finishes(t *testing.T, name string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatalf("%s did not return within 20s", name)
	}
}

// Invariant: a damaged file in a case is a problem in the result, never a crash and never
// an OK case. The call has no recover: a panic fails the test.
func TestInvariantCaseCheckSurvivesAnyDamagedFile(t *testing.T) {
	files := []string{"case.yaml", "actors/example-actor.yaml", "estate/example-estate.yaml", "config/hunt.yaml"}
	for _, rel := range files {
		for name, body := range hostileFiles() {
			dir := copyCase(t)
			if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			finishes(t, rel+" "+name, func() {
				r, err := CaseCheck(dir)
				if err != nil || r == nil {
					t.Errorf("%s %s: a bad case is a result, got %v, %v", rel, name, r, err)
					return
				}
				if r.OK {
					t.Errorf("%s %s: a damaged file left the case OK", rel, name)
				}
				if r.FirstProblem() == "" {
					t.Errorf("%s %s: not OK but no problem named", rel, name)
				}
			})
		}
	}
}

// Invariant: any import file, as a file or a stream, is refused with an error and leaves
// the estate file as it was.
func TestInvariantEstateFactsImportRefusesAnyDamagedImport(t *testing.T) {
	dir := copyCase(t)
	file := "example-estate.yaml"
	estatePath := filepath.Join(dir, "estate", file)
	before, err := os.ReadFile(estatePath)
	if err != nil {
		t.Fatal(err)
	}
	opts := EstateFactsImportOptions{EstateOptions: EstateOptions{File: file}, Apply: true}
	for name, body := range hostileFiles() {
		finishes(t, name, func() {
			p := filepath.Join(t.TempDir(), "in.json")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Error(err)
				return
			}
			if res, err := EstateFactsImport(dir, p, opts); err == nil {
				t.Errorf("%s: damaged import accepted: %+v", name, res)
			}
			o := opts
			o.Input = strings.NewReader(body)
			if res, err := EstateFactsImport(dir, "", o); err == nil {
				t.Errorf("%s (stream): damaged import accepted: %+v", name, res)
			}
		})
	}
	after, _ := os.ReadFile(estatePath)
	if string(after) != string(before) {
		t.Fatal("a refused import changed the estate file")
	}
}

// Invariant: the public config loader refuses a damaged file with an error.
func TestInvariantLoadConfigRefusesAnyDamagedFile(t *testing.T) {
	for name, body := range hostileFiles() {
		p := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		finishes(t, name, func() {
			if c, err := LoadConfig(p); err == nil {
				t.Errorf("%s: damaged config accepted: %+v", name, c)
			}
		})
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("a missing config was accepted")
	}
}
