package jb

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/casefile"
)

func setSubject(t *testing.T, dir, file, subject string) {
	t.Helper()
	c, err := casefile.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, err := casefile.LoadEstateFile(c, file)
	if err != nil {
		t.Fatal(err)
	}
	e.Subject, e.ID = subject, strings.TrimSuffix(file, ".yaml")
	if err := casefile.SaveEstateFile(c, file, e); err != nil {
		t.Fatal(err)
	}
}

func subjectOf(t *testing.T, dir, file string) string {
	t.Helper()
	c, err := casefile.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, err := casefile.LoadEstateFile(c, file)
	if err != nil {
		t.Fatal(err)
	}
	return e.Subject
}

func TestEstateRefreshAndPromoteKeepTheSubject(t *testing.T) {
	w := newEstateWorld()
	dir := copyCase(t)
	enableEstate(t, dir, "dns")
	base := w.opts("base.yaml")
	if _, err := EstateDNS(t.Context(), dir, []string{"example.com"}, EstateExternalOptions{EstateOptions: base}); err != nil {
		t.Fatal(err)
	}
	setSubject(t, dir, "base.yaml", "operated")
	w.tick()
	w.ns = []string{"ns1.example.com", "ns7.example.com"}
	snap, err := EstateRefresh(t.Context(), dir, EstateRefreshOptions{EstateOptions: base})
	if err != nil || !snap.Complete() {
		t.Fatalf("%+v %v", snap, err)
	}
	c, _ := casefile.Load(dir)
	s, err := casefile.LoadEstateSnapshot(c, snap.Snapshot)
	if err != nil || s.Estate.Subject != "operated" {
		t.Fatalf("the snapshot must copy its baseline's subject: %v %+v", err, s)
	}
	if _, err := EstateDiff(t.Context(), dir, EstateDiffOptions{EstateOptions: base}); err != nil {
		t.Fatalf("a baseline and its own snapshot share a subject: %v", err)
	}
	if _, err := EstatePromote(dir, snap.Snapshot, base); err != nil {
		t.Fatal(err)
	}
	if got := subjectOf(t, dir, "base.yaml"); got != "operated" {
		t.Errorf("promote dropped the subject: %q", got)
	}
}

func TestEstateDiffRefusesFilesOfDifferentSubjects(t *testing.T) {
	w := newEstateWorld()
	dir := copyCase(t)
	enableEstate(t, dir, "dns")
	for _, f := range []string{"a.yaml", "b.yaml"} {
		if _, err := EstateDNS(t.Context(), dir, []string{"example.com"}, EstateExternalOptions{EstateOptions: w.opts(f)}); err != nil {
			t.Fatal(err)
		}
	}
	setSubject(t, dir, "a.yaml", "operated")
	setSubject(t, dir, "b.yaml", "adversary")
	_, err := EstateDiff(t.Context(), dir, EstateDiffOptions{EstateOptions: w.opts("a.yaml"), From: "a.yaml", To: "b.yaml"})
	if !IsUsage(err) || !strings.Contains(err.Error(), "operated") || !strings.Contains(err.Error(), "adversary") {
		t.Errorf("want a usage error naming both subjects, got %v", err)
	}
}

func TestCaseWithMixedSubjectsChecksAndLoads(t *testing.T) {
	w := newEstateWorld()
	dir := copyCase(t)
	enableEstate(t, dir, "dns")
	for _, f := range []string{"ours.yaml", "theirs.yaml", "unsorted.yaml"} {
		if _, err := EstateDNS(t.Context(), dir, []string{"example.com"}, EstateExternalOptions{EstateOptions: w.opts(f)}); err != nil {
			t.Fatal(err)
		}
	}
	setSubject(t, dir, "ours.yaml", "operated")
	setSubject(t, dir, "theirs.yaml", "adversary")
	r, err := CaseCheck(dir)
	if err != nil || r.Estate == nil || !r.Estate.OK {
		t.Fatalf("a case with mixed subjects must check: %+v %+v %v", r, r.Estate, err)
	}
	gs, err := dashEstate{c: mustCase(t, dir)}.Estates(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, g := range gs {
		got[g.ID] = g.Subject
	}
	var subjects []string
	for _, s := range got {
		subjects = append(subjects, s)
	}
	if !slices.Contains(subjects, "operated") || !slices.Contains(subjects, "adversary") || !slices.Contains(subjects, "") {
		t.Errorf("the dashboard graphs must carry each file's subject: %v", got)
	}
	// A hostile subject written by hand is refused by the loader, so the check fails.
	p := filepath.Join(dir, "estate", "unsorted.yaml")
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), "apiVersion: jb.estate/v2\n", "apiVersion: jb.estate/v2\nsubject: \"<script>alert(1)</script>\"\n", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	r, _ = CaseCheck(dir)
	if r.Estate.OK || strings.Contains(r.Estate.Error, "<script>") && !strings.Contains(r.Estate.Error, "adversary") {
		t.Errorf("hostile subject must fail the check naming the valid ones: %+v", r.Estate)
	}
}

func mustCase(t *testing.T, dir string) *casefile.Case {
	t.Helper()
	c, err := casefile.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
