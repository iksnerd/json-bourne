package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/jb"
)

// The library result carries the advice the CLI prints to stderr, in the same order, and
// Notice streams the same lines while the call runs (RFC 0013).
func TestLibraryNotesAreTheLinesTheCLIPrints(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	env := func(k string) (string, bool) { v, ok := huntEnv[k]; return v, ok }
	now := func() time.Time { return fixedNow }

	var streamed []string
	res, err := jb.HuntCase(context.Background(), dir, jb.CaseHuntOptions{
		Config: fpConfigRel,
		HuntOptions: jb.HuntOptions{
			Env: env, Now: now, Search: []string{"needle-token"},
			Notice: func(n string) { streamed = append(streamed, n) },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"window 1h from the case (windows.default)",
		"hunting search-20261105T120000Z [2026-11-05T11:00:00Z, 2026-11-05T12:00:00Z) with 1 source(s), 1 detector(s)",
		"narrowed by 1 search term(s) on field message (or each source's search_field); the detectors read the stored evidence for the window, which includes events saved by earlier runs, not only the matches",
	}
	if !reflect.DeepEqual(res.Notes, want) {
		t.Errorf("Hunt notes:\n got %q\nwant %q", res.Notes, want)
	}
	if !reflect.DeepEqual(streamed, res.Notes) {
		t.Errorf("Notice saw %q, Notes hold %q", streamed, res.Notes)
	}

	// A note raised before an error that returns no result still reaches Notice.
	streamed = nil
	editFile(t, dir+"/"+fpConfigRel, "type: kibana", "type: nonesuch")
	if _, err := jb.HuntCase(context.Background(), dir, jb.CaseHuntOptions{Config: fpConfigRel, HuntOptions: jb.HuntOptions{
		Env: env, Now: now, Notice: func(n string) { streamed = append(streamed, n) },
	}}); err == nil {
		t.Fatal("want an error for an unknown source type")
	}
	if len(streamed) != 1 || !strings.HasPrefix(streamed[0], "window 1h from the case") {
		t.Errorf("notes before the error = %q", streamed)
	}
}

func TestLibraryActivityNotes(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	res, err := jb.Activity(context.Background(), dir, jb.ActivityOptions{
		Config: fpConfigRel, Window: time.Hour, NoStore: true,
		Env: func(k string) (string, bool) { v, ok := huntEnv[k]; return v, ok },
		Now: func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	// The fingerprint case config reports activity, so nothing is skipped and nothing
	// needs saying: an empty Notes is the answer, not a missing field.
	if len(res.Notes) != 0 {
		t.Errorf("notes = %q, want none", res.Notes)
	}
}
