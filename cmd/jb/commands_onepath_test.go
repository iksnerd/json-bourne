package main

import (
	"os"
	"strings"
	"testing"
)

// TestEveryRFC0013CommandCallsItsLibraryFunction holds RFC 0013's "one path" rule for the
// commands that are not estate or intel (estate_onepath_test.go holds those): each
// command's file calls its function in package jb, and none of the steps the library owns
// is composed again in cmd/jb. A command that built its own config, store or use case
// would drift from the Go API.
//
// The check reads source because the call sits inside a cobra RunE closure.
func TestEveryRFC0013CommandCallsItsLibraryFunction(t *testing.T) {
	// The steps of a run that jb.Hunt, jb.HuntCase and jb.Activity own.
	runSteps := []string{"app.Hunt(", "app.Activity(", "config.OpenRunStore(", ".Build(", "config.Load(", "planCase(",
		"openCase(", "openCaseSearch(", "runDeps(", "watchrun.", "warnSourceOverlap(", "disabledOf(", "planWindow(", "windowPlan"}
	table := []struct {
		file      string
		calls     []string
		forbidden []string
	}{
		{"hunt.go", []string{"jb.Hunt(", "jb.HuntCase("}, runSteps},
		{"activity.go", []string{"jb.Activity("}, runSteps},
		{"case.go", []string{"jb.CaseCheck("}, nil},
		{"doctor.go", []string{"jb.Doctor("}, nil},
		{"actor.go", []string{"jb.ActorStatus("}, nil},
		{"db.go", []string{"jb.DBStatus(", "jb.Reputation("}, nil},
		{"dbmaint.go", []string{"jb.DBUsage(", "jb.DBPrune(", "jb.DBCompact("}, nil},
		{"dbrename.go", []string{"jb.DBRenameSource("}, nil},
		{"serve.go", []string{"jb.Serve("}, nil},
	}
	for _, c := range table {
		b, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, w := range c.calls {
			if !strings.Contains(src, w) {
				t.Errorf("%s does not call %s", c.file, w)
			}
		}
		for _, f := range c.forbidden {
			if strings.Contains(src, f) {
				t.Errorf("%s uses %s: that step belongs to the library", c.file, f)
			}
		}
	}
}
