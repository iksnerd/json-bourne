package main

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The exit codes are part of the supported CLI surface (RFC 0018): 0 success, 1 runtime
// failure or incomplete result, 2 usage error. The numbers are written out here, not
// taken from the constants, so changing a constant fails the test.
func TestExitCodeValuesAreFixed(t *testing.T) {
	if exitOK != 0 || exitFailure != 1 || exitUsage != 2 {
		t.Fatalf("exit codes are %d/%d/%d, want 0/1/2", exitOK, exitFailure, exitUsage)
	}
}

// Every command of the tree, group or leaf, refuses an unknown flag as a usage error.
func TestEveryCommandExitsTwoOnAnUnknownFlag(t *testing.T) {
	var paths [][]string
	var walk func(c *cobra.Command, prefix []string)
	walk = func(c *cobra.Command, prefix []string) {
		if c.Parent() != nil {
			prefix = append(slices.Clone(prefix), c.Name())
		}
		if c.Name() != "help" && c.Name() != "completion" {
			paths = append(paths, prefix)
		}
		for _, s := range c.Commands() {
			walk(s, prefix)
		}
	}
	walk(newRootCmd(), nil)
	for _, p := range paths {
		t.Run(strings.Join(p, " "), func(t *testing.T) {
			code, stdout, stderr := run(t, testDeps(nil), append(slices.Clone(p), "--no-such-flag")...)
			if code != 2 {
				t.Errorf("exit %d, want 2\nstderr: %s", code, stderr)
			}
			if stdout != "" {
				t.Errorf("a usage error wrote to stdout: %q", stdout)
			}
		})
	}
	if len(paths) < 30 {
		t.Errorf("walked %d commands, expected the whole tree", len(paths))
	}
}

// One real invocation per class of outcome, through the in-process runner.
func TestExitCodesPerOutcome(t *testing.T) {
	okDir, _ := watchCase(t, http.StatusOK)
	downDir, _ := watchCase(t, http.StatusInternalServerError)
	srv := fakeKibana(t, http.StatusOK)
	cfg := writeConfig(t, srv.URL)
	rows := []struct {
		name string
		args []string
		want int
	}{
		{"version succeeds", []string{"version"}, 0},
		{"operations succeeds", []string{"operations"}, 0},
		{"case check succeeds", []string{"case", "check", "--case", "../../examples/case"}, 0},
		{"hunt succeeds", []string{"hunt", "--case", okDir}, 0},
		{"hunt with the source down is incomplete", []string{"hunt", "--case", downDir}, 1},
		{"activity with the source down is incomplete", []string{"activity", "--case", downDir}, 1},
		{"watch once with the source down fails", []string{"watch", "--case", downDir, "--once"}, 1},
		{"db status without a database fails", []string{"db", "status", "--config", cfg}, 1},
		{"case check of a missing case fails", []string{"case", "check", "--case", t.TempDir() + "/nope"}, 1},
		{"hunt without a source", []string{"hunt"}, 2},
		{"hunt unknown output", []string{"hunt", "--case", okDir, "--output", "xml"}, 2},
		{"hunt negative window", []string{"hunt", "--case", okDir, "--window", "-5m"}, 2},
		{"unknown command", []string{"frobnicate"}, 2},
		{"unknown subcommand", []string{"db", "frobnicate"}, 2},
		{"unknown root flag", []string{"--nope"}, 2},
		{"version with an argument", []string{"version", "x"}, 2},
		{"mcp allows only a known operation", []string{"mcp", "--allow", "no_such_operation"}, 2},
		{"mcp takes no argument", []string{"mcp", "extra"}, 2},
		{"serve needs a source", []string{"serve"}, 2},
		{"serve refuses a non-loopback address", []string{"serve", "--case", okDir, "--addr", "0.0.0.0:8090"}, 2},
		{"serve refuses a malformed address", []string{"serve", "--case", okDir, "--addr", "nonsense"}, 2},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			code, stdout, stderr := run(t, testDeps(huntEnv), r.args...)
			if code != r.want {
				t.Errorf("exit %d, want %d\nstdout: %s\nstderr: %s", code, r.want, stdout, stderr)
			}
		})
	}
}
