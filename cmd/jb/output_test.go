package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// outputExempt names the commands that print a result but take no --output, each with
// the reason. A command not listed here and runnable must have the flag. The test
// below fails when a name here no longer exists, so the list cannot go stale.
var outputExempt = map[string]string{
	"jb serve":   "starts a server and prints its address, not a result",
	"jb version": "prints one line of build information",
	"jb mcp":     "speaks JSON-RPC on standard output; its results are tool results, not a document",
}

// Commands cobra adds on its own, after the tree is built. They are not in the tree
// the test walks, so they are named here only to say they were considered.
var _ = []string{"jb help", "jb completion"}

func TestEveryResultCommandTakesOutput(t *testing.T) {
	seen := map[string]bool{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		seen[c.CommandPath()] = true
		// A group command only prints help; its subcommands are checked below.
		if c.Runnable() && len(c.Commands()) == 0 {
			if _, exempt := outputExempt[c.CommandPath()]; !exempt && c.Flags().Lookup("output") == nil {
				t.Errorf("%s prints a result but has no --output flag (add one, or list it in outputExempt with the reason)", c.CommandPath())
			}
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(newRootCmd())
	for name := range outputExempt {
		if !seen[name] {
			t.Errorf("outputExempt names %q, which is not a command", name)
		}
	}
	for name := range outputExempt {
		if c := findCmd(newRootCmd(), name); c != nil && c.Flags().Lookup("output") != nil {
			t.Errorf("%s has --output but is listed as exempt; remove it from outputExempt", name)
		}
	}
}

func findCmd(root *cobra.Command, path string) *cobra.Command {
	var found *cobra.Command
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.CommandPath() == path {
			found = c
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
	return found
}

// Every command that takes --output refuses a value other than table or json as a
// usage error, before it does any work.
func TestOutputFlagRejectsUnknownFormatEverywhere(t *testing.T) {
	var paths [][]string
	var walk func(c *cobra.Command, prefix []string)
	walk = func(c *cobra.Command, prefix []string) {
		if c.Parent() != nil {
			prefix = append(slices.Clone(prefix), c.Name())
		}
		if c.Runnable() && len(c.Commands()) == 0 && c.Flags().Lookup("output") != nil {
			paths = append(paths, prefix)
		}
		for _, s := range c.Commands() {
			walk(s, prefix)
		}
	}
	walk(newRootCmd(), nil)
	for _, p := range paths {
		t.Run(strings.Join(p, " "), func(t *testing.T) {
			// Fill the required flags with values that would pass if --output were fine;
			// a usage error from them also exits 2, so check the message too.
			args := append(slices.Clone(p), "--output", "yaml", "--case", t.TempDir(), "--config", "none.yaml")
			code, _, stderr := run(t, testDeps(nil), args...)
			if code != exitUsage {
				t.Fatalf("exit %d: %s", code, stderr)
			}
		})
	}
	if len(paths) < 10 {
		t.Errorf("walked %d commands with --output, expected the whole tree", len(paths))
	}
}

func TestWatchOnceJSONIsTheCycleReport(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	code, stdout, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once", "--output", "json")
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	var got struct {
		Run     string    `json:"run"`
		Window  [2]string `json:"window"`
		Status  string    `json:"status"`
		Healthy bool      `json:"healthy"`
		Failed  []string  `json:"failed"`
		New     int       `json:"new"`
		Supp    int       `json:"suppressed"`
		Alerts  []struct {
			Kind string `json:"kind"`
			Tag  string `json:"tag"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, stdout)
	}
	if got.Status != "findings" || !got.Healthy || got.New == 0 || got.Failed == nil || len(got.Failed) != 0 ||
		!strings.HasPrefix(got.Run, "watch-") || got.Window[0] == "" || len(got.Alerts) == 0 {
		t.Errorf("report = %+v\n%s", got, stdout)
	}
	// Alert lines still reach the operator, on stderr, so stdout stays one document.
	if !strings.Contains(stderr, "CYCLE FINDINGS") {
		t.Errorf("alert lines missing from stderr:\n%s", stderr)
	}
	if strings.Contains(stdout, "CYCLE ") {
		t.Errorf("alert text leaked into the JSON on stdout:\n%s", stdout)
	}
	if !strings.Contains(readEvidence(t, dir, "watch.log"), "CYCLE FINDINGS") {
		t.Error("the log must still receive the alerts")
	}

	// An incomplete cycle still prints its report, then exits 1.
	down, _ := watchCase(t, http.StatusInternalServerError)
	code, stdout, _ = run(t, testDeps(huntEnv), "watch", "--case", down, "--once", "--output", "json")
	if code != exitFailure {
		t.Fatalf("incomplete cycle exit %d", code)
	}
	var bad struct {
		Status  string   `json:"status"`
		Healthy bool     `json:"healthy"`
		Failed  []string `json:"failed"`
	}
	if err := json.Unmarshal([]byte(stdout), &bad); err != nil || bad.Healthy || bad.Status == "quiet" || len(bad.Failed) == 0 {
		t.Errorf("incomplete report: %v %+v\n%s", err, bad, stdout)
	}
}

func TestWatchJSONNeedsOnce(t *testing.T) {
	dir, served := watchCase(t, http.StatusOK)
	for name, args := range map[string][]string{
		"json without once": {"watch", "--case", dir, "--output", "json"},
		"unknown format":    {"watch", "--case", dir, "--once", "--output", "yaml"},
	} {
		code, _, stderr := run(t, testDeps(huntEnv), args...)
		if code != exitUsage || !strings.Contains(stderr, "--output") {
			t.Errorf("%s: exit %d: %s", name, code, stderr)
		}
	}
	if served() != 0 {
		t.Errorf("a refused watch reached the source (%d requests)", served())
	}
}

func TestDBStatusJSON(t *testing.T) {
	cfg, store := seedTwoLabels(t, 3)
	code, out, errs := run(t, testDeps(nil), "db", "status", "--config", cfg, "--output", "json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var got struct {
		Path        string  `json:"path"`
		Schema      int     `json:"schema_version"`
		BuildSchema int     `json:"build_schema_version"`
		Runs        int     `json:"runs"`
		Events      int     `json:"events"`
		Findings    int     `json:"findings"`
		Reputation  int     `json:"reputation"`
		FirstSeen   *string `json:"first_seen"`
		LastSeen    *string `json:"last_seen"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got.Path != store || got.Events != 6 || got.Schema == 0 || got.Schema != got.BuildSchema || got.FirstSeen == nil || got.LastSeen == nil {
		t.Errorf("status = %+v", got)
	}
}

func TestDBRenameSourceJSON(t *testing.T) {
	cfg, store := seedTwoLabels(t, 4)
	code, out, errs := run(t, testDeps(nil), "db", "rename-source", "--config", cfg, "--merge", "--output", "json", defaultLabel, "ingress")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var got struct {
		Store      string `json:"store"`
		Old        string `json:"old"`
		New        string `json:"new"`
		Applied    bool   `json:"applied"`
		Events     int    `json:"events"`
		Overlap    int    `json:"overlap"`
		Relabelled int    `json:"relabelled"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got.Store != store || got.Old != defaultLabel || got.New != "ingress" || got.Applied || got.Events != 4 || got.Overlap != 4 {
		t.Errorf("dry run report = %+v", got)
	}
	if c := countsBySource(t, store); c[defaultLabel] != 4 {
		t.Errorf("a dry run changed the store: %v", c)
	}
	_, out, _ = run(t, testDeps(nil), "db", "rename-source", "--config", cfg, "--merge", "--apply", "--output", "json", defaultLabel, "ingress")
	if err := json.Unmarshal([]byte(out), &got); err != nil || !got.Applied {
		t.Errorf("applied report: %v %+v\n%s", err, got, out)
	}
}

func TestDBCompactJSON(t *testing.T) {
	cfg, store := seedMaint(t, standardHunts)
	code, out, errs := run(t, testDeps(nil), "db", "compact", "--config", cfg, "--to", store+".new", "--output", "json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var got struct {
		Applied     bool   `json:"applied"`
		Target      string `json:"target"`
		SourceBytes int64  `json:"source_file_bytes"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got.Applied || got.Target != store+".new" || got.SourceBytes == 0 {
		t.Errorf("compact report = %+v", got)
	}
	if strings.Contains(out, "reminder") || strings.Contains(out, "swap") {
		t.Errorf("advice text in the JSON:\n%s", out)
	}
}

func TestEstatePromoteJSON(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "dns", "bgp", "crt.sh")
	w := newWorld()
	w.baseline(t, dir)
	w.tick()
	if code, out, errs := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml"); code != 0 {
		t.Fatalf("refresh: exit %d\n%s\n%s", code, out, errs)
	}
	snaps := snapshotFiles(t, dir)
	id := strings.TrimSuffix(snaps[len(snaps)-1], ".yaml")
	code, out, errs := run(t, w.deps(), "estate", "promote", "--case", dir, "--file", "base.yaml", "--output", "json", id)
	if code != 0 {
		t.Fatalf("promote: exit %d\n%s\n%s", code, out, errs)
	}
	var got struct {
		Promoted string `json:"promoted"`
		Baseline string `json:"baseline"`
		Archived string `json:"archived"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got.Promoted != id || got.Baseline != filepath.ToSlash(filepath.Join("estate", "base.yaml")) || !strings.Contains(got.Archived, "archive") {
		t.Errorf("promote report = %+v", got)
	}
}
