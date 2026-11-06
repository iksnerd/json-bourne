package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var updateFlagSets = flag.Bool("update-flagsets", false, "rewrite testdata/flagsets.golden")

// flagSets lists, for every command of the tree, each flag with its type, default,
// shorthand and usage text. It pins the command line surface: a flag that is renamed,
// retyped, re-defaulted or re-worded shows up as a diff.
func flagSets(root *cobra.Command) string {
	var b strings.Builder
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		b.WriteString("## " + c.CommandPath() + "\n")
		var lines []string
		c.Flags().VisitAll(func(f *pflag.Flag) {
			lines = append(lines, "--"+f.Name+"\t-"+f.Shorthand+"\t"+f.Value.Type()+"\t"+f.DefValue+"\t"+f.Usage)
		})
		sort.Strings(lines)
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
		subs := append([]*cobra.Command{}, c.Commands()...)
		sort.Slice(subs, func(i, j int) bool { return subs[i].Name() < subs[j].Name() })
		for _, s := range subs {
			walk(s)
		}
	}
	walk(root)
	return b.String()
}

// TestFlagSetsAreUnchanged compares every command's flags with the set recorded before
// the commands were built from operations (RFC 0010). A deliberate change is made by
// running the test with -update-flagsets and reading the diff.
func TestFlagSetsAreUnchanged(t *testing.T) {
	got := flagSets(newRootCmdWith(testDeps(nil)))
	const path = "testdata/flagsets.golden"
	if *updateFlagSets {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("flag sets differ from %s (rerun with -update-flagsets if the change is deliberate)\n%s", path, firstDiff(string(want), got))
	}
}

func firstDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var a, b string
		if i < len(w) {
			a = w[i]
		}
		if i < len(g) {
			b = g[i]
		}
		if a != b {
			return fmt.Sprintf("line %d\n  want: %s\n  got:  %s", i+1, a, b)
		}
	}
	return ""
}
