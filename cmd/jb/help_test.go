package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// firstLine returns the first non-empty line of s, trimmed.
func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

// TestEveryCommandHelpIsItsOwn runs `<command> --help` and `<command> -h` for every
// command in the tree and requires the output to start with that command's own text,
// never the root's. A caller types --help first, so a command that answers with the
// root help hides itself.
func TestEveryCommandHelpIsItsOwn(t *testing.T) {
	root := newRootCmdWith(testDeps(nil))
	rootHelp := firstLine(root.Long)
	if rootHelp == "" {
		t.Fatal("the root command has no Long text to compare against")
	}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c != root && !c.Hidden {
			want := firstLine(c.Long)
			if want == "" {
				want = firstLine(c.Short)
			}
			if want == "" {
				t.Errorf("%s has neither Long nor Short text", c.CommandPath())
			}
			args := strings.Fields(strings.TrimPrefix(c.CommandPath(), root.Name()+" "))
			for _, flag := range []string{"--help", "-h"} {
				code, stdout, stderr := run(t, testDeps(nil), append(append([]string{}, args...), flag)...)
				if code != 0 {
					t.Errorf("%s %s: exit %d\n%s", c.CommandPath(), flag, code, stderr)
					continue
				}
				if !strings.HasPrefix(strings.TrimSpace(stdout), want) {
					t.Errorf("%s %s does not start with its own help.\nwant prefix: %q\ngot: %q", c.CommandPath(), flag, want, firstLine(stdout))
				}
				if want != rootHelp && strings.HasPrefix(strings.TrimSpace(stdout), rootHelp) {
					t.Errorf("%s %s printed the root help", c.CommandPath(), flag)
				}
			}
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
}
