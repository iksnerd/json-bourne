package main

import (
	"testing"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
	"github.com/iksnerd/json-bourne/internal/app"
)

// The Go functions and the CLI commands are two surfaces of one operation. They keep
// separate copies of the defaults, so this test is what stops the copies drifting: a
// library caller who passes nothing must get what `jb <command>` with no flag gets.
func TestLibraryDefaultsAreTheCLIDefaults(t *testing.T) {
	def := func(cmd *cobra.Command, flag string) string {
		t.Helper()
		f := cmd.Flags().Lookup(flag)
		if f == nil {
			t.Fatalf("%s has no --%s flag", cmd.Name(), flag)
		}
		return f.DefValue
	}
	hunt, watch, activity := newHuntCmd(), newWatchCmdWith(defaultDeps()), newActivityCmdWith(defaultDeps())
	for _, c := range []struct {
		what, got, want string
	}{
		{"hunt --window / jb.DefaultWindow", def(hunt, "window"), jb.DefaultWindow.String()},
		{"watch --window / jb.DefaultWindow", def(watch, "window"), jb.DefaultWindow.String()},
		{"watch --every / jb.DefaultWatchEvery", def(watch, "every"), jb.DefaultWatchEvery.String()},
		{"watch --ttl / app.DefaultWatchTTL", def(watch, "ttl"), app.DefaultWatchTTL.String()},
		{"watch --keep / app.DefaultWatchKeep", def(watch, "keep"), app.DefaultWatchKeep.String()},
		{"watch --repeat / app.DefaultHealthRepeat", def(watch, "repeat"), app.DefaultHealthRepeat.String()},
		{"activity --window / jb.DefaultActivityWindow", def(activity, "window"), jb.DefaultActivityWindow.String()},
	} {
		if c.got != c.want {
			t.Errorf("%s: the CLI default is %q and the library's is %q", c.what, c.got, c.want)
		}
	}
}
