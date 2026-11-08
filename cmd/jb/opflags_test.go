package main

import (
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/iksnerd/json-bourne/internal/ops"
	"github.com/iksnerd/json-bourne/jb"
)

// ---- the builder ----

func TestBuilderRegistersOneFlagPerPropertyFromTheOperation(t *testing.T) {
	cmd := &cobra.Command{Use: "x"}
	o := addOperationFlags(cmd, "db_prune")
	op := o.op
	for name, p := range op.InputSchema.Properties {
		f := cmd.Flags().Lookup(flagName(name))
		if f == nil {
			t.Errorf("no flag for %s", name)
			continue
		}
		if f.Usage != p.Description {
			t.Errorf("--%s usage = %q, want the operation's %q", f.Name, f.Usage, p.Description)
		}
		wantType := map[string]string{"string": "string", "integer": "int", "boolean": "bool", "array": "stringArray"}[p.Type]
		if f.Value.Type() != wantType {
			t.Errorf("--%s type = %s, want %s", f.Name, f.Value.Type(), wantType)
		}
	}
	// db_prune's apply is the cobra boolean form: --apply, --apply=false.
	if err := cmd.Flags().Parse([]string{"--apply", "--keep-latest", "0", "--run", "a,b", "--run", "c", "--drop-findings=false"}); err != nil {
		t.Fatal(err)
	}
	if !o.Bool("apply") || o.Bool("drop_findings") || o.Int("keep_latest") != 0 || !o.Changed("keep_latest") || o.Changed("kind") {
		t.Errorf("values: apply %v keep %d", o.Bool("apply"), o.Int("keep_latest"))
	}
	if got := o.Strings("run"); !slices.Equal(got, []string{"a,b", "c"}) {
		t.Errorf("an array flag repeats and keeps a comma in a value: %v", got)
	}
	if f := cmd.Flags().Lookup("keep-latest"); f.DefValue != "1" {
		t.Errorf("keep-latest default = %s, want the operation's 1", f.DefValue)
	}
}

func TestBuilderLastPositionalArrayTakesTheRemainingArguments(t *testing.T) {
	cmd := &cobra.Command{Use: "intel"}
	o := addOperationFlags(cmd, "intel")
	if cmd.Flags().Lookup("ips") != nil {
		t.Fatal("a positional property must not be a flag")
	}
	if err := cmd.Flags().Parse([]string{"--case", "c", "192.0.2.1", "192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
	args, err := o.Arguments(cmd.Flags().Args())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(args["ips"].([]string), []string{"192.0.2.1", "192.0.2.2"}) || args["case"] != "c" {
		t.Fatalf("arguments = %v", args)
	}
	if _, ok := args["config"]; ok {
		t.Fatal("an unset flag must not be sent: the handler applies the default")
	}
	if ps := ops.Check(o.op.InputSchema, args); len(ps) != 0 {
		t.Fatalf("the arguments of the command fail the one check: %v", ps)
	}
	if err := o.PositionalArgs()(cmd, nil); err != nil {
		t.Errorf("an array positional takes none: %v", err)
	}
}

func TestBuilderScalarPositionalsAreCountedAsUsageErrors(t *testing.T) {
	cmd := &cobra.Command{Use: "rename-source"}
	o := addOperationFlags(cmd, "db_rename_source")
	check := o.PositionalArgs()
	for _, args := range [][]string{nil, {"old"}, {"a", "b", "c"}} {
		err := check(cmd, args)
		if !jb.IsUsage(err) {
			t.Errorf("%v: err = %v, want a usage error", args, err)
		}
	}
	got, err := o.Arguments([]string{"old", "new"})
	if err != nil || got["old"] != "old" || got["new"] != "new" {
		t.Fatalf("%v, %v", got, err)
	}
}

// ---- command equals operation ----

// notOperations are the commands that are not an operation, each with the reason.
var notOperations = map[string]string{
	"jb watch":        "runs until stopped",
	"jb serve":        "runs until stopped",
	"jb version":      "prints one line of build information",
	"jb operations":   "prints the registry itself",
	"jb mcp":          "serves the registry over the Model Context Protocol; it is not an operation of it",
	"jb estate facts": "group: prints help",
	"jb actor":        "group: prints help",
	"jb case":         "group: prints help",
	"jb db":           "group: prints help",
}

// handWritten are the flags of a command that the operation spells differently: the flag
// on the left is the property on the right (RFC 0009's --no-store is the property store,
// read positively, because a property may not start with no_).
var flagToProperty = map[string]string{"no-store": "store"}

func commandWords(path string) []string { return strings.Fields(strings.TrimPrefix(path, "jb ")) }

// TestEveryCommandIsExactlyOneOperation walks the cobra tree: every runnable command
// that is not named in notOperations has exactly one operation, and every operation has
// exactly one command.
func TestEveryCommandIsExactlyOneOperation(t *testing.T) {
	root := newRootCmdWith(testDeps(nil))
	byCmd := map[string][]string{}
	for _, op := range jb.Operations() {
		c := "jb " + strings.Join(op.CLI.Command, " ")
		byCmd[c] = append(byCmd[c], op.Name)
	}
	seen := map[string]bool{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		path := c.CommandPath()
		seen[path] = true
		if c != root && c.Runnable() {
			if _, exempt := notOperations[path]; !exempt {
				if len(byCmd[path]) != 1 {
					t.Errorf("%s is a command with %d operations %v, want exactly 1 (or list it in notOperations with the reason)", path, len(byCmd[path]), byCmd[path])
				}
			} else if len(byCmd[path]) != 0 {
				t.Errorf("%s is listed as not an operation but %v claims it", path, byCmd[path])
			}
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
	for path := range notOperations {
		if !seen[path] {
			t.Errorf("notOperations names %q, which is not a command", path)
		}
	}
	for path, names := range byCmd {
		if !seen[path] {
			t.Errorf("operation %v names the command %q, which does not exist", names, path)
		}
	}
}

func flagKind(f *pflag.Flag) string {
	switch f.Value.Type() {
	case "string", "duration":
		return "string"
	case "int":
		return "integer"
	case "bool":
		return "boolean"
	case "stringArray", "stringSlice":
		return "array"
	}
	return f.Value.Type()
}

// TestEveryCommandHasTheFlagsOfItsOperation compares, for every command, its flags
// with the properties of its operation: the same names, the same kinds and the same
// defaults. A property named in cli.positional is an argument and not a flag; --output
// and --help belong to the command line alone. A duration flag is a string property
// (RFC 0010: a duration is a string the handler reads), so only its name and kind are
// compared.
func TestEveryCommandHasTheFlagsOfItsOperation(t *testing.T) {
	root := newRootCmdWith(testDeps(nil))
	for _, op := range jb.Operations() {
		c := findCmd(root, "jb "+strings.Join(op.CLI.Command, " "))
		if c == nil {
			continue // reported by TestEveryCommandIsExactlyOneOperation
		}
		props := map[string]ops.Property{}
		for n, p := range op.InputSchema.Properties {
			if !slices.Contains(op.CLI.Positional, n) {
				props[n] = p
			}
		}
		seen := map[string]bool{}
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if f.Name == "output" || f.Name == "help" {
				return
			}
			name := strings.ReplaceAll(f.Name, "-", "_")
			if m, ok := flagToProperty[f.Name]; ok {
				name = m
			}
			p, ok := props[name]
			if !ok {
				t.Errorf("%s: --%s is not a property of %s", c.CommandPath(), f.Name, op.Name)
				return
			}
			seen[name] = true
			if flagKind(f) != p.Type {
				t.Errorf("%s: --%s is a %s flag, %s.%s is %s", c.CommandPath(), f.Name, flagKind(f), op.Name, name, p.Type)
			}
			if f.Value.Type() == "duration" || flagToProperty[f.Name] != "" {
				return
			}
			want := map[string]string{"string": "", "integer": "0", "boolean": "false", "array": "[]"}[p.Type]
			if p.Default != nil {
				want = defaultText(p)
			}
			if f.DefValue != want {
				t.Errorf("%s: --%s defaults to %q, %s.%s to %q", c.CommandPath(), f.Name, f.DefValue, op.Name, name, want)
			}
		})
		// --no-store is the property store read positively: the property defaults to true.
		if f := c.Flags().Lookup("no-store"); f != nil {
			if p := props["store"]; p.Default != true || f.DefValue != "false" {
				t.Errorf("%s: --no-store defaults to %s and store to %v", c.CommandPath(), f.DefValue, p.Default)
			}
		}
		var missing []string
		for n := range props {
			if !seen[n] {
				missing = append(missing, n)
			}
		}
		sort.Strings(missing)
		for _, n := range missing {
			t.Errorf("%s: no flag for property %s.%s", c.CommandPath(), op.Name, n)
		}
	}
}

func defaultText(p ops.Property) string {
	switch d := p.Default.(type) {
	case string:
		return d
	case bool:
		if d {
			return "true"
		}
		return "false"
	case int64:
		return strconv.FormatInt(d, 10)
	}
	return "?"
}

// builtFrom are the commands registered by addOperationFlags: their flags are the
// operation's by construction, and their help text is the operation's description.
var builtFrom = map[string]string{
	"jb actor status":     "actor_status",
	"jb case check":       "case_check",
	"jb case show":        "case_show",
	"jb db compact":       "db_compact",
	"jb db prune":         "db_prune",
	"jb db rename-source": "db_rename_source",
	"jb db reputation":    "db_reputation",
	"jb db status":        "db_status",
	"jb db usage":         "db_usage",
	"jb estate promote":   "estate_promote",
	"jb doctor":           "doctor",
	"jb intel":            "intel",
	"jb watch status":     "watch_status",
}

func TestBuiltCommandsTakeTheirFlagUsageFromTheOperation(t *testing.T) {
	root := newRootCmdWith(testDeps(nil))
	for path, name := range builtFrom {
		c := findCmd(root, path)
		if c == nil {
			t.Errorf("no command %s", path)
			continue
		}
		op := mustOperation(name)
		for n, p := range op.InputSchema.Properties {
			if slices.Contains(op.CLI.Positional, n) {
				continue
			}
			f := c.Flags().Lookup(flagName(n))
			if f == nil || f.Usage != p.Description {
				t.Errorf("%s --%s is not built from %s.%s", path, flagName(n), name, n)
			}
		}
	}
}
