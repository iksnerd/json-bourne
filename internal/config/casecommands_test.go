package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/core"
)

const commandsTestBody = "sources:\n  - type: kibana\n    url: https://kibana.example.com\n    api_key_env: JB_KIBANA_API_KEY\n    index: logs-*\ndetectors:\n  - type: authspike\n    key_field: client_ip\n    status_field: status\n"

// commandsFixture writes configs under the case with the given head (a `commands:`
// line, or empty for no key) and lists exactly those configs in c.Config, in order.
func commandsFixture(t *testing.T, c *casefile.Case, entries [][2]string) {
	t.Helper()
	c.Config = nil
	for _, e := range entries {
		rel, head := e[0], e[1]
		p := filepath.Join(c.Dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(head+commandsTestBody), 0o600); err != nil {
			t.Fatal(err)
		}
		c.Config = append(c.Config, rel)
	}
}

func TestChooseCaseConfigByDeclaredCommand(t *testing.T) {
	c, _ := chooseFixture(t)
	commandsFixture(t, c, [][2]string{
		{"config/hunt.yaml", "commands: [hunt, activity]\n"},
		{"config/fp.yaml", "commands: [watch]\n"},
		{"config/plain.yaml", ""},
	})
	for cmd, want := range map[string]string{"hunt": "hunt.yaml", "activity": "hunt.yaml", "watch": "fp.yaml"} {
		got, err := ChooseCaseConfig(c, "", cmd)
		if err != nil || got != filepath.Join(c.Dir, "config", want) {
			t.Errorf("%s: got %q, %v; want %s", cmd, got, err, want)
		}
	}
	// An explicit --config wins over any declaration.
	got, err := ChooseCaseConfig(c, "config/plain.yaml", "hunt")
	if err != nil || got != filepath.Join(c.Dir, "config", "plain.yaml") {
		t.Errorf("flag: got %q, %v", got, err)
	}
}

func TestChooseCaseConfigNoDeclarationListsEveryConfig(t *testing.T) {
	c, _ := chooseFixture(t)
	commandsFixture(t, c, [][2]string{
		{"config/hunt.yaml", "commands: [hunt]\n"},
		{"config/fp.yaml", "commands: [watch, serve]\n"},
		{"config/plain.yaml", ""},
	})
	_, err := ChooseCaseConfig(c, "", "activity")
	if !core.IsUsage(err) {
		t.Fatalf("want a usage error, got %v", err)
	}
	for _, want := range []string{"activity", "config/hunt.yaml", "hunt", "config/fp.yaml", "watch, serve", "config/plain.yaml", "no commands"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

func TestChooseCaseConfigTwoDeclareTheSameCommand(t *testing.T) {
	c, _ := chooseFixture(t)
	commandsFixture(t, c, [][2]string{
		{"config/a.yaml", "commands: [hunt]\n"},
		{"config/b.yaml", "commands: [hunt, watch]\n"},
	})
	_, err := ChooseCaseConfig(c, "", "hunt")
	if !core.IsUsage(err) || !strings.Contains(err.Error(), "config/a.yaml") || !strings.Contains(err.Error(), "config/b.yaml") || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("want a usage error naming both configs, got %v", err)
	}
	if got, err := ChooseCaseConfig(c, "", "watch"); err != nil || got != filepath.Join(c.Dir, "config", "b.yaml") {
		t.Errorf("watch: %q, %v", got, err)
	}
}

func TestChooseCaseConfigSingleConfigNeedsNoDeclaration(t *testing.T) {
	c, _ := chooseFixture(t)
	commandsFixture(t, c, [][2]string{{"config/only.yaml", "commands: [watch]\n"}})
	got, err := ChooseCaseConfig(c, "", "hunt")
	if err != nil || got != filepath.Join(c.Dir, "config", "only.yaml") {
		t.Errorf("got %q, %v", got, err)
	}
}

func TestChooseCaseConfigUnreadableListedConfig(t *testing.T) {
	c, _ := chooseFixture(t)
	commandsFixture(t, c, [][2]string{{"config/a.yaml", ""}, {"config/b.yaml", "commands: [nope]\n"}})
	_, err := ChooseCaseConfig(c, "", "hunt")
	if err == nil || !strings.Contains(err.Error(), "config/b.yaml") || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("want an error naming the file and the bad command, got %v", err)
	}
	if core.IsUsage(err) {
		t.Errorf("a broken config is not a usage error: %v", err)
	}
}

func TestChooseCaseConfigRefusesACommandOutsideTheSet(t *testing.T) {
	c, _ := chooseFixture(t)
	if _, err := ChooseCaseConfig(c, "", "frobnicate"); err == nil {
		t.Fatal("an empty flag with a command outside the closed set must fail")
	}
	// With a flag the command is not consulted (jb doctor passes none).
	if _, err := ChooseCaseConfig(c, "config/hunt.yaml", ""); err != nil {
		t.Errorf("flag with no command: %v", err)
	}
}

func TestLoadCommandsReadsOnlyThatKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte("commands: [hunt, estate]\nsources: []\nsomething_else: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCommands(p)
	if err != nil || len(got) != 2 || got[0] != "hunt" || got[1] != "estate" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestParseCommandsKey(t *testing.T) {
	f, err := Parse([]byte("commands: [hunt, watch]\n" + commandsTestBody))
	if err != nil || len(f.Commands) != 2 {
		t.Fatalf("valid: %v %v", f, err)
	}
	for name, y := range map[string]string{
		"unknown":   "commands: [hunter]\n",
		"duplicate": "commands: [hunt, hunt]\n",
		"empty":     "commands: [\"\"]\n",
		"scalar":    "commands: hunt\n",
	} {
		if _, err := Parse([]byte(y + commandsTestBody)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := Parse([]byte("commands: [hunter]\n" + commandsTestBody)); err == nil || !strings.Contains(err.Error(), "activity, actor") {
		t.Errorf("the error should list the closed set, got %v", err)
	}
}
