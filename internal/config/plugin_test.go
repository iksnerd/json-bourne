//go:build unix

package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/iksnerd/json-bourne/internal/adapters/plugin"
)

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

// regexlinesBinary builds plugins/regexlines once into a 0755 directory of its own.
func regexlinesBinary(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		d, err := os.MkdirTemp("", "jb-config-plugin")
		if err != nil {
			binErr = err
			return
		}
		d, _ = filepath.EvalSymlinks(d)
		_ = os.Chmod(d, 0o755)
		binPath = filepath.Join(d, "regexlines")
		cmd := exec.Command("go", "build", "-o", binPath, "./plugins/regexlines")
		cmd.Dir = filepath.Join("..", "..")
		if out, err := cmd.CombinedOutput(); err != nil {
			binErr = fmt.Errorf("%v\n%s", err, out)
		}
	})
	if binErr != nil {
		t.Fatal(binErr)
	}
	return binPath
}

// withAllowlist points the config layer at an allowlist naming the given plugins.
func withAllowlist(t *testing.T, entries map[string]string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("plugins:\n")
	for n, p := range entries {
		fmt.Fprintf(&b, "  - name: %s\n    path: %s\n", n, p)
	}
	f := filepath.Join(t.TempDir(), "plugins.yaml")
	if err := os.WriteFile(f, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	old := PluginAllowlist
	PluginAllowlist = func() (*plugin.Allowlist, error) { return plugin.LoadAllowlist(f) }
	t.Cleanup(func() { PluginAllowlist = old })
}

const nginxPluginMapper = `    mapper: plugin:example.regexlines
    mapper_config:
      pattern: '^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]+) (?P<path>[^?#\s]*)\S* [^"]+" (?P<status>\d{3}) (?:\d+|-) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
      fields:
        client_ip: {from: ip, type: ip, required: true}
        method: {from: method, required: true}
        path: {from: path, required: true}
        status: {from: status, type: int, required: true}
        user_agent: {from: ua, omit: ["-"]}
        referer: {from: referer, omit: ["-"]}
`

// The configured plugin and the built-in nginx_ingress mapper give the same findings
// from the same index through the real config path, detector and all.
func TestPluginMapperGivesTheSameFindingsAsTheBuiltIn(t *testing.T) {
	withAllowlist(t, map[string]string{"example.regexlines": regexlinesBinary(t)})
	want := nginxToAuthspike(t, "    mapper: nginx_ingress\n")
	got := nginxToAuthspike(t, nginxPluginMapper)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("through the plugin: %v\nthrough the built-in: %v", got, want)
	}
}

// A case is data the operator may have received from elsewhere. It names a plugin and
// nothing else: no path, no command, no allowlist entry, no environment.
func TestHostileCaseConfigsCannotReachAnythingButAnAllowlistedName(t *testing.T) {
	withAllowlist(t, map[string]string{"example.regexlines": regexlinesBinary(t)})
	with := func(lines string) string {
		return strings.Replace(valid, "    index: logs-auth-*\n", "    index: logs-auth-*\n"+lines, 1)
	}
	cases := map[string]struct{ yaml, want string }{
		"absolute path":             {with("    mapper: plugin:/tmp/evil\n"), "cannot give a path"},
		"relative path":             {with("    mapper: plugin:./evil\n"), "cannot give a path"},
		"traversal":                 {with("    mapper: plugin:../../bin/sh\n"), "cannot give a path"},
		"command line":              {with("    mapper: \"plugin:sh -c id\"\n"), "cannot give a path"},
		"undotted name":             {with("    mapper: plugin:evil\n"), "cannot give a path"},
		"upper case":                {with("    mapper: plugin:Example.Regexlines\n"), "cannot give a path"},
		"empty name":                {with("    mapper: \"plugin:\"\n"), "cannot give a path"},
		"unlisted plugin":           {with("    mapper: plugin:acme.unlisted\n"), "not allowlisted"},
		"path key":                  {with("    mapper: plugin:example.regexlines\n    path: /tmp/evil\n"), "path"},
		"command key":               {with("    mapper: plugin:example.regexlines\n    command: /bin/sh\n"), "command"},
		"allowlist in the case":     {"plugins:\n  - name: acme.evil\n    path: /tmp/evil\n" + with("    mapper: plugin:acme.evil\n"), "plugins"},
		"mapper_config sans plugin": {with("    mapper: nginx_ingress\n    mapper_config: {a: 1}\n"), "mapper_config is only valid"},
		"mapper_config no mapper":   {with("    mapper_config: {a: 1}\n"), "mapper_config is only valid"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(c.yaml))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one containing %q", err, c.want)
			}
		})
	}
	// The control: the allowlisted name, spelled right, loads.
	if _, err := Parse([]byte(with("    mapper: plugin:example.regexlines\n    mapper_config: {fields: {a: {from: b}}}\n"))); err != nil {
		t.Fatalf("the control case must load: %v", err)
	}
}

func TestPluginHostIsOnePerSourceAndClosedWithTheRuntime(t *testing.T) {
	withAllowlist(t, map[string]string{"example.regexlines": regexlinesBinary(t)})
	y := strings.Replace(valid, "    index: logs-auth-*\n", "    index: logs-auth-*\n"+nginxPluginMapper, 1)
	f, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rt.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	var nilRT *Runtime
	if err := nilRT.Close(); err != nil {
		t.Fatal(err)
	}
}

// A build that fails after a plugin source was built returns no runtime and an error;
// the host built first is closed inside Build (a host launches its child lazily, so no
// process exists yet either way).
func TestPartialBuildFailureReturnsNoRuntime(t *testing.T) {
	withAllowlist(t, map[string]string{"example.regexlines": regexlinesBinary(t)})
	y := strings.Replace(valid, "    index: logs-auth-*\n", "    index: logs-auth-*\n"+nginxPluginMapper, 1)
	y = strings.Replace(y, "detectors:", `  - type: kibana
    url: https://kibana.example.com
    api_key_env: JB_MISSING_KEY
    index: logs-other-*
detectors:`, 1)
	f, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err == nil || rt != nil {
		t.Fatalf("rt=%v err=%v: a partly built runtime must not be handed out", rt, err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error leaks a credential: %v", err)
	}
}

func TestPluginLeavesLineNamesThePlugin(t *testing.T) {
	withAllowlist(t, map[string]string{"example.regexlines": regexlinesBinary(t)})
	y := strings.Replace(valid, "    index: logs-auth-*\n", "    index: logs-auth-*\n"+nginxPluginMapper, 1)
	f, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, s := range f.Services() {
		if strings.Contains(s.Leaves, "local plugin example.regexlines") {
			found = true
		}
	}
	if !found {
		t.Errorf("doctor's service list does not say documents go to the plugin: %+v", f.Services())
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	if binPath != "" {
		os.RemoveAll(filepath.Dir(binPath))
	}
	os.Exit(code)
}

// The shipped example configs load under an allowlist that names their plugins, so the
// docs cannot drift from the format.
func TestShippedPluginExamplesLoad(t *testing.T) {
	withAllowlist(t, map[string]string{"example.regexlines": "/opt/x/regexlines", "example.kvlines": "/opt/x/kvlines"})
	for _, name := range []string{"hunt-plugin-nginx.example.yaml", "hunt-plugin-eventlog.example.yaml"} {
		if _, err := Load(filepath.Join("..", "..", "examples", name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "examples", "plugins.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.ParseAllowlist(b); err != nil {
		t.Errorf("plugins.example.yaml: %v", err)
	}
}
