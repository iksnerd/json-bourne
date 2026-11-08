//go:build unix

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var (
	pluginBinMu  sync.Mutex
	pluginBinDir string
)

// cleanupPluginBins removes the plugin binaries the tests built (called from TestMain).
func cleanupPluginBins() {
	if pluginBinDir != "" {
		os.RemoveAll(pluginBinDir)
	}
}

// pluginBinary builds ./examples/plugins/<name> into its own 0755 directory, once per test run.
func pluginBinary(t *testing.T, name string) string {
	t.Helper()
	pluginBinMu.Lock()
	defer pluginBinMu.Unlock()
	if pluginBinDir == "" {
		d, err := os.MkdirTemp("", "jb-cmd-plugins")
		if err != nil {
			t.Fatal(err)
		}
		pluginBinDir, _ = filepath.EvalSymlinks(d)
	}
	dir := filepath.Join(pluginBinDir, name)
	bin := filepath.Join(dir, name)
	if _, err := os.Stat(bin); err == nil {
		return bin
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(dir, 0o755)
	cmd := exec.Command("go", "build", "-o", bin, "./examples/plugins/"+name)
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build plugin %s: %v\n%s", name, err, out)
	}
	return bin
}

// allowPlugin writes an allowlist naming the built plugin and points JB_PLUGINS_FILE
// at it for this test (and for any jb subprocess it starts).
func allowPlugin(t *testing.T, name, bin string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plugins.yaml")
	y := fmt.Sprintf("plugins:\n  - name: %s\n    path: %s\n", name, bin)
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JB_PLUGINS_FILE", p)
}

const jsondocMapper = `    mapper: plugin:example.jsondoc
    mapper_config:
      fields:
        client_ip: {from: client_ip, type: ip, required: true}
        status: {from: status, type: int, required: true}
        path: {from: path}
`

// usePlugin switches the example case's source to the jsondoc plugin mapper.
func usePlugin(t *testing.T, dir, mapper string) {
	t.Helper()
	editFile(t, filepath.Join(dir, "config", "hunt.yaml"), "    index: logs-auth-*\n", "    index: logs-auth-*\n"+mapper)
}

// hourCase is readyCase with the one-hour window the fake Kibana's data is shaped for.
func hourCase(t *testing.T) string {
	t.Helper()
	dir, _ := readyCase(t)
	editFile(t, filepath.Join(dir, "case.yaml"), "default: 24h", "default: 1h")
	return dir
}

// noPluginProcess waits briefly for every process started from bin to be gone.
func noPluginProcess(t *testing.T, bin string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		out, _ := exec.Command("pgrep", "-f", bin).Output()
		if strings.TrimSpace(string(out)) == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("plugin process still running after jb finished: %s", out)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func tagsOf(h huntJSON) string {
	var tags []string
	for _, f := range h.Findings {
		tags = append(tags, f.Tag)
	}
	sort.Strings(tags)
	return strings.Join(tags, ",")
}

// The plugin path must behave exactly as the built-in path: same findings, complete.
func TestHuntThroughAPluginMatchesTheDefaultMapper(t *testing.T) {
	bin := pluginBinary(t, "jsondoc")
	allowPlugin(t, "example.jsondoc", bin)
	plain := hourCase(t)
	want, _, stderr, code := huntCase(t, "--case", plain)
	if code != 0 || !want.Complete || len(want.Findings) == 0 {
		t.Fatalf("baseline hunt: exit %d complete=%v findings=%d\n%s", code, want.Complete, len(want.Findings), stderr)
	}
	viaPlugin := hourCase(t)
	usePlugin(t, viaPlugin, jsondocMapper)
	got, stdout, stderr, code := huntCase(t, "--case", viaPlugin)
	if code != 0 || !got.Complete {
		t.Fatalf("plugin hunt: exit %d complete=%v\n%s\n%s", code, got.Complete, stdout, stderr)
	}
	if tagsOf(got) != tagsOf(want) {
		t.Errorf("findings through the plugin = %s, through the default mapper = %s", tagsOf(got), tagsOf(want))
	}
	noPluginProcess(t, bin) // the hunt has returned: its child must not outlive it
}

// A plugin that cannot do its job fails the source: INCOMPLETE, exit 1, never a clean empty result.
func TestHuntWithABrokenPluginIsIncompleteNeverClean(t *testing.T) {
	allowPlugin(t, "example.jsondoc", pluginBinary(t, "jsondoc"))
	dir := hourCase(t)
	usePlugin(t, dir, "    mapper: plugin:example.jsondoc\n    mapper_config: {fields: {a: {from: b, type: float}}}\n")
	got, stdout, stderr, code := huntCase(t, "--case", dir)
	if code != exitFailure || got.Complete {
		t.Fatalf("exit %d complete=%v, want exit 1 and incomplete\n%s\n%s", code, got.Complete, stdout, stderr)
	}
	if !strings.Contains(stdout+stderr, "plugin example.jsondoc") {
		t.Errorf("the output does not name the plugin:\n%s\n%s", stdout, stderr)
	}
}

func TestHuntWithAPluginTheOperatorDidNotAllowIsALoadError(t *testing.T) {
	t.Setenv("JB_PLUGINS_FILE", filepath.Join(t.TempDir(), "absent.yaml"))
	dir, _ := readyCase(t)
	usePlugin(t, dir, jsondocMapper)
	_, stdout, stderr, code := huntCase(t, "--case", dir)
	if code == 0 || !strings.Contains(stdout+stderr, "not allowlisted") {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
}

// An interrupt ends the plugin's child process with jb, between cycles and mid-cycle.
func TestWatchSignalLeavesNoPluginProcess(t *testing.T) {
	bin := pluginBinary(t, "jsondoc")
	allowPlugin(t, "example.jsondoc", bin)
	dir := signalCase(t, recentKibana(t, nil, nil).URL)
	usePlugin(t, dir, jsondocMapper)
	cmd, lines, stderr := startJB(t, "watch", "--case", dir, "--every", "1h")
	waitLine(t, lines, "CYCLE FINDINGS")
	if out, _ := exec.Command("pgrep", "-f", bin).Output(); strings.TrimSpace(string(out)) == "" {
		t.Fatal("the plugin was not running during the cycle; the test would prove nothing")
	}
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if code := exitCode(t, cmd); code != 0 {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}
	noPluginProcess(t, bin)
}

func TestDoctorShowsAllowlistedPlugins(t *testing.T) {
	bin := pluginBinary(t, "kvlines")
	p := filepath.Join(t.TempDir(), "plugins.yaml")
	y := fmt.Sprintf("plugins:\n  - name: example.kvlines\n    path: %s\n  - name: example.gone\n    path: %s/nope\n", bin, filepath.Dir(bin))
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JB_PLUGINS_FILE", p)
	t.Setenv("SENTINEL_SECRET_VALUE", "sentinel-9c1e")
	code, stdout, stderr := run(t, testDeps(huntEnv), "doctor")
	out := stdout + stderr
	if !strings.Contains(out, "example.kvlines") || !strings.Contains(out, "pin: none") || !strings.Contains(out, "example.gone") {
		t.Errorf("doctor does not show the plugins:\n%s", out)
	}
	if code == 0 {
		t.Errorf("a missing plugin file must fail doctor:\n%s", out)
	}
	if strings.Contains(out, "sentinel-9c1e") {
		t.Error("an environment value reached the doctor report")
	}
}
