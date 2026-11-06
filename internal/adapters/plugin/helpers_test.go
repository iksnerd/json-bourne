package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

var fakeBin string // path of the built fakeplugin

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "jb-plugin-fake")
	if err != nil {
		panic(err)
	}
	fakeBin = filepath.Join(dir, "fakeplugin")
	if out, err := exec.Command("go", "build", "-o", fakeBin, "./testdata/fakeplugin").CombinedOutput(); err != nil {
		os.Stderr.Write(out)
		os.RemoveAll(dir)
		os.Exit(2)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// install puts a copy of the fake plugin in its own directory, mode 0755 (the umask of
// the test machine must not decide), with the behaviour named by mode.
func install(t *testing.T, mode string) Entry {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "plug")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(fakeBin)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "fakeplugin")
	if err := os.WriteFile(p, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mode"), []byte(mode), 0o644); err != nil {
		t.Fatal(err)
	}
	// EvalSymlinks: macOS temp dirs sit under a /var -> /private/var link.
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return Entry{Name: "test.fake", Path: p}
}

func sum(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func newHost(t *testing.T, e Entry, l Limits, cfg map[string]any) *Host {
	t.Helper()
	if l.Deadline == 0 {
		l.Deadline = 5 * time.Second
	}
	h, err := NewHost(Options{Entry: e, Limits: l, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func docs(n int) []map[string]any {
	out := make([]map[string]any, n)
	for i := range out {
		out[i] = map[string]any{"x": i}
	}
	return out
}

func readFile(dir, name string) string {
	b, _ := os.ReadFile(filepath.Join(dir, name))
	return string(b)
}
