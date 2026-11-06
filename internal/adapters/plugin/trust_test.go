package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func wantErr(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), sub) {
		t.Fatalf("err = %v, want one containing %q", err, sub)
	}
}

func TestVerifyAcceptsAGoodPlugin(t *testing.T) {
	e := install(t, "ok")
	if _, err := Verify(e); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRefusesAWorldWritableFile(t *testing.T) {
	e := install(t, "ok")
	if err := os.Chmod(e.Path, 0o757); err != nil {
		t.Fatal(err)
	}
	_, err := Verify(e)
	wantErr(t, err, "writable by group or others")
}

func TestVerifyRefusesAGroupWritableFile(t *testing.T) {
	e := install(t, "ok")
	if err := os.Chmod(e.Path, 0o775); err != nil {
		t.Fatal(err)
	}
	_, err := Verify(e)
	wantErr(t, err, "writable by group or others")
}

func TestVerifyRefusesAWritableDirectory(t *testing.T) {
	e := install(t, "ok")
	if err := os.Chmod(filepath.Dir(e.Path), 0o777); err != nil {
		t.Fatal(err)
	}
	_, err := Verify(e)
	wantErr(t, err, "directory")
}

func TestVerifyRefusesASymlinkOutOfTheDirectory(t *testing.T) {
	e := install(t, "ok")
	other := install(t, "ok") // a different, perfectly good plugin elsewhere
	link := filepath.Join(filepath.Dir(e.Path), "linked")
	if err := os.Symlink(other.Path, link); err != nil {
		t.Fatal(err)
	}
	_, err := Verify(Entry{Name: "test.link", Path: link})
	wantErr(t, err, "outside its own directory")
}

func TestVerifyAllowsASymlinkInsideTheDirectory(t *testing.T) {
	e := install(t, "ok")
	link := filepath.Join(filepath.Dir(e.Path), "alias")
	if err := os.Symlink(filepath.Base(e.Path), link); err != nil {
		t.Fatal(err)
	}
	v, err := Verify(Entry{Name: "test.link", Path: link})
	if err != nil {
		t.Fatal(err)
	}
	if v.Path != e.Path {
		t.Errorf("launch path = %s, want the resolved %s", v.Path, e.Path)
	}
}

func TestVerifyRefusesAPinMismatch(t *testing.T) {
	e := install(t, "ok")
	e.SHA256 = strings.Repeat("0", 64)
	_, err := Verify(e)
	wantErr(t, err, "pinned sha256 does not match")
	e.SHA256 = sum(t, e.Path)
	if _, err := Verify(e); err != nil {
		t.Fatalf("a correct pin must pass: %v", err)
	}
}

func TestVerifyRefusesNonRegularAndNonExecutable(t *testing.T) {
	e := install(t, "ok")
	if err := os.Chmod(e.Path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Verify(e)
	wantErr(t, err, "not executable")
	_, err = Verify(Entry{Name: "test.dir", Path: filepath.Dir(e.Path)})
	wantErr(t, err, "regular file")
}

func TestVerifyRefusesTraversalInThePath(t *testing.T) {
	e := install(t, "ok")
	dir := filepath.Dir(e.Path)
	_, err := Verify(Entry{Name: "test.trav", Path: dir + "/../plug/fakeplugin"})
	wantErr(t, err, "absolute and clean")
}

func TestAllowlistIsStrict(t *testing.T) {
	good := "plugins:\n  - name: acme.kvlines\n    path: /opt/jb/kvlines\n    sha256: " + strings.Repeat("a", 64) + "\n"
	a, err := ParseAllowlist([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if e, err := a.Lookup("acme.kvlines"); err != nil || e.Path != "/opt/jb/kvlines" {
		t.Fatalf("lookup = %+v, %v", e, err)
	}
	cases := map[string]string{
		"unknown key":      "plugins:\n  - name: a.b\n    path: /x/y\n    args: [\"-v\"]\n",
		"bad name":         "plugins:\n  - name: kvlines\n    path: /x/y\n",
		"upper name":       "plugins:\n  - name: Acme.kv\n    path: /x/y\n",
		"path in name":     "plugins:\n  - name: a/b.c\n    path: /x/y\n",
		"relative path":    "plugins:\n  - name: a.b\n    path: x/y\n",
		"dotdot path":      "plugins:\n  - name: a.b\n    path: /x/../y\n",
		"short pin":        "plugins:\n  - name: a.b\n    path: /x/y\n    sha256: abc\n",
		"upper pin":        "plugins:\n  - name: a.b\n    path: /x/y\n    sha256: " + strings.Repeat("A", 64) + "\n",
		"duplicate":        "plugins:\n  - name: a.b\n    path: /x/y\n  - name: a.b\n    path: /x/z\n",
		"two documents":    "plugins: []\n---\nplugins: []\n",
		"unknown toplevel": "plugin: []\n",
	}
	for name, src := range cases {
		if _, err := ParseAllowlist([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := a.Lookup("acme.other"); err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Errorf("unlisted lookup = %v", err)
	}
}

func TestAllowlistFileMustNotBeWritableByOthersAndMissingMeansEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "plugins.yaml")
	a, err := LoadAllowlist(p)
	if err != nil || len(a.Entries()) != 0 || a.Source != "" {
		t.Fatalf("missing file: %+v, %v", a, err)
	}
	if err := os.WriteFile(p, []byte("plugins: []\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err = LoadAllowlist(p)
	wantErr(t, err, "writable by group or others")
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAllowlist(p); err != nil {
		t.Fatal(err)
	}
}

func TestAllowlistPathPrefersTheEnvironmentVariable(t *testing.T) {
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	p, _ := AllowlistPath(env(map[string]string{"JB_PLUGINS_FILE": "/etc/jb/p.yaml", "HOME": "/h"}))
	if p != "/etc/jb/p.yaml" {
		t.Errorf("path = %s", p)
	}
	p, _ = AllowlistPath(env(map[string]string{"HOME": "/h"}))
	if p != "/h/.jb/plugins.yaml" {
		t.Errorf("path = %s", p)
	}
}

func TestInspectReportsPinAndModeWithoutLaunching(t *testing.T) {
	e := install(t, "ok")
	e.SHA256 = strings.Repeat("0", 64)
	a := &Allowlist{entries: map[string]Entry{e.Name: e}, order: []string{e.Name}}
	st := a.Inspect()
	if len(st) != 1 || st[0].Pin != "MISMATCH" || st[0].Err == "" {
		t.Fatalf("status = %+v", st)
	}
	if readFile(filepath.Dir(e.Path), "launches") != "" {
		t.Error("Inspect launched the plugin")
	}
}
