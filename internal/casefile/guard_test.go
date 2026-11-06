package casefile

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitInit(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	d := t.TempDir()
	if out, err := exec.Command("git", "-C", d, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return d
}

func TestGuard(t *testing.T) {
	t.Run("not ignored is an error", func(t *testing.T) {
		d := gitInit(t)
		if st, err := Guard(filepath.Join(d, "evidence")); err == nil || !strings.Contains(err.Error(), "not ignored") {
			t.Fatalf("got %v, %v", st, err)
		}
	})
	t.Run("ignored, directory missing", func(t *testing.T) {
		d := gitInit(t)
		os.WriteFile(filepath.Join(d, ".gitignore"), []byte("/evidence/\n"), 0o640)
		if st, err := Guard(filepath.Join(d, "evidence")); err != nil || st != GuardIgnored {
			t.Fatalf("got %v, %v", st, err)
		}
	})
	t.Run("not a work tree is a distinct result", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skip("git not installed")
		}
		st, err := Guard(filepath.Join(t.TempDir(), "evidence"))
		if err != nil || st != GuardNotWorkTree || st == GuardIgnored {
			t.Fatalf("got %v, %v", st, err)
		}
	})
	t.Run("tracked file under an ignored dir is an error", func(t *testing.T) {
		d := gitInit(t)
		os.MkdirAll(filepath.Join(d, "evidence"), 0o750)
		os.WriteFile(filepath.Join(d, "evidence", "log.txt"), []byte("x"), 0o640)
		if out, err := exec.Command("git", "-C", d, "add", "evidence/log.txt").CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		os.WriteFile(filepath.Join(d, ".gitignore"), []byte("/evidence/\n"), 0o640)
		if _, err := Guard(filepath.Join(d, "evidence")); err == nil || !strings.Contains(err.Error(), "tracks") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("unreadable answer is an error", func(t *testing.T) {
		d := gitInit(t)
		fake := t.TempDir()
		os.WriteFile(filepath.Join(fake, "git"), []byte("#!/bin/sh\necho nonsense >&2\nexit 3\n"), 0o755)
		t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
		if st, err := Guard(filepath.Join(d, "evidence")); err == nil {
			t.Fatalf("an unreadable git answer must not pass: %v", st)
		}
	})
}
