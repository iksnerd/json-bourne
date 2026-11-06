package casefile

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCorpus walks testdata/valid and testdata/invalid. A valid case must load and
// pass Guard. An invalid case carries want_error, a substring the error must contain,
// so each case fails for its own reason and not for any other.
func TestCorpus(t *testing.T) {
	_, gitErr := exec.LookPath("git")
	for _, kind := range []string{"valid", "invalid"} {
		dirs, err := os.ReadDir(filepath.Join("testdata", kind))
		if err != nil || len(dirs) == 0 {
			t.Fatalf("no %s corpus: %v", kind, err)
		}
		for _, d := range dirs {
			dir := filepath.Join("testdata", kind, d.Name())
			t.Run(kind+"/"+d.Name(), func(t *testing.T) {
				err := loadAndGuard(t, dir, gitErr == nil)
				if kind == "valid" {
					if err != nil {
						t.Fatalf("valid case rejected: %v", err)
					}
					return
				}
				raw, rerr := os.ReadFile(filepath.Join(dir, "want_error"))
				if rerr != nil {
					t.Fatalf("invalid case needs a want_error file: %v", rerr)
				}
				want := strings.TrimSpace(string(raw))
				if want == "" {
					t.Fatal("want_error is empty")
				}
				if err == nil {
					t.Fatalf("invalid case accepted; want error containing %q", want)
				}
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not contain %q", err, want)
				}
			})
		}
	}
}

// loadAndGuard loads dir, then checks the evidence directory in a git-initialised
// copy, so the answer does not depend on the repository the corpus lives in.
func loadAndGuard(t *testing.T, dir string, haveGit bool) error {
	t.Helper()
	c, err := Load(dir)
	if err != nil {
		return err
	}
	if !haveGit {
		return nil
	}
	tmp := t.TempDir()
	copyTree(t, dir, tmp)
	if out, err := exec.Command("git", "-C", tmp, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	st, err := Guard(filepath.Join(tmp, c.Paths.Evidence))
	if err != nil {
		return err
	}
	if st != GuardIgnored {
		t.Fatalf("guard status in a git work tree = %v, want ignored", st)
	}
	return nil
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o750)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o640)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDefaults(t *testing.T) {
	c, err := Load("testdata/valid/minimal")
	if err != nil {
		t.Fatal(err)
	}
	if c.Classification != "internal" || *c.Retention.EvidenceDays != 90 || *c.Retention.FindingsDays != 365 ||
		c.Windows["default"] != "24h" || c.Paths.Evidence != "evidence" || !*c.Handling.PassiveOnly ||
		len(c.Handling.RedactInReports) != 1 || c.Handling.RedactInReports[0] != "email" {
		t.Fatalf("defaults not applied: %+v", c)
	}
}

func TestParseEdges(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"empty":        {"", "empty"},
		"two docs":     {"apiVersion: jb.case/v1\nid: a\ntitle: t\nstatus: open\nopened: 2026-11-01\n---\nid: b\n", "more than one"},
		"null id":      {"apiVersion: jb.case/v1\nid:\ntitle: t\nstatus: open\nopened: 2026-11-01\n", `missing required key "id"`},
		"bad date":     {"apiVersion: jb.case/v1\nid: a\ntitle: t\nstatus: open\nopened: yesterday\n", "opened"},
		"duplicate":    {"apiVersion: jb.case/v1\nid: a\nid: b\ntitle: t\nstatus: open\nopened: 2026-11-01\n", "already"},
		"scope cidr":   {"apiVersion: jb.case/v1\nid: a\ntitle: t\nstatus: open\nopened: 2026-11-01\nscope: {cidrs: [192.0.2.1/24]}\n", "scope.cidrs[0]"},
		"scope domain": {"apiVersion: jb.case/v1\nid: a\ntitle: t\nstatus: open\nopened: 2026-11-01\nscope: {domains: [Example.COM]}\n", "scope.domains[0]"},
		"redact dup":   {"apiVersion: jb.case/v1\nid: a\ntitle: t\nstatus: open\nopened: 2026-11-01\nhandling: {redact_in_reports: [ip, ip]}\n", "twice"},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := Parse([]byte(tc.in))
			if err == nil && c != nil {
				c.Dir = t.TempDir()
				err = c.Validate()
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestCredentialErrorNeverEchoesValue(t *testing.T) {
	secret := "Zk3Qm9Xr2Lt7" + "Vb5Nc8Wd4Hs6Jp1Gy0Fa" // gitleaks:allow (synthetic)
	_, err := Parse([]byte("apiVersion: jb.case/v1\nid: a\ntitle: " + secret + "\nstatus: open\nopened: 2026-11-01\n"))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("want a refusal that omits the value, got %v", err)
	}
}

// Key-shaped prefixes are assembled at run time so this file holds no token-shaped literal.
func TestLooksLikeCredential(t *testing.T) {
	yes := []string{
		"gh" + "p_" + strings.Repeat("a1B2", 8),
		"AK" + "IA" + "ABCDEFGHIJKLMNOP",
		"-----BEGIN " + "RSA PRIVATE KEY-----",
		"Bear" + "er abcdefghijklmnop12345",
		"eyJ" + "hbGciOiJIUzI1.eyJ" + "zdWIiOiIxMjM0.sig",
		"https://user:hunter2@example.com/",
		strings.Repeat("0123456789abcdef", 3),
	}
	no := []string{
		"KIBANA_API_KEY", "config/hunt.yaml", "Credential stuffing against the example login, wave 2",
		"example-case-2026-credential-stuffing-wave-two-of-three", "192.0.2.0/24", "https://kibana.example.com",
	}
	for _, s := range yes {
		if !looksLikeCredential(s) {
			t.Errorf("not refused: %.12q...", s)
		}
	}
	for _, s := range no {
		if looksLikeCredential(s) {
			t.Errorf("refused: %q", s)
		}
	}
}

func TestResolveInsideDangling(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(root, "gone"), filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	real, _ := realRoot(root)
	if _, err := resolveInside(real, "dangling"); err == nil {
		t.Fatal("a dangling symlink must be refused")
	}
	if _, err := resolveInside(real, "new/dir"); err != nil {
		t.Fatalf("a not-yet-existing path inside the root is fine: %v", err)
	}
}
