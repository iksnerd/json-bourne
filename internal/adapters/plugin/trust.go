package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// checkMode refuses anything writable by group or others.
func checkMode(fi fs.FileInfo) error {
	if m := fi.Mode().Perm(); m&0o022 != 0 {
		return fmt.Errorf("mode %04o is writable by group or others", uint32(m))
	}
	return nil
}

// Verified is a plugin file that passed every check at one moment.
type Verified struct {
	Entry Entry
	Path  string // the resolved file to execute (symlinks followed, inside Dir)
	Dir   string // the plugin's own directory, used as its working directory
}

// Verify runs every trust check on an allowlisted plugin and returns the file to
// launch. It is called before EVERY launch, never once at load:
//
//   - the path resolves (symlinks followed) to a regular file whose directory is the
//     directory of the allowlisted path: a symlink that points out of the plugin
//     directory is refused;
//   - neither the file nor its directory is writable by group or others;
//   - the file is executable by its owner;
//   - when the entry carries a sha256 pin, the file's digest equals it.
//
// The digest and the exec are not one atomic step (Go cannot exec a descriptor
// portably). The mode check on the directory is what closes that window: nobody but
// the owner can replace the file between the two.
func Verify(e Entry) (Verified, error) {
	fail := func(format string, a ...any) (Verified, error) {
		return Verified{}, fmt.Errorf("plugin %s: %s", e.Name, fmt.Sprintf(format, a...))
	}
	if !filepath.IsAbs(e.Path) || filepath.Clean(e.Path) != e.Path {
		return fail("path is not absolute and clean")
	}
	wantDir, err := filepath.EvalSymlinks(filepath.Dir(e.Path))
	if err != nil {
		return fail("directory: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(e.Path)
	if err != nil {
		return fail("file: %v", err)
	}
	if filepath.Dir(resolved) != wantDir {
		return fail("the file resolves outside its own directory (symlink out of the plugin dir)")
	}
	di, err := os.Stat(wantDir)
	if err != nil || !di.IsDir() {
		return fail("plugin directory is not a directory")
	}
	if err := checkMode(di); err != nil {
		return fail("directory: %v", err)
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return fail("file: %v", err)
	}
	if !fi.Mode().IsRegular() {
		return fail("not a regular file")
	}
	if err := checkMode(fi); err != nil {
		return fail("file: %v", err)
	}
	if fi.Mode().Perm()&0o100 == 0 {
		return fail("file is not executable by its owner")
	}
	if e.SHA256 != "" {
		got, err := fileSHA256(resolved)
		if err != nil {
			return fail("pin: %v", err)
		}
		if got != e.SHA256 {
			return fail("pinned sha256 does not match the file on disk (it changed since it was pinned); refusing to launch")
		}
	}
	return Verified{Entry: e, Path: resolved, Dir: wantDir}, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Status is one allowlisted plugin as `jb doctor` shows it. It never carries an
// environment value.
type Status struct {
	Name, Path string
	Pin        string // "none", "ok" or "MISMATCH"
	Err        string // "": every check passed; otherwise the first failed check
}

// Inspect reports the state of every entry without launching anything.
func (a *Allowlist) Inspect() []Status {
	var out []Status
	for _, e := range a.Entries() {
		st := Status{Name: e.Name, Path: e.Path, Pin: "none"}
		if e.SHA256 != "" {
			st.Pin = "ok"
		}
		if _, err := Verify(e); err != nil {
			st.Err = strings.TrimPrefix(err.Error(), "plugin "+e.Name+": ")
			if e.SHA256 != "" && strings.Contains(st.Err, "pinned sha256") {
				st.Pin = "MISMATCH"
			}
		}
		out = append(out, st)
	}
	return out
}
