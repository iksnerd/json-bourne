package casefile

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

func isIP(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == "" && a.String() == s
}

func isCIDR(s string) bool {
	p, err := netip.ParsePrefix(s)
	return err == nil && p.String() == s && p == p.Masked()
}

// realRoot returns the case directory with symlinks resolved. Every confinement
// check compares against this, so a case directory reached through a symlink works.
func realRoot(dir string) (string, error) {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("case directory %s: %w", dir, err)
	}
	st, err := os.Stat(real)
	if err != nil || !st.IsDir() {
		return "", fmt.Errorf("case directory %s is not a directory", dir)
	}
	return real, nil
}

// lexical rejects a path before the filesystem is consulted: empty, absolute,
// drive-lettered, backslashed, NUL-bearing, "." or containing a ".." element.
func lexical(rel string) error {
	switch {
	case rel == "":
		return errors.New("path is empty")
	case strings.ContainsRune(rel, 0):
		return errors.New("path contains a NUL byte")
	case strings.ContainsRune(rel, '\\'):
		return errors.New("path contains a backslash; use / separators")
	case strings.HasPrefix(rel, "/") || filepath.IsAbs(rel) || (len(rel) > 1 && rel[1] == ':'):
		return errors.New("absolute path is not allowed: paths are relative to the case directory")
	}
	parts := strings.Split(rel, "/")
	clean := true
	for _, p := range parts {
		if p == ".." {
			return errors.New("path contains '..': paths must stay inside the case directory")
		}
		if p != "" && p != "." {
			clean = false
		}
	}
	if clean {
		return errors.New("path names the case directory itself")
	}
	return nil
}

// resolveInside checks rel against root (already symlink-resolved) and returns the
// resolved location. The longest existing prefix is passed through EvalSymlinks, so
// a symlink anywhere on the way that leads outside root is refused, and so is a
// dangling one. The part that does not exist yet is lexically clean by lexical().
func resolveInside(root, rel string) (string, error) {
	if err := lexical(rel); err != nil {
		return "", err
	}
	parts := strings.Split(rel, "/")
	p, i := root, 0
	for ; i < len(parts); i++ {
		next := filepath.Join(p, parts[i])
		if _, err := os.Lstat(next); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				break
			}
			return "", err
		}
		p = next
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("cannot resolve %q (dangling symlink?): %w", rel, err)
	}
	if !within(root, real) {
		return "", fmt.Errorf("%q resolves outside the case directory (symlink escape)", rel)
	}
	return filepath.Join(append([]string{real}, parts[i:]...)...), nil
}

func within(root, p string) bool {
	r, err := filepath.Rel(root, p)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) && !filepath.IsAbs(r)
}
