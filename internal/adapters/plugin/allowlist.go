// Package plugin is the host for out-of-process mappers.
//
// A plugin is an executable the operator has allowlisted by name. jb starts it as a
// child process, speaks newline-delimited JSON with it over stdio, and turns its
// answers into events. This package is the only place in jb that starts a process
// (internal/archtest enforces that).
//
// What this package does not do: it does not sandbox the child. The child runs as the
// same user with the same filesystem and network access as jb; jb only controls what
// the child is handed (an almost empty environment, a working directory, no extra file
// descriptors), what it may send back (size and time limits) and which file may be
// launched at all (the allowlist, a mode check and an optional sha256 pin).
package plugin

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// EnvAllowlistFile names the environment variable that overrides the allowlist location.
const EnvAllowlistFile = "JB_PLUGINS_FILE"

const maxAllowlistBytes = 1 << 20

// NamePattern is the shape of a plugin name: dotted, lower case, at least two segments.
// A name can therefore never be a path, a flag or a shell word.
var NamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$`)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Entry is one allowlisted plugin.
type Entry struct {
	Name   string `yaml:"name"`
	Path   string `yaml:"path"`
	SHA256 string `yaml:"sha256"` // optional pin, lower-case hex
}

// Allowlist is the operator's list of plugins, read from jb's own location. A case or
// hunt config can only name an entry in it; it can never add one.
type Allowlist struct {
	Source  string // file the list was read from ("" when there is none)
	entries map[string]Entry
	order   []string
}

type fileFormat struct {
	Plugins []Entry `yaml:"plugins"`
}

// AllowlistPath is where the allowlist is read from: $JB_PLUGINS_FILE, else
// ~/.jb/plugins.yaml. env looks a variable up (os.LookupEnv in production).
func AllowlistPath(env func(string) (string, bool)) (string, error) {
	if p, ok := env(EnvAllowlistFile); ok && p != "" {
		return p, nil
	}
	home, ok := env("HOME")
	if !ok || home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("plugin allowlist: no %s and no home directory: %w", EnvAllowlistFile, err)
		}
		home = h
	}
	return filepath.Join(home, ".jb", "plugins.yaml"), nil
}

// LoadAllowlist reads and strictly validates the allowlist at path. A missing file is
// an empty allowlist (Source is then ""): no plugin is allowed, which is the safe
// default. A file that exists but is writable by group or others, unreadable, or not
// strictly valid is an error.
func LoadAllowlist(path string) (*Allowlist, error) {
	a := &Allowlist{entries: map[string]Entry{}}
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, fmt.Errorf("plugin allowlist %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("plugin allowlist %s: not a regular file", path)
	}
	if err := checkMode(fi); err != nil {
		return nil, fmt.Errorf("plugin allowlist %s: %w", path, err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("plugin allowlist %s: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxAllowlistBytes+1))
	if err != nil {
		return nil, fmt.Errorf("plugin allowlist %s: %w", path, err)
	}
	if len(data) > maxAllowlistBytes {
		return nil, fmt.Errorf("plugin allowlist %s: larger than %d bytes", path, maxAllowlistBytes)
	}
	if err := a.parse(data); err != nil {
		return nil, fmt.Errorf("plugin allowlist %s: %w", path, err)
	}
	a.Source = path
	return a, nil
}

// ParseAllowlist is LoadAllowlist for bytes already in memory (tests).
func ParseAllowlist(data []byte) (*Allowlist, error) {
	a := &Allowlist{entries: map[string]Entry{}}
	if err := a.parse(data); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Allowlist) parse(data []byte) error {
	if err := checkYAMLShape(data); err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var ff fileFormat
	if err := dec.Decode(&ff); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("not strict YAML: %w", err)
	}
	var extra fileFormat
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("more than one YAML document")
	}
	for i, e := range ff.Plugins {
		if !NamePattern.MatchString(e.Name) {
			return fmt.Errorf("plugins[%d]: name %q must match %s", i, e.Name, NamePattern)
		}
		if _, dup := a.entries[e.Name]; dup {
			return fmt.Errorf("plugins[%d]: duplicate name %q", i, e.Name)
		}
		if !filepath.IsAbs(e.Path) || filepath.Clean(e.Path) != e.Path {
			return fmt.Errorf("plugins[%d] (%s): path must be absolute and clean (no .., no //, no trailing slash)", i, e.Name)
		}
		if e.SHA256 != "" && !sha256Pattern.MatchString(e.SHA256) {
			return fmt.Errorf("plugins[%d] (%s): sha256 must be 64 lower-case hex digits", i, e.Name)
		}
		a.entries[e.Name] = e
		a.order = append(a.order, e.Name)
	}
	return nil
}

// Lookup returns the entry for name, or an error saying the plugin is not allowed.
func (a *Allowlist) Lookup(name string) (Entry, error) {
	e, ok := a.entries[name]
	if !ok {
		where := a.Source
		if where == "" {
			where = "no allowlist file found"
		}
		return Entry{}, fmt.Errorf("plugin %q is not allowlisted (%s); only the operator can add it to the allowlist", name, where)
	}
	return e, nil
}

// Entries lists the allowlisted plugins in file order.
func (a *Allowlist) Entries() []Entry {
	out := make([]Entry, 0, len(a.order))
	for _, n := range a.order {
		out = append(out, a.entries[n])
	}
	return out
}
