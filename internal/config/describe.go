package config

import (
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/core"
)

// Description is a config as plain data: what a run would read, judge and send,
// without running anything. It is built from the parsed file alone. It reads no
// environment variable, opens no store and makes no connection, so it can hold the
// NAME of a credential variable and never a value.
//
// Options hold the keys the file set. A key that is absent takes the detector's or
// source's own default, which Describe does not resolve.
type Description struct {
	Sources   []SourceDescription   `json:"sources"`
	Detectors []DetectorDescription `json:"detectors"`
	Store     StoreDescription      `json:"store"`
	Alerts    []AlertDescription    `json:"alerts"`
}

// SourceDescription is one entry of `sources:`.
type SourceDescription struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// URL has no query and no fragment.
	URL   string `json:"url,omitempty"`
	Index string `json:"index,omitempty"`
	// CredentialEnv is the name of the environment variable that holds the credential.
	CredentialEnv string         `json:"credential_env,omitempty"`
	Options       map[string]any `json:"options,omitempty"`
}

// DetectorDescription is one entry of `detectors:`.
type DetectorDescription struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Sources is the `sources:` scope as written; nil means every source.
	Sources []string `json:"sources,omitempty"`
	// Reads names the enabled sources the detector reads. Nil for a disabled detector.
	Reads   []string       `json:"reads,omitempty"`
	Options map[string]any `json:"options,omitempty"`
}

// StoreDescription says where the evidence database is. Path is as the file (or the
// case placement) gives it, with `~/` unexpanded. Default means the path was empty,
// so a run uses $JB_DB, then ~/.jb/jb.duckdb; Describe does not read either.
type StoreDescription struct {
	Path    string `json:"path,omitempty"`
	Default bool   `json:"default"`
}

// AlertDescription is one entry of `alerts:`. The destination of a webhook is the
// value of CredentialEnv, which is a secret, so no host is shown.
type AlertDescription struct {
	Type          string         `json:"type"`
	CredentialEnv string         `json:"credential_env,omitempty"`
	Options       map[string]any `json:"options,omitempty"`
}

// optioner is implemented by a detector or alert spec: the plain data of its options.
type optioner interface{ options() any }

// sourceDescriber is implemented by a source spec.
type sourceDescriber interface{ describeSource() SourceDescription }

// Describe returns the effective configuration as plain data. See Description.
func (f *File) Describe() Description {
	d := Description{
		Sources:   []SourceDescription{},
		Detectors: []DetectorDescription{},
		Alerts:    []AlertDescription{},
		Store:     StoreDescription{Path: f.Store.Path, Default: f.Store.Path == ""},
	}
	for _, e := range f.Sources {
		sd := SourceDescription{Type: e.Type}
		if sp, ok := e.spec.(sourceDescriber); ok {
			sd = sp.describeSource()
		} else {
			sd.Name = e.spec.describe().Name
		}
		sd.Type, sd.Enabled = e.Type, !e.Disabled
		d.Sources = append(d.Sources, sd)
	}
	for _, e := range f.Detectors {
		dd := DetectorDescription{Type: e.Type, Name: e.DisplayName(), Enabled: !e.Disabled, Sources: slices.Clone(e.Sources)}
		if !e.Disabled {
			for _, i := range f.readsSources(e) {
				dd.Reads = append(dd.Reads, f.Sources[i].spec.describe().Name)
			}
		}
		if o, ok := e.spec.(optioner); ok {
			dd.Options = plainOptions(o.options(), "name")
		}
		d.Detectors = append(d.Detectors, dd)
	}
	for _, e := range f.Alerts {
		ad := AlertDescription{Type: e.Type}
		if o, ok := e.spec.(optioner); ok {
			ad.Options = plainOptions(o.options(), "url_env")
		}
		if w, ok := e.spec.(webhookSpec); ok {
			ad.CredentialEnv = w.URLEnv
		}
		d.Alerts = append(d.Alerts, ad)
	}
	return d
}

func (s kibanaSpec) describeSource() SourceDescription {
	opts := map[string]any{}
	if s.TimeField != "" {
		opts["time_field"] = s.TimeField
	}
	if s.PageSize != 0 {
		opts["page_size"] = s.PageSize
	}
	if s.Mapper != "" {
		opts["mapper"] = s.Mapper
	}
	if len(s.MapperConfig) > 0 {
		// Keys only: mapper_config is free-form data for a plugin and may hold anything.
		keys := make([]string, 0, len(s.MapperConfig))
		for k := range s.MapperConfig {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		opts["mapper_config_keys"] = keys
	}
	if s.SearchField != "" {
		opts["search_field"] = s.SearchField
	}
	if len(s.Filter) > 0 {
		opts["filter"] = plainValue(s.Filter)
	}
	if len(opts) == 0 {
		opts = nil
	}
	return SourceDescription{Name: s.label(), URL: stripURL(s.URL), Index: s.Index, CredentialEnv: s.APIKeyEnv, Options: opts}
}

// stripURL drops the query, the fragment and any user info: only where, never how.
func stripURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return u.String()
}

func (s authspikeSpec) options() any   { return s.cfg }
func (s fingerprintSpec) options() any { return s }
func (s signupSpec) options() any      { return s.cfg }
func (s newkeySpec) options() any      { return s.cfg }
func (s behaviourSpec) options() any   { return s.cfg }
func (s signatureSpec) options() any   { return s.cfg }
func (s webhookSpec) options() any     { return s }

// plainOptions returns v as a map of its yaml keys with unset (zero) values left out,
// minus the named keys.
func plainOptions(v any, drop ...string) map[string]any {
	m, _ := plainValue(v).(map[string]any)
	for _, k := range drop {
		delete(m, k)
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// plainValue round-trips v through yaml, so keys are the file's keys, and prunes zero
// values. It panics on nothing: a value that cannot marshal becomes nil.
func plainValue(v any) any {
	b, err := yaml.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	if err := yaml.Unmarshal(b, &out); err != nil {
		return nil
	}
	return prune(out)
}

func prune(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if e = prune(e); isZero(e) {
				delete(x, k)
			} else {
				x[k] = e
			}
		}
		return x
	case []any:
		for i := range x {
			x[i] = prune(x[i])
		}
		return x
	}
	return v
}

func isZero(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map, reflect.Slice:
		return rv.Len() == 0
	}
	return rv.IsZero()
}

// CaseShow is the described config of one config of a case.
type CaseShow struct {
	Case string `json:"case"`
	// Config is the config file, relative to the case directory when it is inside it.
	Config string `json:"config"`
	// Notes are advice lines, such as a store outside the evidence directory.
	Notes []string `json:"notes,omitempty"`
	Description
}

// ShowCase loads the case, chooses the config (see chooseShown), places the
// store as a hunt would, and describes the result. It runs no git command, reads no
// environment variable, opens no store and reads nothing under evidence/.
func ShowCase(dir, cfgFlag string) (*CaseShow, error) {
	c, err := casefile.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("case %s: %w", dir, err)
	}
	p, err := chooseShown(c, cfgFlag)
	if err != nil {
		return nil, err
	}
	f, err := Load(p)
	if err != nil {
		return nil, err
	}
	f.UseCase(c)
	out := &CaseShow{Case: c.ID, Config: p}
	if rel, err := filepath.Rel(c.Dir, p); err == nil && filepath.IsLocal(rel) {
		out.Config = filepath.ToSlash(rel)
	}
	if note := PlaceCaseStore(c, f); note != "" {
		out.Notes = append(out.Notes, note)
	}
	out.Description = f.Describe()
	return out, nil
}

// chooseShown picks the config `case show` describes. No command stands for it, so the
// `commands:` rule does not apply: --config names one, else the case's only config.
// More than one listed config is a usage error that shows each with its commands.
func chooseShown(c *casefile.Case, flag string) (string, error) {
	if flag != "" {
		return ChooseCaseConfig(c, flag, "")
	}
	switch len(c.Config) {
	case 0:
		return "", core.Usagef("case %s lists no config: pass --config FILE (a file inside the case)", c.ID)
	case 1:
		return filepath.Join(c.Dir, filepath.FromSlash(c.Config[0])), nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "case %s lists %d configs, pass --config with one of these:", c.ID, len(c.Config))
	for _, rel := range c.Config {
		list := "no commands declared"
		if cmds, err := LoadCommands(filepath.Join(c.Dir, filepath.FromSlash(rel))); err == nil && len(cmds) > 0 {
			list = "commands: " + strings.Join(cmds, ", ")
		}
		fmt.Fprintf(&b, "\n  %s  (%s)", rel, list)
	}
	return "", core.Usagef("%s", b.String())
}
