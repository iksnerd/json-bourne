// Package config is the composition root: it reads the YAML file and builds the
// adapters. It is the one place besides cmd/jb that may import them.
//
// The file never holds a credential. A source names the environment variable that
// does (api_key_env) and Build reads it, failing when it is unset. Unknown keys and
// unknown types fail at Load, so a typo cannot silently turn a safeguard off.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/adapters/kibana"
	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/core"
)

// maxFileSize bounds what Load reads; a config is a few hundred bytes.
const maxFileSize = 1 << 20

// Env looks an environment variable up. It is a parameter so tests need not touch
// the process environment.
type Env func(name string) (string, bool)

// OSEnv reads the process environment.
func OSEnv(name string) (string, bool) { return os.LookupEnv(name) }

// errEnvNotSet is the error for a named variable that is unset or empty. It says where
// jb looks and where to read how to fill it. It names the variable, never a value.
func errEnvNotSet(name string) error {
	return fmt.Errorf("environment variable %s is not set (jb reads it from the process environment, not from the config file or a .env file; see \"Supplying credentials\" in docs/CONFIG.md)", name)
}

// File is the parsed, validated configuration. Credentials are not resolved yet.
type File struct {
	// Commands names the jb commands this file is for (see CaseCommands), so a case
	// that lists several configs can choose the one that answers a command. Optional.
	Commands  []string        `yaml:"commands"`
	Sources   []SourceEntry   `yaml:"sources"`
	Detectors []DetectorEntry `yaml:"detectors"`
	Store     Store           `yaml:"store"`
	Feeds     []FeedEntry     `yaml:"feeds"`
	Intel     IntelConfig     `yaml:"intel"`
	Alerts    []AlertEntry    `yaml:"alerts"`
	Estate    EstateConfig    `yaml:"estate"`

	caseRef *casefile.Case // set by UseCase; not part of the file

	search      []string // set by WithSearch; not part of the file
	searchField string
}

// Store configures the evidence database.
type Store struct {
	// Path of the DuckDB file. Empty means $JB_DB, then ~/.jb/jb.duckdb.
	Path string `yaml:"path"`
}

// IntelConfig holds the options of `jb intel` that are not about one feed.
type IntelConfig struct {
	// IPFields are the event fields addresses are read from in the latest stored run.
	// Default: client_ip.
	IPFields []string `yaml:"ip_fields"`
	// MaxIndicators caps how many distinct addresses one run asks about. Default 10.
	MaxIndicators *int `yaml:"max_indicators"`
}

// IntelOptions is IntelConfig with defaults applied.
type IntelOptions struct {
	IPFields      []string
	MaxIndicators int
}

// IntelOptions returns the intel options with defaults applied.
func (f *File) IntelOptions() IntelOptions {
	o := IntelOptions{IPFields: f.Intel.IPFields, MaxIndicators: defaultMaxIndicators}
	if len(o.IPFields) == 0 {
		o.IPFields = []string{defaultIntelIPField}
	}
	if f.Intel.MaxIndicators != nil {
		o.MaxIndicators = *f.Intel.MaxIndicators
	}
	return o
}

func (c IntelConfig) validate() error {
	if c.IPFields != nil {
		if len(c.IPFields) == 0 || len(c.IPFields) > maxIntelIPFields {
			return fmt.Errorf("intel.ip_fields: 1 to %d fields, or remove the key", maxIntelIPFields)
		}
		for _, f := range c.IPFields {
			if !filterField.MatchString(f) {
				return errors.New("intel.ip_fields: each field must be 1-128 characters of letters, digits, _ @ . -")
			}
		}
	}
	if c.MaxIndicators != nil && (*c.MaxIndicators < 1 || *c.MaxIndicators > maxMaxIndicators) {
		return fmt.Errorf("intel.max_indicators %d outside 1..%d", *c.MaxIndicators, maxMaxIndicators)
	}
	return nil
}

// FeedEntry is one element of `feeds:`. Its Type selects the builder.
type FeedEntry struct {
	Type string
	spec feedSpec
}

type feedSpec interface {
	build(env Env) (core.Feed, error)
	// feedName is the name the built feed reports; it is the reputation table's source
	// column, so two feeds in one config must not share it.
	feedName() string
	// enabled is false for a feed that sends data off the machine and was not switched on.
	enabled() bool
	describe() ServiceInfo
}

// UnmarshalYAML picks the builder by `type:` and strictly decodes the rest.
func (e *FeedEntry) UnmarshalYAML(n *yaml.Node) error {
	t, spec, err := decodeTyped("feed", n, feedTypes())
	if err != nil {
		return err
	}
	e.Type, e.spec = t, spec
	return nil
}

// BuildFeeds constructs the reputation feeds, reading credentials from env. It is
// separate from Build so that a hunt never needs a feed's key. An error never
// contains a credential value.
func (f *File) BuildFeeds(env Env) ([]core.Feed, error) {
	if env == nil {
		env = OSEnv
	}
	var out []core.Feed
	var errs []error
	for i, e := range f.Feeds {
		if !e.spec.enabled() {
			continue // listed but off: nothing is built, nothing is asked
		}
		feed, err := e.spec.build(env)
		if err != nil {
			errs = append(errs, fmt.Errorf("feeds[%d] (%s): %w", i, e.Type, err))
			continue
		}
		out = append(out, feed)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}

// DisabledFeeds names the feeds the file lists but BuildFeeds skips because they are not
// enabled, so a command can say so instead of silently asking fewer feeds.
func (f *File) DisabledFeeds() []string {
	var out []string
	for _, e := range f.Feeds {
		if !e.spec.enabled() {
			out = append(out, e.spec.feedName())
		}
	}
	return out
}

// checkFeedNames refuses two feeds that report the same name: the source column of the
// reputation table must say which feed an answer came from.
func (f *File) checkFeedNames() error {
	seen := map[string]int{}
	for i, e := range f.Feeds {
		n := e.spec.feedName()
		if j, dup := seen[n]; dup {
			return fmt.Errorf("feeds[%d] (%s) and feeds[%d] both report the name %q; the reputation source column would not say which one answered", j, e.Type, i, n)
		}
		seen[n] = i
	}
	return nil
}

// SourceEntry is one element of `sources:`. Its Type selects the builder.
type SourceEntry struct {
	Type string
	spec sourceSpec
	// Disabled is true for `enabled: false`. A disabled source is validated at Load like
	// any other and is then never built, never asked and never contacts the network. It
	// is listed by name wherever a run is described: see File.DisabledSources.
	Disabled bool
}

// DetectorEntry is one element of `detectors:`.
type DetectorEntry struct {
	Type string
	spec detectorSpec
	// Sources are the names of the sources the detector reads, or nil for all of them.
	// Parse guarantees every name is a configured source, and that an enabled detector
	// names no disabled one.
	Sources []string
	// Disabled is true for `enabled: false`: validated at Load, never built, never run.
	Disabled bool
	name     string // the detector's `name:` as written, for listing it when it is not built
}

// DisplayName is the name the detector runs under (its `name:`), which a disabled
// detector has not been built to report; the type when the file gave none.
func (e DetectorEntry) DisplayName() string {
	if e.name != "" {
		return e.name
	}
	return e.Type
}

type sourceSpec interface {
	build(env Env) (core.Source, error)
	describe() ServiceInfo
}

// buildCtx is what a detector may need beyond its own options.
type buildCtx struct {
	// c is the case the config belongs to, or nil when there is none. A detector that
	// reads case data (an actor file) refuses to build without it.
	c *casefile.Case
}

type detectorSpec interface {
	build(bc buildCtx) (core.Detector, error)
}

// UseCase tells the config which case it belongs to, so detectors can read the case's
// data files by name. Without it such a detector fails to build.
func (f *File) UseCase(c *casefile.Case) { f.caseRef = c }

// searchable is implemented by a source spec that can narrow its query by an ad-hoc term
// on the server. A source that cannot makes `--search` an error: a term applied to some
// sources only would read as a complete answer.
type searchable interface {
	withSearch(terms []string, field string) sourceSpec
}

// WithSearch narrows every source by terms for this run only. The terms are validated by
// ValidateSearch; field overrides each source's search_field and may be empty. It
// refuses a config with a source that cannot search, and one whose combined filter would
// pass the clause cap.
func (f *File) WithSearch(terms []string, field string) error {
	if err := ValidateSearch(terms); err != nil {
		return err
	}
	if field != "" && !filterField.MatchString(field) {
		return errors.New("search field must be 1-128 characters of letters, digits, _ @ . -")
	}
	for i, e := range f.Sources {
		if e.Disabled {
			continue // never built, so never asked
		}
		if _, ok := e.spec.(searchable); !ok {
			return fmt.Errorf("sources[%d] (%s) cannot be searched; --search needs every source to support it", i, e.Type)
		}
		if ks, ok := e.spec.(kibanaSpec); ok && len(ks.Filter)+len(terms) > maxFilterClauses {
			return fmt.Errorf("sources[%d] (%s): %d configured filter clause(s) and %d search term(s) exceed the %d-clause limit", i, e.Type, len(ks.Filter), len(terms), maxFilterClauses)
		}
	}
	f.search, f.searchField = append([]string(nil), terms...), field
	return nil
}

// Search returns the terms set by WithSearch.
func (f *File) Search() []string { return append([]string(nil), f.search...) }

// UnmarshalYAML picks the builder by `type:` and strictly decodes the rest.
func (e *SourceEntry) UnmarshalYAML(n *yaml.Node) error {
	enabled, rest, err := splitEnabled(n)
	if err != nil {
		return err
	}
	t, spec, err := decodeTyped("source", rest, sourceTypes())
	if err != nil {
		return err
	}
	e.Type, e.spec, e.Disabled = t, spec, !enabled
	return nil
}

// UnmarshalYAML picks the builder by `type:` and strictly decodes the rest.
//
// `sources:` is common to every detector type, so it is taken out here and the type's
// own options never see it.
func (e *DetectorEntry) UnmarshalYAML(n *yaml.Node) error {
	srcs, rest, err := splitSources(n)
	if err != nil {
		return err
	}
	enabled, rest, err := splitEnabled(rest)
	if err != nil {
		return err
	}
	t, spec, err := decodeTyped("detector", rest, detectorTypes())
	if err != nil {
		return err
	}
	e.Type, e.spec, e.Sources, e.Disabled, e.name = t, spec, srcs, !enabled, scalarKey(rest, "name")
	return nil
}

// scalarKey returns the scalar value of key in a mapping node, or "".
func scalarKey(n *yaml.Node, key string) string {
	if n == nil || n.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key && n.Content[i+1].Kind == yaml.ScalarNode {
			return n.Content[i+1].Value
		}
	}
	return ""
}

// splitEnabled reads the `enabled:` key common to every source and detector and returns
// whether it is on (true when the key is absent) and the mapping without it. The value
// must be a YAML boolean: the string "false", a number or an empty value is an error,
// because a switch that is read as something other than what was written is the failure
// this key exists to prevent.
func splitEnabled(n *yaml.Node) (bool, *yaml.Node, error) {
	if n.Kind != yaml.MappingNode {
		return true, n, nil // decodeTyped reports it
	}
	rest := &yaml.Node{Kind: yaml.MappingNode, Tag: n.Tag, Line: n.Line, Column: n.Column}
	enabled, found := true, false
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Value != "enabled" {
			rest.Content = append(rest.Content, k, v)
			continue
		}
		if found {
			return false, nil, fmt.Errorf("line %d: `enabled:` appears twice", k.Line)
		}
		found = true
		if v.Kind != yaml.ScalarNode || v.ShortTag() != "!!bool" {
			return false, nil, fmt.Errorf("line %d: enabled must be the YAML boolean true or false, not %q", k.Line, v.Value)
		}
		if err := v.Decode(&enabled); err != nil {
			return false, nil, fmt.Errorf("line %d: enabled must be the YAML boolean true or false, not %q", k.Line, v.Value)
		}
	}
	return enabled, rest, nil
}

// splitSources reads the `sources:` key of a detector mapping and returns the names and
// the mapping without it. An absent key is nil (every source); a present key must be a
// non-empty list of distinct names, because an empty one would mean "no source" and a
// detector that reads nothing reports nothing.
func splitSources(n *yaml.Node) ([]string, *yaml.Node, error) {
	if n.Kind != yaml.MappingNode {
		return nil, n, nil // decodeTyped reports it
	}
	rest := &yaml.Node{Kind: yaml.MappingNode, Tag: n.Tag, Line: n.Line, Column: n.Column}
	var names []string
	found := false
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Value != "sources" {
			rest.Content = append(rest.Content, k, v)
			continue
		}
		if found {
			return nil, nil, fmt.Errorf("line %d: detector has `sources:` twice", k.Line)
		}
		found = true
		if v.Kind != yaml.SequenceNode {
			return nil, nil, fmt.Errorf("line %d: sources must be a list of source names", k.Line)
		}
		if len(v.Content) == 0 {
			return nil, nil, fmt.Errorf("line %d: sources is an empty list; remove the key to read every source", k.Line)
		}
		seen := map[string]bool{}
		for _, item := range v.Content {
			if item.Kind != yaml.ScalarNode || item.Value == "" {
				return nil, nil, fmt.Errorf("line %d: sources must be a list of source names", item.Line)
			}
			if seen[item.Value] {
				return nil, nil, fmt.Errorf("line %d: sources lists %q twice", item.Line, item.Value)
			}
			seen[item.Value] = true
			names = append(names, item.Value)
		}
	}
	return names, rest, nil
}

// Load reads and validates the file at path. It does not read the environment.
func Load(path string) (*File, error) {
	fh, err := os.Open(path) // #nosec G304 -- path is the operator's own --config flag
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("config %s is larger than %d bytes", path, maxFileSize)
	}
	f, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return f, nil
}

// Parse validates YAML bytes. Unknown keys and unknown types are errors.
func Parse(data []byte) (*File, error) {
	var f File
	if err := strictDecode(data, &f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("file is empty")
		}
		return nil, err
	}
	if err := checkCommands(f.Commands); err != nil {
		return nil, err
	}
	if len(f.Sources) == 0 {
		return nil, errors.New("sources: at least one source is required")
	}
	if len(f.Detectors) == 0 {
		return nil, errors.New("detectors: at least one detector is required")
	}
	if err := f.Intel.validate(); err != nil {
		return nil, err
	}
	if err := f.Estate.validate(); err != nil {
		return nil, err
	}
	if err := f.checkFeedNames(); err != nil {
		return nil, err
	}
	if err := f.checkSourceNames(); err != nil {
		return nil, err
	}
	if err := f.checkDetectorSources(); err != nil {
		return nil, err
	}
	if err := f.checkSomethingToRun(); err != nil {
		return nil, err
	}
	if err := f.checkScopesAreEnabled(); err != nil {
		return nil, err
	}
	if err := f.checkQuietNeedsFilters(); err != nil {
		return nil, err
	}
	if err := f.checkFieldsAreEmitted(); err != nil {
		return nil, err
	}
	return &f, nil
}

// checkSourceNames refuses two sources that report the same name: the name is part of
// the run id and the stored source column, so a duplicate would replace the other's
// events. Give one of them a `name`.
func (f *File) checkSourceNames() error {
	seen := map[string]int{}
	for i, e := range f.Sources {
		n := e.spec.describe().Name
		if j, dup := seen[n]; dup {
			return fmt.Errorf("sources[%d] (%s) and sources[%d] (%s) both report the name %q; give one a distinct `name:` (^[a-z][a-z0-9_.:-]{0,63}$) to read the same index twice", j, f.Sources[j].Type, i, e.Type, n)
		}
		seen[n] = i
	}
	return nil
}

// checkDetectorSources refuses a detector scoped to a source the file does not define,
// naming the detector and the name. A misspelt scope must not leave the detector
// reading nothing, or everything.
func (f *File) checkDetectorSources() error {
	known := make([]string, len(f.Sources))
	for i, s := range f.Sources {
		known[i] = s.spec.describe().Name
	}
	for di, d := range f.Detectors {
		for _, n := range d.Sources {
			if !slices.Contains(known, n) {
				return fmt.Errorf("detectors[%d] (%s): sources: unknown source %q (defined: %s)", di, d.Type, n, strings.Join(known, ", "))
			}
		}
	}
	return nil
}

// checkSomethingToRun refuses a file whose every source, or every detector, is switched
// off: the run would read nothing, or judge nothing, and say so in a table that looks
// like any other.
func (f *File) checkSomethingToRun() error {
	if len(f.DisabledSources()) == len(f.Sources) {
		return fmt.Errorf("sources: every source has enabled: false (%s); nothing to run. Enable at least one", strings.Join(f.DisabledSources(), ", "))
	}
	if len(f.DisabledDetectors()) == len(f.Detectors) {
		return fmt.Errorf("detectors: every detector has enabled: false (%s); nothing to run. Enable at least one", strings.Join(f.DisabledDetectors(), ", "))
	}
	return nil
}

// checkScopesAreEnabled refuses an enabled detector whose `sources:` names a disabled
// source: it would read nothing from it, and report that as an ordinary empty window.
// A disabled detector may be scoped to anything; it does not run.
func (f *File) checkScopesAreEnabled() error {
	off := map[string]int{}
	for i, s := range f.Sources {
		if s.Disabled {
			off[s.spec.describe().Name] = i
		}
	}
	for di, d := range f.Detectors {
		if d.Disabled {
			continue
		}
		for _, n := range d.Sources {
			if si, ok := off[n]; ok {
				return fmt.Errorf("detectors[%d] (%s, %q): sources: %q is disabled (sources[%d] has enabled: false), so this detector would read nothing from it. Enable the source, take it out of `sources:`, or set enabled: false on the detector",
					di, d.Type, d.DisplayName(), n, si)
			}
		}
	}
	return nil
}

// DisabledSources names the sources switched off with `enabled: false`, in file order.
func (f *File) DisabledSources() []string {
	var out []string
	for _, s := range f.Sources {
		if s.Disabled {
			out = append(out, s.spec.describe().Name)
		}
	}
	return out
}

// DisabledDetectors names the detectors switched off with `enabled: false`, in file order.
func (f *File) DisabledDetectors() []string {
	var out []string
	for _, d := range f.Detectors {
		if d.Disabled {
			out = append(out, d.DisplayName())
		}
	}
	return out
}

// readsSources returns the indexes of the enabled sources a detector reads: its scope,
// or all of them. A disabled source is never read, so it never counts.
func (f *File) readsSources(d DetectorEntry) []int {
	var out []int
	for i, s := range f.Sources {
		if s.Disabled {
			continue
		}
		if d.Sources == nil || slices.Contains(d.Sources, s.spec.describe().Name) {
			out = append(out, i)
		}
	}
	return out
}

// quietCapable is implemented by a detector spec that can treat "no matching event" as a
// quiet answer. That is only safe when no source can be silently empty.
type quietCapable interface{ needsFilteredSources() bool }

// checkQuietNeedsFilters refuses empty_is_quiet unless every source the detector reads
// (its `sources:`, else all of them) is a kibana source with a filter. A filtered source proves its index alive before it returns an empty
// window; an unfiltered one cannot, and for it an empty window means a broken source.
func (f *File) checkQuietNeedsFilters() error {
	for di, d := range f.Detectors {
		q, ok := d.spec.(quietCapable)
		if d.Disabled || !ok || !q.needsFilteredSources() {
			continue
		}
		for _, si := range f.readsSources(d) {
			s := f.Sources[si]
			if ks, ok := s.spec.(kibanaSpec); !ok || len(ks.Filter) == 0 {
				return fmt.Errorf("detectors[%d] (%s): empty_is_quiet needs every source it reads to be a kibana source with a filter; source %q (sources[%d], %s) has none, so an empty window there would read as quiet instead of broken%s",
					di, d.Type, s.spec.describe().Name, si, s.Type, scopeHint(d))
			}
		}
	}
	return nil
}

// fieldReader is implemented by a detector spec whose whole job is one event field. A
// detector that flags a field nothing fills never fires, and a quiet answer would read
// as "nobody sent it": the silent failure this check closes.
type fieldReader interface{ readsField() string }

// checkFieldsAreEmitted refuses a detector whose field is not one the mapper of a source
// it reads can emit. It can only judge a built-in mapper whose output follows from its
// config (request_dump); a source with another mapper is not second-guessed.
func (f *File) checkFieldsAreEmitted() error {
	for di, d := range f.Detectors {
		r, ok := d.spec.(fieldReader)
		if d.Disabled || !ok {
			continue
		}
		for _, si := range f.readsSources(d) {
			ks, ok := f.Sources[si].spec.(kibanaSpec)
			if !ok {
				continue
			}
			emits := kibana.MapperFields(ks.Mapper, ks.MapperConfig)
			if emits == nil || slices.Contains(emits, r.readsField()) {
				continue
			}
			return fmt.Errorf("detectors[%d] (%s): field %q is never emitted by the %s mapper of source %q (sources[%d]); it emits %s. Add it to header_fields, or this detector would stay quiet whatever the log holds",
				di, d.Type, r.readsField(), ks.Mapper, ks.label(), si, strings.Join(emits, ", "))
		}
	}
	return nil
}

// scopeHint tells an unscoped detector that `sources:` can narrow what it reads.
func scopeHint(d DetectorEntry) string {
	if d.Sources != nil {
		return ""
	}
	return " (or list only the sources that have one under `sources:`)"
}

// StorePath is where the evidence database lives.
func (f *File) StorePath() string {
	p := f.Store.Path
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	if p == "" {
		return duckdb.DefaultPath()
	}
	return p
}

// Runtime is what Build produces: the adapters, ready to hand to the use case.
type Runtime struct {
	Sources   []core.Source
	Detectors []core.Detector
	// Scopes maps a detector's name to the source names it reads. A detector without
	// `sources:` has no entry. Hand it to app.Deps.Scopes unchanged.
	Scopes map[string][]string
	// DisabledSources and DisabledDetectors name what the file switched off with
	// `enabled: false`. They were not built; a command that describes the run lists
	// them (DISABLED: ...) so that what was not read is never left to be inferred.
	DisabledSources, DisabledDetectors []string
}

// Close releases what the built sources hold: today, the child process of a plugin
// mapper. Commands call it when they are done (defer), and on an interrupt the context
// ends the fetch first, so no child outlives the run. Safe to call more than once.
func (rt *Runtime) Close() error {
	if rt == nil {
		return nil
	}
	var errs []error
	for _, s := range rt.Sources {
		if c, ok := s.(io.Closer); ok {
			errs = append(errs, c.Close())
		}
	}
	return errors.Join(errs...)
}

// Build constructs every source and detector, reading credentials from env. It
// reports every problem at once. An error never contains a credential value.
func (f *File) Build(env Env) (*Runtime, error) {
	if env == nil {
		env = OSEnv
	}
	var rt Runtime
	var errs []error
	for i, e := range f.Sources {
		if e.Disabled {
			continue // no credential read, no connection, no adapter
		}
		spec := e.spec
		if len(f.search) > 0 {
			sp, ok := spec.(searchable)
			if !ok {
				errs = append(errs, fmt.Errorf("sources[%d] (%s): cannot be searched", i, e.Type))
				continue
			}
			spec = sp.withSearch(f.search, f.searchField)
		}
		s, err := spec.build(env)
		if err != nil {
			errs = append(errs, fmt.Errorf("sources[%d] (%s): %w", i, e.Type, err))
			continue
		}
		rt.Sources = append(rt.Sources, s)
	}
	ds, scopes, derr := f.buildDetectors()
	if derr != nil {
		errs = append(errs, derr)
	}
	rt.Detectors, rt.Scopes = ds, scopes
	rt.DisabledSources, rt.DisabledDetectors = f.DisabledSources(), f.DisabledDetectors()
	if err := errors.Join(errs...); err != nil {
		_ = rt.Close() // a plugin host built before the failure must not be left behind
		return nil, err
	}
	return &rt, nil
}

// BuildDetectors constructs the detectors only. It reads no environment variable, so
// `jb case check` can use it to prove that every case file a detector names loads.
func (f *File) BuildDetectors() ([]core.Detector, error) {
	ds, _, err := f.buildDetectors()
	if err != nil {
		return nil, err
	}
	return ds, nil
}

func (f *File) buildDetectors() ([]core.Detector, map[string][]string, error) {
	var out []core.Detector
	scopes := map[string][]string{}
	var errs []error
	for i, e := range f.Detectors {
		if e.Disabled {
			continue
		}
		d, err := e.spec.build(buildCtx{c: f.caseRef})
		if err != nil {
			errs = append(errs, fmt.Errorf("detectors[%d] (%s): %w", i, e.Type, err))
			continue
		}
		out = append(out, d)
		if e.Sources != nil {
			scopes[d.Name()] = append([]string(nil), e.Sources...)
		}
	}
	return out, scopes, errors.Join(errs...)
}

func strictDecode(data []byte, dst any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	return dec.Decode(dst)
}

// decodeTyped reads the `type:` key of a mapping node, finds its builder and decodes
// the remaining keys strictly into the builder's own struct. yaml.v3 does not apply
// KnownFields inside a custom unmarshaler, so the node is re-encoded and decoded again.
func decodeTyped[T any](kind string, n *yaml.Node, reg map[string]func(*yaml.Node) (T, error)) (string, T, error) {
	var zero T
	if n.Kind != yaml.MappingNode {
		return "", zero, fmt.Errorf("line %d: a %s must be a mapping with a `type:`", n.Line, kind)
	}
	var typ string
	rest := &yaml.Node{Kind: yaml.MappingNode, Tag: n.Tag, Line: n.Line, Column: n.Column}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Value == "type" {
			if v.Kind != yaml.ScalarNode {
				return "", zero, fmt.Errorf("line %d: %s type must be a string", k.Line, kind)
			}
			typ = v.Value
			continue
		}
		rest.Content = append(rest.Content, k, v)
	}
	if typ == "" {
		return "", zero, fmt.Errorf("line %d: %s has no `type:`", n.Line, kind)
	}
	build, ok := reg[typ]
	if !ok {
		known := make([]string, 0, len(reg))
		for k := range reg {
			known = append(known, k)
		}
		sort.Strings(known)
		return "", zero, fmt.Errorf("line %d: unknown %s type %q (known: %s)", n.Line, kind, typ, strings.Join(known, ", "))
	}
	spec, err := build(rest)
	if err != nil {
		return "", zero, fmt.Errorf("%s %q at line %d: %w", kind, typ, n.Line, err)
	}
	return typ, spec, nil
}

// decodeNode strictly decodes a mapping node into dst.
func decodeNode(n *yaml.Node, dst any) error {
	data, err := yaml.Marshal(n)
	if err != nil {
		return err
	}
	return strictDecode(data, dst)
}
