package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/iksnerd/json-bourne/internal/adapters/kibana"
	"github.com/iksnerd/json-bourne/internal/adapters/plugin"
	"github.com/iksnerd/json-bourne/internal/core"
)

// envName is deliberately narrow: upper-case letters, digits, underscore. A pasted
// API key usually carries lower-case letters or '=', and is refused here instead of
// being echoed back in a "variable not set" error.
var envName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

type kibanaSpec struct {
	URL       string `yaml:"url"`
	APIKeyEnv string `yaml:"api_key_env"`
	Index     string `yaml:"index"`
	// Name labels the source in events, run ids and output. Default "kibana:<index>".
	// Set it to put two sources on one index.
	Name      string `yaml:"name"`
	TimeField string `yaml:"time_field"`
	PageSize  int    `yaml:"page_size"`
	Mapper    string `yaml:"mapper"`
	// MapperConfig is handed to a plugin mapper as data on every request. It is only
	// valid with `mapper: plugin:<name>`; it can never name a path, a command or an
	// allowlist entry, because the plugin is chosen by name from the operator's own list.
	MapperConfig map[string]any `yaml:"mapper_config"`
	// Filter narrows the query on the server. Every clause must match (AND). Without it
	// the source downloads every document in the window.
	Filter []filterClause `yaml:"filter"`
	// SearchField is the field `jb hunt --search` matches a term against. Default "message".
	SearchField string `yaml:"search_field"`
	// KeyMatch says which raw field of the index holds a key and how it is matched, so a
	// newkey detector with a `history` block can count a key's events there (RFC 0014).
	KeyMatch *keyMatchSpec `yaml:"key_match"`

	// search is the ad-hoc terms of one run, set by File.WithSearch and never by the file.
	search      []string
	searchField string // the run's override of SearchField; empty keeps SearchField
}

// keyMatchSpec is `key_match`: the field of the index that holds the key, and whether the
// key is an exact keyword value (term) or a phrase in analysed text (phrase). The mode has
// no default: the wrong one returns zero for every key, or over-counts.
type keyMatchSpec struct {
	Field string `yaml:"field"`
	Mode  string `yaml:"mode"`
}

func (k *keyMatchSpec) validate() error {
	if k == nil {
		return nil
	}
	if !filterField.MatchString(k.Field) {
		return errors.New("key_match.field is required: 1-128 characters of letters, digits, _ @ . -")
	}
	if k.Mode != kibana.ModeTerm && k.Mode != kibana.ModePhrase {
		return fmt.Errorf("key_match.mode is required and must be %s (exact value in a keyword field) or %s (the key as a phrase in an analysed field); there is no default", kibana.ModeTerm, kibana.ModePhrase)
	}
	return nil
}

// filterClause is exactly one of match_phrase (analysed text, such as a log line), term
// (an exact keyword value) or any_of (at least one of 2 to 16 plain match_phrase / term
// members). any_of does not nest. Anything richer is deliberately not expressible here:
// the config is data a case carries around, not a query language.
type filterClause struct {
	MatchPhrase *filterMatch   `yaml:"match_phrase"`
	Term        *filterMatch   `yaml:"term"`
	AnyOf       []filterMember `yaml:"any_of"`
}

// filterMember is one alternative inside any_of: a plain match clause, never another any_of.
type filterMember struct {
	MatchPhrase *filterMatch `yaml:"match_phrase"`
	Term        *filterMatch `yaml:"term"`
}

type filterMatch struct {
	Field string `yaml:"field"`
	Value string `yaml:"value"`
}

const (
	// maxFilterClauses bounds the entries of a source's filter list. An any_of is one
	// entry however many members it has, so it counts as one clause; `jb hunt --search`
	// terms count against the same bound.
	maxFilterClauses = 8
	maxFilterValue   = 512
	minAnyOf         = 2
	maxAnyOf         = 16
	// maxFilterLeaves bounds the match clauses of a whole filter, plain ones and any_of
	// members together, so eight any_of of 16 cannot send a 128-clause query.
	maxFilterLeaves = 64
)

var sourceName = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,63}$`)

// label is the name the source reports: the configured name, else kibana:<index>.
func (s kibanaSpec) label() string {
	if s.Name != "" {
		return s.Name
	}
	return "kibana:" + s.Index
}

func validateMatch(where string, m *filterMatch) error {
	if !filterField.MatchString(m.Field) {
		return fmt.Errorf("%s: field must be 1-128 characters of letters, digits, _ @ . -", where)
	}
	if m.Value == "" || len(m.Value) > maxFilterValue {
		return fmt.Errorf("%s: value must be 1-%d characters", where, maxFilterValue)
	}
	for _, r := range m.Value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("%s: value must not contain control or format characters", where)
		}
	}
	return nil
}

var filterField = regexp.MustCompile(`^[A-Za-z0-9_@.-]{1,128}$`)

func (s kibanaSpec) validateFilter() error {
	if s.Filter == nil {
		return nil
	}
	if len(s.Filter) == 0 {
		return errors.New("filter: an empty list; remove the key or add a clause")
	}
	if len(s.Filter) > maxFilterClauses {
		return fmt.Errorf("filter: %d clauses, at most %d", len(s.Filter), maxFilterClauses)
	}
	leaves := 0
	for i, c := range s.Filter {
		where := fmt.Sprintf("filter[%d]", i)
		n := 0
		for _, set := range []bool{c.MatchPhrase != nil, c.Term != nil, c.AnyOf != nil} {
			if set {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("%s: exactly one of match_phrase, term or any_of", where)
		}
		if c.AnyOf != nil {
			if len(c.AnyOf) < minAnyOf || len(c.AnyOf) > maxAnyOf {
				return fmt.Errorf("%s: any_of has %d members, needs %d to %d", where, len(c.AnyOf), minAnyOf, maxAnyOf)
			}
			for j, mem := range c.AnyOf {
				mw := fmt.Sprintf("%s.any_of[%d]", where, j)
				if (mem.MatchPhrase == nil) == (mem.Term == nil) {
					return fmt.Errorf("%s: exactly one of match_phrase or term (any_of does not nest)", mw)
				}
				m := mem.MatchPhrase
				if m == nil {
					m = mem.Term
				}
				if err := validateMatch(mw, m); err != nil {
					return err
				}
				leaves++
			}
			continue
		}
		m := c.MatchPhrase
		if m == nil {
			m = c.Term
		}
		if err := validateMatch(where, m); err != nil {
			return err
		}
		leaves++
	}
	if leaves > maxFilterLeaves {
		return fmt.Errorf("filter: %d match clauses in all (any_of members included), at most %d", leaves, maxFilterLeaves)
	}
	return nil
}

// query is the ES clause ANDed with the window filter, or nil for no filter. The
// configured filter and the run's search terms are all ANDed, each as a match_phrase or
// term clause whose value is a JSON string: a term is data in the request body and is
// never spliced into query text.
func (s kibanaSpec) query() map[string]any {
	if len(s.Filter) == 0 && len(s.search) == 0 {
		return nil
	}
	clauses := make([]any, 0, len(s.Filter)+len(s.search))
	field := s.searchField
	if field == "" {
		field = s.SearchField
	}
	if field == "" {
		field = DefaultSearchField
	}
	for _, t := range s.search {
		clauses = append(clauses, map[string]any{"match_phrase": map[string]any{field: t}})
	}
	for _, c := range s.Filter {
		if c.AnyOf != nil {
			should := make([]any, 0, len(c.AnyOf))
			for _, m := range c.AnyOf {
				should = append(should, matchClause(m.MatchPhrase, m.Term))
			}
			clauses = append(clauses, map[string]any{"bool": map[string]any{"should": should, "minimum_should_match": 1}})
			continue
		}
		clauses = append(clauses, matchClause(c.MatchPhrase, c.Term))
	}
	return map[string]any{"bool": map[string]any{"filter": clauses}}
}

// matchClause is the ES clause of one plain member; the value is a JSON string in the body.
func matchClause(phrase, term *filterMatch) map[string]any {
	if phrase != nil {
		return map[string]any{"match_phrase": map[string]any{phrase.Field: phrase.Value}}
	}
	return map[string]any{"term": map[string]any{term.Field: term.Value}}
}

func registerKibana(m map[string]func(*yaml.Node) (sourceSpec, error)) {
	m["kibana"] = func(n *yaml.Node) (sourceSpec, error) {
		var s kibanaSpec
		if err := decodeNode(n, &s); err != nil {
			return nil, err
		}
		if err := s.validate(); err != nil {
			return nil, err
		}
		return s, nil
	}
}

// withSearch returns the spec narrowed by terms (already validated) on field, or on the
// spec's search_field when field is empty.
func (s kibanaSpec) withSearch(terms []string, field string) sourceSpec {
	s.search = append([]string(nil), terms...)
	s.searchField = field
	return s
}

func (s kibanaSpec) validate() error {
	if s.SearchField != "" && !filterField.MatchString(s.SearchField) {
		return errors.New("search_field must be 1-128 characters of letters, digits, _ @ . -")
	}
	if s.Index == "" {
		return errors.New("index is required")
	}
	if s.Name != "" && !sourceName.MatchString(s.Name) {
		return errors.New("name must match ^[a-z][a-z0-9_.:-]{0,63}$ (lower case, no slash)")
	}
	if s.PageSize < 0 || s.PageSize > kibana.MaxPageSize {
		return fmt.Errorf("page_size %d outside 0..%d", s.PageSize, kibana.MaxPageSize)
	}
	if err := s.validateFilter(); err != nil {
		return err
	}
	if err := s.KeyMatch.validate(); err != nil {
		return err
	}
	if err := s.validateMapper(); err != nil {
		return err
	}
	if !envName.MatchString(s.APIKeyEnv) {
		return errors.New("api_key_env must name an environment variable (upper-case letters, digits, underscore); put the variable's name here, never the key")
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Host == "" {
		return errors.New("url must be an absolute https URL")
	}
	// The key travels in a header; refuse to send it in clear except to this machine.
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return errors.New("url must use https (http is allowed for loopback only)")
	}
	if u.User != nil {
		return errors.New("url must not carry credentials")
	}
	return nil
}

// pluginPrefix marks a mapper that is an allowlisted plugin, by name.
const pluginPrefix = "plugin:"

// PluginAllowlist loads the operator's plugin allowlist. It reads jb's own location
// ($JB_PLUGINS_FILE, else ~/.jb/plugins.yaml), never anything a case carries. It is a
// variable so tests can point it elsewhere.
var PluginAllowlist = func() (*plugin.Allowlist, error) {
	p, err := plugin.AllowlistPath(OSEnv)
	if err != nil {
		return nil, err
	}
	return plugin.LoadAllowlist(p)
}

// pluginName returns the plugin a mapper value names.
func pluginName(mapper string) (string, bool) { return strings.CutPrefix(mapper, pluginPrefix) }

func (s kibanaSpec) validateMapper() error {
	name, isPlugin := pluginName(s.Mapper)
	if !isPlugin {
		if s.Mapper == "" && s.MapperConfig != nil {
			return errors.New("mapper_config is only valid with mapper: plugin:<name> or a mapper that takes one (" + strings.Join(kibana.ConfigurableMapperNames(), ", ") + ")")
		}
		if s.Mapper != "" {
			if _, ok := kibana.LookupMapper(s.Mapper); !ok {
				return fmt.Errorf("unknown mapper %q (known: %s, or plugin:<name> for an allowlisted plugin)", s.Mapper, strings.Join(kibana.MapperNames(), ", "))
			}
			if s.MapperConfig != nil {
				if b, err := json.Marshal(s.MapperConfig); err != nil {
					return fmt.Errorf("mapper_config must be plain data (string keys, no anchors to code): %v", err)
				} else if len(b) > 64<<10 {
					return fmt.Errorf("mapper_config is %d bytes, at most %d", len(b), 64<<10)
				}
			}
			if _, err := kibana.NewMapper(s.Mapper, s.MapperConfig); err != nil {
				return fmt.Errorf("mapper %q: %v", s.Mapper, err)
			}
		}
		return nil
	}
	// The value after "plugin:" is a name and nothing else. A path, a command line or
	// a flag cannot match the name pattern, so a case cannot smuggle one in here.
	if !plugin.NamePattern.MatchString(name) {
		return fmt.Errorf("mapper %q: a plugin is named like acme.kvlines (dotted, lower case); a case cannot give a path or a command", s.Mapper)
	}
	if s.MapperConfig != nil {
		b, err := json.Marshal(s.MapperConfig)
		if err != nil {
			return fmt.Errorf("mapper_config must be plain data (string keys, no anchors to code): %v", err)
		}
		if len(b) > 64<<10 {
			return fmt.Errorf("mapper_config is %d bytes, at most %d", len(b), 64<<10)
		}
	}
	al, err := PluginAllowlist()
	if err != nil {
		return fmt.Errorf("mapper %q: %v", s.Mapper, err)
	}
	if _, err := al.Lookup(name); err != nil {
		return fmt.Errorf("mapper %q: %v", s.Mapper, err)
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s kibanaSpec) build(env Env) (core.Source, error) {
	key, ok := env(s.APIKeyEnv)
	if !ok || key == "" {
		return nil, errEnvNotSet(s.APIKeyEnv)
	}
	src := &kibana.Source{
		Client:    kibana.New(s.URL, key),
		Index:     s.Index,
		Label:     s.Name,
		TimeField: s.TimeField,
		PageSize:  s.PageSize,
		Query:     s.query(),
	}
	if s.KeyMatch != nil {
		src.KeyMatch = &kibana.KeyMatch{Field: s.KeyMatch.Field, Mode: s.KeyMatch.Mode}
	}
	if name, isPlugin := pluginName(s.Mapper); isPlugin {
		al, err := PluginAllowlist()
		if err != nil {
			return nil, err
		}
		entry, err := al.Lookup(name)
		if err != nil {
			return nil, err
		}
		// One host, so one child process, per source per run. Runtime.Close ends it.
		h, err := plugin.NewHost(plugin.Options{Entry: entry, Config: s.MapperConfig, Env: env})
		if err != nil {
			return nil, err
		}
		src.Batch = h
	} else if s.Mapper != "" { // empty keeps the source's own default
		m, err := kibana.NewMapper(s.Mapper, s.MapperConfig) // validated at load
		if err != nil {
			return nil, fmt.Errorf("mapper %q: %v", s.Mapper, err)
		}
		src.Map = m
	}
	return src, nil
}

func (s kibanaSpec) describe() ServiceInfo {
	host := hostOf(s.URL)
	leaves := "the search query (index, window, filter) and the API key, to " + host
	if name, ok := pluginName(s.Mapper); ok {
		leaves += "; every fetched document, to the local plugin " + name + " (a child process on this machine; jb grants it no network but does not enforce that)"
	}
	if s.KeyMatch != nil {
		leaves += "; with a newkey `history` block, candidate keys (the values of its key_field, such as client addresses) in the body of a count request, to " + host
	}
	return ServiceInfo{Kind: "source", Type: "kibana", Name: s.label(), Enabled: true, EnvVars: []string{s.APIKeyEnv}, Host: hostPort(s.URL), Leaves: leaves}
}
