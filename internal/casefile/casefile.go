// Package casefile loads and validates a case directory: the data that defines one
// investigation, kept outside the tool's repository. The format is specified in
// docs/CASE-SPEC.md and schemas/case.schema.json.
//
// The loader is strict. An unknown key, an apiVersion other than APIVersion, a path
// that leaves the case directory, a credential-shaped value, or passive_only set to
// false is an error at Load, before anything reads the case. The package imports the
// standard library and yaml.v3 only; the one subprocess (git check-ignore) lives in
// guard.go.
package casefile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// APIVersion is the only case format this build reads.
const APIVersion = "jb.case/v1"

// FileName is the case file at the root of a case directory.
const FileName = "case.yaml"

// maxFileSize bounds what Load reads; a case file is a few hundred bytes.
const maxFileSize = 1 << 20

// Statuses are the allowed values of status.
var Statuses = []string{"open", "monitoring", "closed"}

// RedactKinds are the allowed values of handling.redact_in_reports.
var RedactKinds = []string{"ip", "email", "hostname", "account_id", "user_agent"}

// RequiredKeys are the top-level keys that must be present.
var RequiredKeys = []string{"apiVersion", "id", "title", "status", "opened"}

// Defaults applied when a key is omitted.
const (
	DefaultClassification = "internal"
	DefaultEvidenceDays   = 90
	DefaultFindingsDays   = 365
	DefaultWindowName     = "default"
	DefaultWindow         = "24h"
	maxRetentionDays      = 3650
)

var (
	idRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	roleRE   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	winName  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	winValue = regexp.MustCompile(`^[1-9][0-9]{0,3}[hd]$`)
	dnsName  = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// Case is a parsed, validated case.yaml. Omitted optional keys hold their defaults
// after Load.
type Case struct {
	APIVersion     string            `yaml:"apiVersion"`
	ID             string            `yaml:"id"`
	Title          string            `yaml:"title"`
	Status         string            `yaml:"status"`
	Opened         string            `yaml:"opened"` // YYYY-MM-DD
	Classification string            `yaml:"classification"`
	Owners         []string          `yaml:"owners"`
	Scope          Scope             `yaml:"scope"`
	Windows        map[string]string `yaml:"windows"`
	Retention      Retention         `yaml:"retention"`
	Paths          Paths             `yaml:"paths"`
	Config         []string          `yaml:"config"`
	Handling       Handling          `yaml:"handling"`

	// Dir is the case directory Load was given. Not part of the file.
	Dir string `yaml:"-"`
}

// Scope names what the case covers. Anything else is out of scope.
type Scope struct {
	Domains []string `yaml:"domains"` // DNS names; a name covers itself and its subdomains
	Hosts   []string `yaml:"hosts"`   // DNS names or IP literals, exact match
	ASNs    []uint32 `yaml:"asns"`
	CIDRs   []string `yaml:"cidrs"`
}

// Retention is how long the case keeps things, in days.
type Retention struct {
	EvidenceDays *int `yaml:"evidence_days"`
	FindingsDays *int `yaml:"findings_days"`
}

// Paths are case-relative directories. Each must stay inside the case directory.
type Paths struct {
	Assets   string `yaml:"assets"`
	Actors   string `yaml:"actors"`
	Estate   string `yaml:"estate"`
	Notes    string `yaml:"notes"`
	Reports  string `yaml:"reports"`
	Evidence string `yaml:"evidence"`
}

// Handling holds the rules for how the case is worked.
type Handling struct {
	// PassiveOnly defaults to true and cannot be false in v1.
	PassiveOnly     *bool    `yaml:"passive_only"`
	RedactInReports []string `yaml:"redact_in_reports"`
}

// EvidenceDir is the absolute evidence directory. Pass it to Guard.
func (c *Case) EvidenceDir() string {
	return filepath.Join(c.Dir, filepath.FromSlash(c.Paths.Evidence))
}

// Load reads, strictly decodes, defaults and validates dir/case.yaml. It does not
// run git: call Guard on EvidenceDir before putting evidence there.
func Load(dir string) (*Case, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	root, err := realRoot(abs)
	if err != nil {
		return nil, err
	}
	file, err := resolveInside(root, FileName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	fh, err := os.Open(file) // #nosec G304 -- confined by resolveInside
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", FileName, err)
	}
	defer fh.Close()
	if st, err := fh.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", FileName)
	}
	data, err := io.ReadAll(io.LimitReader(fh, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", FileName, err)
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", FileName, maxFileSize)
	}
	c, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	c.Dir = abs
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	return c, nil
}

// Parse decodes YAML bytes into a defaulted Case without touching the filesystem.
// It checks apiVersion first, so a file written for a later version reports the
// version rather than whatever key that version added.
func Parse(data []byte) (*Case, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("file is empty")
	}
	if err := CheckYAMLShape("case file", data); err != nil {
		return nil, err
	}
	var probe struct {
		APIVersion string `yaml:"apiVersion"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	switch probe.APIVersion {
	case APIVersion:
	case "":
		return nil, fmt.Errorf("apiVersion is required (this build reads %s)", APIVersion)
	default:
		return nil, fmt.Errorf("unsupported apiVersion %q: this build reads only %s", probe.APIVersion, APIVersion)
	}
	var keys map[string]any
	if err := yaml.Unmarshal(data, &keys); err != nil {
		return nil, err
	}
	for _, k := range RequiredKeys {
		if v, ok := keys[k]; !ok || v == nil {
			return nil, fmt.Errorf("missing required key %q", k)
		}
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if err := scanCredentials(&root); err != nil {
		return nil, err
	}
	var c Case
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		if strings.Contains(err.Error(), "not found in type") {
			return nil, fmt.Errorf("unknown key (rejected, not ignored): %w", err)
		}
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one YAML document")
	}
	c.applyDefaults()
	return &c, nil
}

func (c *Case) applyDefaults() {
	if c.Classification == "" {
		c.Classification = DefaultClassification
	}
	if c.Windows == nil {
		c.Windows = map[string]string{DefaultWindowName: DefaultWindow}
	}
	if c.Retention.EvidenceDays == nil {
		c.Retention.EvidenceDays = ptr(DefaultEvidenceDays)
	}
	if c.Retention.FindingsDays == nil {
		c.Retention.FindingsDays = ptr(DefaultFindingsDays)
	}
	for p, d := range map[*string]string{
		&c.Paths.Assets: "assets", &c.Paths.Actors: "actors", &c.Paths.Estate: "estate", &c.Paths.Notes: "notes",
		&c.Paths.Reports: "reports", &c.Paths.Evidence: "evidence",
	} {
		if *p == "" {
			*p = d
		}
	}
	if c.Handling.PassiveOnly == nil {
		c.Handling.PassiveOnly = ptr(true)
	}
	if c.Handling.RedactInReports == nil {
		c.Handling.RedactInReports = []string{"email"}
	}
}

func ptr[T any](v T) *T { return &v }

// Validate checks every rule that needs more than decoding. It needs Dir, because
// path confinement is a question about the filesystem. It reports all problems.
func (c *Case) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.APIVersion != APIVersion {
		bad("apiVersion must be %s", APIVersion)
	}
	if !idRE.MatchString(c.ID) {
		bad("id %q must match %s", c.ID, idRE)
	}
	if t := strings.TrimSpace(c.Title); t == "" || len(c.Title) > 200 || strings.ContainsAny(c.Title, "\r\n") {
		bad("title must be one line of 1 to 200 bytes")
	}
	if !slices.Contains(Statuses, c.Status) {
		bad("status %q must be one of %s", c.Status, strings.Join(Statuses, ", "))
	}
	if _, err := time.Parse("2006-01-02", c.Opened); err != nil {
		bad("opened %q must be a date, YYYY-MM-DD", c.Opened)
	}
	if c.Classification == "" || len(c.Classification) > 64 || strings.ContainsAny(c.Classification, "\r\n") {
		bad("classification must be one line of 1 to 64 bytes")
	}
	for i, o := range c.Owners {
		if !roleRE.MatchString(o) {
			bad("owners[%d] must be a role name matching %s (no emails, no personal names)", i, roleRE)
		}
	}
	errs = append(errs, c.Scope.validate()...)
	for name, v := range c.Windows {
		if !winName.MatchString(name) {
			bad("windows: name %q must match %s", name, winName)
		}
		if !winValue.MatchString(v) {
			bad("windows.%s: %q must be a number of hours or days, such as 24h or 7d", name, v)
		}
	}
	for name, d := range map[string]*int{"evidence_days": c.Retention.EvidenceDays, "findings_days": c.Retention.FindingsDays} {
		if d == nil || *d < 1 || *d > maxRetentionDays {
			bad("retention.%s must be 1 to %d", name, maxRetentionDays)
		}
	}
	if c.Handling.PassiveOnly == nil || !*c.Handling.PassiveOnly {
		bad("handling.passive_only cannot be false in %s: active probing of third-party hosts is not a case setting", APIVersion)
	}
	seen := map[string]bool{}
	for i, k := range c.Handling.RedactInReports {
		if !slices.Contains(RedactKinds, k) {
			bad("handling.redact_in_reports[%d] %q must be one of %s", i, k, strings.Join(RedactKinds, ", "))
		}
		if seen[k] {
			bad("handling.redact_in_reports lists %q twice", k)
		}
		seen[k] = true
	}
	errs = append(errs, c.validatePaths()...)
	return errors.Join(errs...)
}

func (s Scope) validate() []error {
	var errs []error
	for i, d := range s.Domains {
		if !dnsName.MatchString(d) {
			errs = append(errs, fmt.Errorf("scope.domains[%d] %q must be a lower-case DNS name", i, d))
		}
	}
	for i, h := range s.Hosts {
		if !dnsName.MatchString(h) && !isIP(h) {
			errs = append(errs, fmt.Errorf("scope.hosts[%d] %q must be a lower-case DNS name or an IP literal", i, h))
		}
	}
	for i, a := range s.ASNs {
		if a == 0 {
			errs = append(errs, fmt.Errorf("scope.asns[%d] must be 1 or more", i))
		}
	}
	for i, c := range s.CIDRs {
		if !isCIDR(c) {
			errs = append(errs, fmt.Errorf("scope.cidrs[%d] %q must be a CIDR such as 192.0.2.0/24", i, c))
		}
	}
	return errs
}

func (c *Case) validatePaths() []error {
	var errs []error
	if c.Dir == "" {
		return []error{errors.New("Dir is not set: paths cannot be checked")}
	}
	root, err := realRoot(c.Dir)
	if err != nil {
		return []error{err}
	}
	sections := []struct{ name, rel string }{
		{"assets", c.Paths.Assets}, {"actors", c.Paths.Actors}, {"estate", c.Paths.Estate}, {"notes", c.Paths.Notes},
		{"reports", c.Paths.Reports}, {"evidence", c.Paths.Evidence},
	}
	seen := map[string]string{}
	for _, s := range sections {
		if _, err := resolveInside(root, s.rel); err != nil {
			errs = append(errs, fmt.Errorf("paths.%s: %w", s.name, err))
			continue
		}
		key := filepath.ToSlash(filepath.Clean(s.rel))
		if other, dup := seen[key]; dup {
			errs = append(errs, fmt.Errorf("paths.%s and paths.%s are both %q: each section needs its own directory", s.name, other, s.rel))
		}
		seen[key] = s.name
	}
	for i, rel := range c.Config {
		real, err := resolveInside(root, rel)
		if err != nil {
			errs = append(errs, fmt.Errorf("config[%d]: %w", i, err))
			continue
		}
		if st, err := os.Stat(real); err != nil || !st.Mode().IsRegular() {
			errs = append(errs, fmt.Errorf("config[%d] %q is not an existing regular file", i, rel))
		}
	}
	return errs
}
