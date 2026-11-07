package casefile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ActorAPIVersion is the only actor file format this build reads. The format is
// specified in docs/CASE-SPEC.md section 4.4 and schemas/actor.schema.json.
const ActorAPIVersion = "jb.actor/v1"

// ActorRequiredKeys are the top-level keys that must be present.
var ActorRequiredKeys = []string{"apiVersion", "id", "label", "confidence", "indicators"}

// IndicatorRequiredKeys are the keys every indicator must carry.
var IndicatorRequiredKeys = []string{"kind", "value"}

// Confidences are the allowed values of confidence.
var Confidences = []string{"low", "medium", "high"}

// IndicatorKinds are the allowed values of an indicator's kind.
var IndicatorKinds = []string{"ip", "asn", "user_agent", "domain", "fingerprint"}

const (
	maxIndicators   = 1000
	maxDetectionLen = 200 // entries in noise_paths or grant_paths
	maxUserAgent    = 1024
	maxMarker       = 256
	maxFingerprint  = 512
)

var (
	typeRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	methodRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// Scalar is a YAML scalar kept as the text written in the file. A fingerprint such
// as a run of 62 digits is a number to YAML; read as one it would be rewritten.
type Scalar string

// UnmarshalYAML keeps the source text of a scalar and refuses anything else.
func (s *Scalar) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		return fmt.Errorf("line %d: value must be a single scalar", n.Line)
	}
	*s = Scalar(n.Value)
	return nil
}

// Actor is a parsed, validated jb.actor/v1 file.
type Actor struct {
	APIVersion string      `yaml:"apiVersion"`
	ID         string      `yaml:"id"`
	Label      string      `yaml:"label"`
	Confidence string      `yaml:"confidence"`
	Indicators []Indicator `yaml:"indicators"`
	Detection  Detection   `yaml:"detection"`
}

// Indicator is one observation about an actor. An address is an observation, not an
// identity: nothing matches on an ip indicator.
type Indicator struct {
	Kind      string `yaml:"kind"`
	Value     Scalar `yaml:"value"`
	FirstSeen string `yaml:"first_seen"` // YYYY-MM-DD
	Note      string `yaml:"note"`
	// Fingerprint only. Two fingerprints taken by different methods must not be compared.
	Type        string `yaml:"type"`
	Method      string `yaml:"method"`
	ProbeTarget string `yaml:"probe_target"`
}

// Detection is how the fingerprint detector tells the actor from noise that shares
// its user agent.
type Detection struct {
	// NoisePaths are case-insensitive substring markers of commodity-scanner traffic.
	NoisePaths []string `yaml:"noise_paths"`
	// BareRoot4xxNoise: a 4xx on "/" is a scanner probe. Absent means true.
	BareRoot4xxNoise *bool `yaml:"bare_root_4xx_is_noise"`
	// GrantPaths are case-insensitive substrings of a token endpoint's path.
	GrantPaths []string `yaml:"grant_paths"`
}

// UserAgents lists the values of the user_agent indicators, in file order.
func (a *Actor) UserAgents() []string {
	var out []string
	for _, i := range a.Indicators {
		if i.Kind == "user_agent" {
			out = append(out, string(i.Value))
		}
	}
	return out
}

// BareRoot4xxIsNoise is the rule with its default applied: true unless the file says false.
func (a *Actor) BareRoot4xxIsNoise() bool {
	return a.Detection.BareRoot4xxNoise == nil || *a.Detection.BareRoot4xxNoise
}

// ParseActor decodes and validates one actor file without touching the filesystem.
// It checks apiVersion first, so a file written for a later version reports the
// version rather than whatever key that version added.
func ParseActor(data []byte) (*Actor, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("file is empty")
	}
	var probe struct {
		APIVersion string `yaml:"apiVersion"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	switch probe.APIVersion {
	case ActorAPIVersion:
	case "":
		return nil, fmt.Errorf("apiVersion is required (this build reads %s)", ActorAPIVersion)
	default:
		return nil, fmt.Errorf("unsupported apiVersion %q: this build reads only %s", probe.APIVersion, ActorAPIVersion)
	}
	var keys map[string]any
	if err := yaml.Unmarshal(data, &keys); err != nil {
		return nil, err
	}
	for _, k := range ActorRequiredKeys {
		if v, ok := keys[k]; !ok || v == nil {
			return nil, fmt.Errorf("missing required key %q", k)
		}
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if err := scanActorCredentials(&root); err != nil {
		return nil, err
	}
	var a Actor
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&a); err != nil {
		if strings.Contains(err.Error(), "not found in type") {
			return nil, fmt.Errorf("unknown key (rejected, not ignored): %w", err)
		}
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one YAML document")
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

// scanActorCredentials is scanCredentials with one exemption: the value of a
// fingerprint indicator. A JARM hash is 62 hex characters and would be refused as a
// key. Every other string, including a fingerprint's note, is still scanned.
func scanActorCredentials(doc *yaml.Node) error {
	root := doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return errors.New("an actor file must be a mapping")
	}
	sc := newScanner() // one budget for the whole file
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, val := root.Content[i].Value, root.Content[i+1]
		if key != "indicators" || val.Kind != yaml.SequenceNode {
			if err := sc.walk(val, key, 1); err != nil {
				return err
			}
			continue
		}
		for j, item := range val.Content {
			path := fmt.Sprintf("indicators[%d]", j)
			if item.Kind != yaml.MappingNode {
				if err := sc.walk(item, path, 2); err != nil {
					return err
				}
				continue
			}
			isFingerprint := false
			for k := 0; k+1 < len(item.Content); k += 2 {
				if item.Content[k].Value == "kind" && item.Content[k+1].Value == "fingerprint" {
					isFingerprint = true
				}
			}
			for k := 0; k+1 < len(item.Content); k += 2 {
				field := item.Content[k].Value
				if isFingerprint && field == "value" {
					continue
				}
				if err := sc.walk(item.Content[k+1], path+"."+field, 3); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func oneLine(s string, max int) bool {
	return s != "" && len(s) <= max && !strings.ContainsAny(s, "\r\n")
}

func (a *Actor) validate() error {
	var errs []error
	bad := func(format string, v ...any) { errs = append(errs, fmt.Errorf(format, v...)) }

	if a.APIVersion != ActorAPIVersion {
		bad("apiVersion must be %s", ActorAPIVersion)
	}
	if !idRE.MatchString(a.ID) {
		bad("id %q must match %s", a.ID, idRE)
	}
	if !oneLine(strings.TrimSpace(a.Label), 200) || len(a.Label) > 200 {
		bad("label must be one line of 1 to 200 bytes")
	}
	if !slices.Contains(Confidences, a.Confidence) {
		bad("confidence %q must be one of %s", a.Confidence, strings.Join(Confidences, ", "))
	}
	if n := len(a.Indicators); n < 1 || n > maxIndicators {
		bad("indicators must hold 1 to %d entries, has %d", maxIndicators, n)
	}
	seen := map[string]int{}
	for i, ind := range a.Indicators {
		if i >= maxIndicators {
			break
		}
		for _, e := range ind.validate() {
			bad("indicators[%d]: %v", i, e)
		}
		key := ind.Kind + "\x00" + string(ind.Value) + "\x00" + ind.Method
		if j, dup := seen[key]; dup {
			bad("indicators[%d] repeats indicators[%d] (%s)", i, j, ind.Kind)
		}
		seen[key] = i
	}
	errs = append(errs, a.Detection.validate()...)
	return errors.Join(errs...)
}

func (i Indicator) validate() []error {
	var errs []error
	bad := func(format string, v ...any) { errs = append(errs, fmt.Errorf(format, v...)) }
	v := string(i.Value)

	if !slices.Contains(IndicatorKinds, i.Kind) {
		bad("kind %q must be one of %s", i.Kind, strings.Join(IndicatorKinds, ", "))
		return errs
	}
	if i.FirstSeen != "" {
		if _, err := time.Parse("2006-01-02", i.FirstSeen); err != nil {
			bad("first_seen %q must be a date, YYYY-MM-DD", i.FirstSeen)
		}
	}
	if i.Note != "" && !oneLine(i.Note, 300) {
		bad("note must be one line of up to 300 bytes")
	}
	if i.Kind != "fingerprint" && (i.Type != "" || i.Method != "" || i.ProbeTarget != "") {
		bad("type, method and probe_target belong to a fingerprint, not a %s", i.Kind)
	}
	switch i.Kind {
	case "ip":
		if !isIP(v) {
			bad("value must be an IP address in canonical form; a CIDR or a zoned address is not an identity")
		}
	case "asn":
		if n, err := strconv.ParseUint(v, 10, 32); err != nil || n == 0 || strconv.FormatUint(n, 10) != v {
			bad("value must be an AS number from 1 to 4294967295, digits only")
		}
	case "domain":
		if !dnsName.MatchString(v) {
			bad("value must be a lower-case DNS name")
		}
	case "user_agent":
		switch {
		case v == "" || len(v) > maxUserAgent:
			bad("value must be 1 to %d bytes", maxUserAgent)
		case strings.TrimSpace(v) != v:
			// The detector compares the whole string. A stray space would never match,
			// and an actor that never matches looks like a clean network.
			bad("value must not start or end with a space: it is compared in full")
		case strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }):
			bad("value contains a control character")
		}
	case "fingerprint":
		if v == "" || len(v) > maxFingerprint || strings.ContainsFunc(v, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
			bad("value must be 1 to %d bytes with no whitespace", maxFingerprint)
		}
		if !typeRE.MatchString(i.Type) {
			bad("a fingerprint must name its type (jarm, ja3, ...), matching %s", typeRE)
		}
		if !methodRE.MatchString(i.Method) {
			bad("a fingerprint must name its method (how it was probed), matching %s: fingerprints taken by different methods cannot be compared", methodRE)
		}
		if i.ProbeTarget != "" && !oneLine(i.ProbeTarget, 255) {
			bad("probe_target must be one line of up to 255 bytes")
		}
	}
	return errs
}

// validate checks shape only. fingerprint.New re-checks the same bounds and the
// cross-rule (a grant path must not contain a noise marker) when a detector is built,
// which `jb case check` does for every config.
func (d Detection) validate() []error {
	var errs []error
	if len(d.NoisePaths) > maxDetectionLen || len(d.GrantPaths) > maxDetectionLen {
		errs = append(errs, fmt.Errorf("detection: noise_paths and grant_paths hold at most %d entries each", maxDetectionLen))
		return errs
	}
	for i, m := range d.NoisePaths {
		// A one-character marker such as "/" would call every path noise.
		if strings.TrimSpace(m) != m || len(m) < 2 || len(m) > maxMarker || strings.ContainsAny(m, "\r\n") {
			errs = append(errs, fmt.Errorf("detection.noise_paths[%d] %q must be 2 to %d bytes with no surrounding space", i, m, maxMarker))
		}
	}
	for i, g := range d.GrantPaths {
		if !strings.HasPrefix(g, "/") || len(g) > maxMarker || strings.ContainsAny(g, "? \t\r\n") {
			errs = append(errs, fmt.Errorf("detection.grant_paths[%d] %q must start with / and carry no query string", i, g))
		}
	}
	return errs
}

// actorFile reports whether a file name is read as an actor file.
func actorFile(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

// ValidActorName checks an actor file name the way LoadActorFile does before it
// touches the filesystem, so a bad name in a config fails when the config loads.
func ValidActorName(name string) error {
	if err := lexical(name); err != nil {
		return fmt.Errorf("actor file %q: %w", name, err)
	}
	if !actorFile(name) {
		return fmt.Errorf("actor file %q: must end in .yaml or .yml", name)
	}
	return nil
}

// LoadActorFile reads one actor file. name is relative to the case's actors directory
// (paths.actors): it must be a .yaml or .yml file, must not leave that directory, by
// `..` or by a symlink, and is at most 1 MiB.
func LoadActorFile(c *Case, name string) (*Actor, error) {
	if err := ValidActorName(name); err != nil {
		return nil, err
	}
	if c.Dir == "" {
		return nil, errors.New("Dir is not set: paths cannot be checked")
	}
	root, err := realRoot(c.Dir)
	if err != nil {
		return nil, err
	}
	dir, err := resolveInside(root, c.Paths.Actors)
	if err != nil {
		return nil, fmt.Errorf("paths.actors: %w", err)
	}
	file, err := resolveInside(root, path.Join(c.Paths.Actors, name))
	if err != nil {
		return nil, fmt.Errorf("actor file %q: %w", name, err)
	}
	if !within(dir, file) {
		return nil, fmt.Errorf("actor file %q resolves outside the actors directory %q", name, c.Paths.Actors)
	}
	fh, err := os.Open(file) // #nosec G304 -- confined by resolveInside and the actors directory check
	if err != nil {
		return nil, fmt.Errorf("actor file %q: %w", name, err)
	}
	defer fh.Close()
	if st, err := fh.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("actor file %q is not a regular file", name)
	}
	data, err := io.ReadAll(io.LimitReader(fh, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read actor file %q: %w", name, err)
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("actor file %q is larger than %d bytes", name, maxFileSize)
	}
	a, err := ParseActor(data)
	if err != nil {
		return nil, fmt.Errorf("actor file %q: %w", name, err)
	}
	return a, nil
}

// LoadActors reads every .yaml and .yml file directly inside the actors directory, in
// name order. A missing directory means no actors. Other files are not actor files and
// are left alone. Every broken file is reported, and so is an id used by two files.
func LoadActors(c *Case) ([]*Actor, error) {
	if c.Dir == "" {
		return nil, errors.New("Dir is not set: paths cannot be checked")
	}
	root, err := realRoot(c.Dir)
	if err != nil {
		return nil, err
	}
	dir, err := resolveInside(root, c.Paths.Actors)
	if err != nil {
		return nil, fmt.Errorf("paths.actors: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read actors directory: %w", err)
	}
	var out []*Actor
	var errs []error
	from := map[string]string{}
	for _, e := range entries {
		if !actorFile(e.Name()) {
			continue
		}
		a, err := LoadActorFile(c, e.Name())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if other, dup := from[a.ID]; dup {
			errs = append(errs, fmt.Errorf("actor id %q is used by %s and %s", a.ID, other, e.Name()))
			continue
		}
		from[a.ID] = e.Name()
		out = append(out, a)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}
