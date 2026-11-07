package casefile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// EstateSnapshotAPIVersion is the only snapshot format this build reads. A snapshot is
// one dated, complete-or-not run of the passive collectors over the targets an estate
// file already names (docs/CASE-SPEC.md section 4.5.1). It wraps an ordinary
// jb.estate/v2 body so that every claim keeps its source, method and time.
const EstateSnapshotAPIVersion = "jb.estate-snapshot/v2"

// estateSnapshotV1APIVersion is refused with a message that says how to get a v2 snapshot.
const estateSnapshotV1APIVersion = "jb.estate-snapshot/v1"

// EstateSnapshotDir is the directory, inside paths.estate, that holds snapshots. The
// estate loader reads only files directly inside paths.estate, so a snapshot is never
// mistaken for a map and `jb case check` does not treat it as one.
const EstateSnapshotDir = "snapshots"

const (
	maxSnapshotSize     = 6 << 20
	maxSnapshotFailures = 500
	maxSnapshotText     = 500
)

// SnapshotIDFormat is the layout of a snapshot id, which is also its file stem: the
// UTC time of the run, so names sort in time order.
const SnapshotIDFormat = "20060102T150405Z"

var snapshotIDRE = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)

// Snapshot service states.
const (
	ServiceRan     = "ran"     // the collector was run for every target it had
	ServiceSkipped = "skipped" // targets exist but the service is not enabled in estate.external: nothing was sent
	ServiceNone    = "none"    // the estate names no target for this service
)

// SnapshotService says what happened to one collector in a refresh. A service that did
// not run is listed, never silently absent.
type SnapshotService struct {
	Name    string `yaml:"name"`
	State   string `yaml:"state"`
	Targets int    `yaml:"targets"`
	Reason  string `yaml:"reason,omitempty"`
}

// SnapshotFailure is a lookup that did not get a full answer, or a claim that could not
// be recorded. It is the reason a snapshot is incomplete. Its text is one short line.
type SnapshotFailure struct {
	Target string `yaml:"target"`
	Lookup string `yaml:"lookup"`
	Reason string `yaml:"reason"`
}

// SnapshotTargets are the targets the run took from the estate file it was based on.
type SnapshotTargets struct {
	Domains   []string `yaml:"domains,omitempty"`
	Addresses []string `yaml:"addresses,omitempty"`
	ASNs      []string `yaml:"asns,omitempty"`
}

// EstateSnapshot is a parsed, validated jb.estate-snapshot/v2 file.
type EstateSnapshot struct {
	APIVersion string `yaml:"apiVersion"`
	ID         string `yaml:"id"`
	Taken      string `yaml:"taken"`
	// Complete is true only when every lookup got a full answer and nothing was dropped.
	// An incomplete snapshot is evidence of a run, never a baseline.
	Complete bool   `yaml:"complete"`
	BasedOn  string `yaml:"based_on,omitempty"` // the estate file the targets were read from
	// BasedOnSHA256 is the lowercase hex SHA-256 of the exact bytes of the baseline file
	// the refresh read. Promotion refuses a snapshot whose baseline no longer has this
	// digest. It is optional in the format, so older snapshots still load and diff, but a
	// snapshot without it cannot be promoted.
	BasedOnSHA256 string            `yaml:"based_on_sha256,omitempty"`
	Note          string            `yaml:"note,omitempty"`
	Targets       SnapshotTargets   `yaml:"targets"`
	Services      []SnapshotService `yaml:"services"`
	Failures      []SnapshotFailure `yaml:"failures,omitempty"`
	Estate        Estate            `yaml:"estate"`
}

// SnapshotID returns the id of a snapshot taken at t.
func SnapshotID(t time.Time) string { return t.UTC().Format(SnapshotIDFormat) }

// ValidSnapshotID reports whether s has the shape of a snapshot id.
func ValidSnapshotID(s string) bool { return snapshotIDRE.MatchString(s) }

// ParseEstateSnapshot decodes and validates one snapshot without touching the
// filesystem. Unknown keys are errors, and `complete` must be written out: a missing
// flag is never read as either value.
func ParseEstateSnapshot(data []byte) (*EstateSnapshot, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("file is empty")
	}
	if err := CheckYAMLShape("estate snapshot", data); err != nil {
		return nil, err
	}
	var probe struct {
		APIVersion string `yaml:"apiVersion"`
		Complete   *bool  `yaml:"complete"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	switch probe.APIVersion {
	case EstateSnapshotAPIVersion:
	case "":
		return nil, fmt.Errorf("apiVersion is required (this build reads %s)", EstateSnapshotAPIVersion)
	case estateSnapshotV1APIVersion:
		return nil, fmt.Errorf("unsupported apiVersion %q: this build reads only %s; rewrite apiVersion to %s and the apiVersion of its estate body to %s, or regenerate the snapshot with `jb estate refresh`", probe.APIVersion, EstateSnapshotAPIVersion, EstateSnapshotAPIVersion, EstateAPIVersion)
	default:
		return nil, fmt.Errorf("unsupported apiVersion %q: this build reads only %s", probe.APIVersion, EstateSnapshotAPIVersion)
	}
	if probe.Complete == nil {
		return nil, errors.New(`missing required field "complete": a snapshot must say whether every lookup got a full answer`)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if err := scanCredentialsWithDigest(&root, "based_on_sha256"); err != nil {
		return nil, err
	}
	var s EstateSnapshot
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		if strings.Contains(err.Error(), "not found in type") {
			return nil, fmt.Errorf("unknown key (rejected, not ignored): %w", err)
		}
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one YAML document")
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *EstateSnapshot) validate() error {
	var errs []error
	bad := func(format string, v ...any) { errs = append(errs, fmt.Errorf(format, v...)) }
	if s.APIVersion != EstateSnapshotAPIVersion {
		bad("apiVersion must be %s", EstateSnapshotAPIVersion)
	}
	if !ValidSnapshotID(s.ID) {
		bad("id %q must look like 20261106T100000Z (the UTC time of the run)", s.ID)
	}
	if t, err := time.Parse(time.RFC3339, s.Taken); err != nil {
		bad("taken %q must be an RFC 3339 timestamp with a zone", s.Taken)
	} else if ValidSnapshotID(s.ID) && SnapshotID(t) != s.ID {
		bad("id %q does not match taken %q", s.ID, s.Taken)
	}
	if s.Note != "" {
		if err := checkLine("note", s.Note, maxSnapshotText); err != nil {
			errs = append(errs, err)
		}
	}
	if s.BasedOn != "" {
		if err := checkLine("based_on", s.BasedOn, maxSnapshotText); err != nil {
			errs = append(errs, err)
		}
	}
	if s.BasedOnSHA256 != "" && !sha256HexRE.MatchString(s.BasedOnSHA256) {
		bad("based_on_sha256 must be 64 lowercase hex digits (the SHA-256 of the baseline file the run read)")
	}
	if len(s.Failures) > maxSnapshotFailures {
		bad("failures hold at most %d entries, has %d", maxSnapshotFailures, len(s.Failures))
	}
	for i, f := range s.Failures {
		for _, x := range []struct{ name, v string }{{"target", f.Target}, {"lookup", f.Lookup}, {"reason", f.Reason}} {
			if err := checkLine(x.name, x.v, maxSnapshotText); err != nil {
				bad("failures[%d]: %v", i, err)
			}
		}
	}
	switch {
	case s.Complete && len(s.Failures) > 0:
		bad("complete is true but %d failure(s) are listed", len(s.Failures))
	case !s.Complete && len(s.Failures) == 0:
		bad("complete is false but no failure says why")
	}
	seen := map[string]bool{}
	for i, sv := range s.Services {
		if err := checkLine("name", sv.Name, 64); err != nil {
			bad("services[%d]: %v", i, err)
		}
		if seen[sv.Name] {
			bad("services[%d]: %q is listed twice", i, sv.Name)
		}
		seen[sv.Name] = true
		switch sv.State {
		case ServiceRan, ServiceSkipped, ServiceNone:
		default:
			bad("services[%d]: state %q must be ran, skipped or none", i, sv.State)
		}
		if sv.Targets < 0 {
			bad("services[%d]: targets is negative", i)
		}
		if sv.Reason != "" {
			if err := checkLine("reason", sv.Reason, maxSnapshotText); err != nil {
				bad("services[%d]: %v", i, err)
			}
		}
	}
	// A run that failed before any claim was recorded has no nodes; the body is only
	// validated as an estate when there is something in it.
	if len(s.Estate.Nodes) == 0 && !s.Complete {
		if len(s.Estate.Edges) > 0 || len(s.Estate.Absences) > 0 {
			bad("estate has edges or absences but no nodes")
		}
		if s.Estate.APIVersion != EstateAPIVersion {
			bad("estate.apiVersion must be %s", EstateAPIVersion)
		}
		if s.Estate.Subject != "" && !slices.Contains(EstateSubjects, s.Estate.Subject) {
			bad("estate: %v", errSubject())
		}
	} else if err := s.Estate.validate(); err != nil {
		errs = append(errs, fmt.Errorf("estate: %w", err))
	}
	return errors.Join(errs...)
}

// MarshalEstateSnapshot validates s and renders it as YAML.
func MarshalEstateSnapshot(s *EstateSnapshot) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("refusing to write an invalid snapshot: %w", err)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > maxSnapshotSize {
		return nil, fmt.Errorf("snapshot would be %d bytes, over the %d byte limit", buf.Len(), maxSnapshotSize)
	}
	// What is written must be what the loader reads back.
	if _, err := ParseEstateSnapshot(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("refusing to write a snapshot the loader would reject: %w", err)
	}
	return buf.Bytes(), nil
}

func snapshotPaths(c *Case, id string) (dir, file string, err error) {
	if !ValidSnapshotID(id) {
		return "", "", fmt.Errorf("snapshot id %q must look like 20261106T100000Z", id)
	}
	if c.Dir == "" {
		return "", "", errors.New("Dir is not set: paths cannot be checked")
	}
	root, err := realRoot(c.Dir)
	if err != nil {
		return "", "", err
	}
	dir, err = resolveInside(root, path.Join(c.Paths.Estate, EstateSnapshotDir))
	if err != nil {
		return "", "", fmt.Errorf("snapshot directory: %w", err)
	}
	file, err = resolveInside(root, path.Join(c.Paths.Estate, EstateSnapshotDir, id+".yaml"))
	if err != nil {
		return "", "", fmt.Errorf("snapshot %q: %w", id, err)
	}
	if !within(dir, file) {
		return "", "", fmt.Errorf("snapshot %q resolves outside the snapshot directory", id)
	}
	return dir, file, nil
}

func readSnapshotFile(file, label string) (*EstateSnapshot, error) {
	fh, err := os.Open(file) // #nosec G304 -- confined by snapshotPaths
	if err != nil {
		return nil, fmt.Errorf("snapshot %q: %w", label, err)
	}
	defer fh.Close()
	if st, err := fh.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("snapshot %q is not a regular file", label)
	}
	data, err := io.ReadAll(io.LimitReader(fh, maxSnapshotSize+1))
	if err != nil {
		return nil, fmt.Errorf("read snapshot %q: %w", label, err)
	}
	if len(data) > maxSnapshotSize {
		return nil, fmt.Errorf("snapshot %q is larger than %d bytes", label, maxSnapshotSize)
	}
	s, err := ParseEstateSnapshot(data)
	if err != nil {
		return nil, fmt.Errorf("snapshot %q: %w", label, err)
	}
	if s.ID != label {
		return nil, fmt.Errorf("snapshot %q: the id inside the file is %q; a snapshot is named for its id", label, s.ID)
	}
	return s, nil
}

// LoadEstateSnapshot reads one snapshot by id. A missing, corrupt or unknown file is an
// error; it is never an empty baseline.
func LoadEstateSnapshot(c *Case, id string) (*EstateSnapshot, error) {
	_, file, err := snapshotPaths(c, id)
	if err != nil {
		return nil, err
	}
	return readSnapshotFile(file, id)
}

// ListEstateSnapshots reads every snapshot, oldest first. A missing directory means
// there are none. Any file in the directory that is not a valid snapshot is an error
// naming it: a corrupt snapshot is never skipped over, because skipping it would pick an
// older baseline without saying so.
func ListEstateSnapshots(c *Case) ([]*EstateSnapshot, error) {
	if c.Dir == "" {
		return nil, errors.New("Dir is not set: paths cannot be checked")
	}
	root, err := realRoot(c.Dir)
	if err != nil {
		return nil, err
	}
	dir, err := resolveInside(root, path.Join(c.Paths.Estate, EstateSnapshotDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("snapshot directory: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read snapshot directory: %w", err)
	}
	var out []*EstateSnapshot
	var errs []error
	for _, en := range entries {
		name := en.Name()
		if strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp") {
			continue // a half-written temporary file of an interrupted write
		}
		id, ok := strings.CutSuffix(name, ".yaml")
		if !ok || !ValidSnapshotID(id) {
			errs = append(errs, fmt.Errorf("snapshot directory holds %q, which is not a snapshot (<id>.yaml)", name))
			continue
		}
		s, err := LoadEstateSnapshot(c, id)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, s)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// LatestEstateSnapshot returns the newest snapshot, complete or not, or nil when there
// is none.
func LatestEstateSnapshot(c *Case) (*EstateSnapshot, error) {
	all, err := ListEstateSnapshots(c)
	if err != nil || len(all) == 0 {
		return nil, err
	}
	return all[len(all)-1], nil
}

// ErrSnapshotExists means a snapshot with that id is already on disk. A snapshot is
// never overwritten.
var ErrSnapshotExists = errors.New("snapshot already exists")

// WriteEstateSnapshot validates s and writes <paths.estate>/snapshots/<id>.yaml. The
// bytes go to a temporary file in the same directory and are then hard-linked to the
// final name, which fails if the name is taken: an existing snapshot is never replaced,
// and a reader never sees a half-written one. It returns the case-relative path.
func WriteEstateSnapshot(c *Case, s *EstateSnapshot) (string, error) {
	data, err := MarshalEstateSnapshot(s)
	if err != nil {
		return "", err
	}
	dir, file, err := snapshotPaths(c, s.ID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create snapshot directory: %w", err)
	}
	// MkdirAll may have created the directory through a path that was a symlink a moment
	// ago; check once more now that it exists.
	if _, _, err := snapshotPaths(c, s.ID); err != nil {
		return "", err
	}
	if err := writeNoOverwrite(dir, file, data); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("%w: %s", ErrSnapshotExists, s.ID)
		}
		return "", err
	}
	return path.Join(c.Paths.Estate, EstateSnapshotDir, s.ID+".yaml"), nil
}

// writeNoOverwrite writes data to a temporary file in dir and hard-links it to file,
// which fails with an error wrapping os.ErrExist if file is taken. The temporary name
// is removed either way.
func writeNoOverwrite(dir, file string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".snapshot-*.tmp")
	if err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(file), err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(file), err)
	}
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), file); err != nil {
		if errors.Is(err, os.ErrExist) {
			return err
		}
		return fmt.Errorf("write %s: %w", filepath.Base(file), err)
	}
	syncDir(dir)
	return nil
}

// syncDir flushes a directory entry (a rename or link just made) to disk. It is best
// effort: some platforms and filesystems cannot sync a directory, and the file itself is
// already synced, so a failure here is not an error.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// EstateArchiveDir is where promotion keeps the baseline it replaced, inside paths.estate.
const EstateArchiveDir = "archive"

// ArchiveEstateFile copies the named estate file, as it is now, to
// <paths.estate>/archive/<stem>-<id>.yaml without overwriting anything, and returns the
// case-relative path. The file is re-read through the strict loader first, so a file
// that does not load is never archived as if it were a good baseline.
//
// Archiving is idempotent for an unchanged baseline: when an archive of the same stem
// already holds exactly these bytes (a promotion that archived and then failed to
// replace the baseline), that archive is returned and no second copy is written. A name
// that exists with different bytes is an error and is left alone.
func ArchiveEstateFile(c *Case, name, id string) (string, error) {
	e, err := LoadEstateFile(c, name)
	if err != nil {
		return "", err
	}
	data, err := MarshalEstate(e)
	if err != nil {
		return "", err
	}
	root, err := realRoot(c.Dir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(c.Paths.Estate), EstateArchiveDir), 0o750); err != nil {
		return "", fmt.Errorf("create archive directory: %w", err)
	}
	dir, err := resolveInside(root, path.Join(c.Paths.Estate, EstateArchiveDir))
	if err != nil {
		return "", fmt.Errorf("archive directory: %w", err)
	}
	stem := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
	rel := path.Join(c.Paths.Estate, EstateArchiveDir, stem+"-"+id+".yaml")
	file, err := resolveInside(root, rel)
	if err != nil {
		return "", err
	}
	if !within(dir, file) {
		return "", errors.New("archive path resolves outside the archive directory")
	}
	if existing := findArchiveCopy(dir, stem, data); existing != "" {
		return path.Join(c.Paths.Estate, EstateArchiveDir, existing), nil
	}
	if err := writeNoOverwrite(dir, file, data); err != nil {
		return "", err
	}
	return rel, nil
}

// findArchiveCopy returns the name of a regular file <stem>-<id>.yaml in dir whose bytes
// equal data, or "". The newest id wins. Symlinks and unreadable entries are ignored.
func findArchiveCopy(dir, stem string, data []byte) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	best := ""
	for _, en := range entries {
		id, ok := strings.CutSuffix(strings.TrimPrefix(en.Name(), stem+"-"), ".yaml")
		if !ok || !strings.HasPrefix(en.Name(), stem+"-") || !ValidSnapshotID(id) || !en.Type().IsRegular() {
			continue
		}
		got, err := os.ReadFile(filepath.Join(dir, en.Name()))
		if err != nil || !bytes.Equal(got, data) {
			continue
		}
		if en.Name() > best {
			best = en.Name()
		}
	}
	return best
}

// EstateState is one side of a comparison: an estate file or a snapshot, loaded
// strictly. Snapshot is nil for a plain estate file.
type EstateState struct {
	Ref      string // as the operator named it, or the file name
	Path     string // case-relative
	Estate   *Estate
	Snapshot *EstateSnapshot
}

// LoadEstateState resolves ref and loads it. ref is a snapshot id
// (20261106T100000Z), or a file name inside the estate directory (estate.yaml), or
// snapshots/<id>.yaml. Anything else, and anything that does not load, is an error.
func LoadEstateState(c *Case, ref string) (*EstateState, error) {
	switch {
	case ValidSnapshotID(ref):
		s, err := LoadEstateSnapshot(c, ref)
		if err != nil {
			return nil, err
		}
		return &EstateState{Ref: ref, Path: path.Join(c.Paths.Estate, EstateSnapshotDir, ref+".yaml"), Estate: &s.Estate, Snapshot: s}, nil
	case strings.HasPrefix(ref, EstateSnapshotDir+"/"):
		id, ok := strings.CutSuffix(strings.TrimPrefix(ref, EstateSnapshotDir+"/"), ".yaml")
		if !ok || !ValidSnapshotID(id) {
			return nil, fmt.Errorf("%q is not a snapshot (snapshots/<id>.yaml)", ref)
		}
		return LoadEstateState(c, id)
	}
	e, err := LoadEstateFile(c, ref)
	if err != nil {
		return nil, err
	}
	return &EstateState{Ref: ref, Path: path.Join(c.Paths.Estate, ref), Estate: e}, nil
}
