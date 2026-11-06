package jb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

type (
	// DoctorCheck is one line of a [DoctorResult]: a group, a name, a status and a detail
	// that never holds a credential.
	DoctorCheck = app.Check
	// DoctorService is an outbound service the config names, with its state and what
	// would leave the machine if the command that uses it ran.
	DoctorService = app.ServiceReport
	// CheckStatus is the outcome of one doctor check.
	CheckStatus = app.CheckStatus
)

// Doctor check statuses. CheckSkipped means the thing is not configured, not applicable
// or not asked for: it is never a pass.
const (
	CheckOK      = app.CheckOK
	CheckWarn    = app.CheckWarn
	CheckFail    = app.CheckFail
	CheckSkipped = app.CheckSkipped
)

const (
	// DoctorReachTimeout bounds one connection of a [DoctorOptions.Online] check.
	DoctorReachTimeout = 4 * time.Second
	// DoctorLockWait is how long [Doctor] waits for a writer that holds the store, much
	// shorter than the wait of a command that must do its work: doctor reports, it does
	// not queue. A held lock still fails the check, but only after this budget.
	DoctorLockWait = 3 * time.Second
)

// doctorOverlapSpan is how far back the source-label overlap check looks.
const doctorOverlapSpan = 24 * time.Hour

// DoctorOptions say what [Doctor] checks and where it reads its inputs.
type DoctorOptions struct {
	// Case is a case directory. With it, doctor runs the checks of `jb case check` (the
	// evidence git guard included) and checks each config the case lists. Empty means no
	// case: that check is skipped.
	Case string
	// Config is a config file. With Case it names one of the case's configs, as in
	// [CaseHuntOptions.Config], and only that one is checked. Empty with Case means all
	// of the case's configs; empty without Case means no config is loaded.
	Config string
	// Online adds one TCP connect per distinct service host, bounded by
	// [DoctorReachTimeout]. The connection sends no bytes: no request, no credential, no
	// webhook URL path. A host reached through a DNS resolver is listed but not probed.
	// False sends nothing.
	Online bool
	// Env answers whether a named variable is set. Nil reads the process environment. Only
	// "set and non-empty" is ever read from it: no value and no length reaches the result.
	Env Env
	// Now is the clock of the source-label overlap check. Nil means time.Now.
	Now func() time.Time
	// Version, Commit and Date say which build to report. A link-time value from the
	// caller goes here; an empty field falls back to the build information of the
	// running program (the json-bourne module, else the main module), then "dev".
	Version, Commit, Date string
}

// DoctorResult is what [Doctor] found, the document `jb doctor --output json` prints.
type DoctorResult struct {
	Checks   []DoctorCheck
	Services []DoctorService
}

// OK is true when no check failed. Warnings and skips do not fail it, and a skip is not
// a pass: see [DoctorResult.Complete]. The CLI exits 0 exactly when OK is true.
func (r DoctorResult) OK() bool { return app.DoctorReport(r).OK() }

// Failed counts the failed checks.
func (r DoctorResult) Failed() int { return app.DoctorReport(r).Failed() }

// Skipped counts the checks that did not run because the thing is not configured or was
// not asked for (no case given, no --online, a store not created yet).
func (r DoctorResult) Skipped() int {
	n := 0
	for _, c := range r.Checks {
		if c.Status == CheckSkipped {
			n++
		}
	}
	return n
}

// Complete is true when no check was skipped, so every check doctor knows ran. All
// checks passed is OK() && Complete() with no warning in Checks; OK() alone with
// Complete() false means nothing failed but something was not looked at.
func (r DoctorResult) Complete() bool { return r.Skipped() == 0 }

// MarshalJSON writes {"ok", "checks", "services"}, with [] for an empty list.
func (r DoctorResult) MarshalJSON() ([]byte, error) {
	out := struct {
		OK       bool            `json:"ok"`
		Checks   []DoctorCheck   `json:"checks"`
		Services []DoctorService `json:"services"`
	}{OK: r.OK(), Checks: r.Checks, Services: r.Services}
	if out.Checks == nil {
		out.Checks = []DoctorCheck{}
	}
	if out.Services == nil {
		out.Services = []DoctorService{}
	}
	return json.Marshal(out)
}

// Doctor checks the environment and the config before a run, as `jb doctor` does: that
// each config loads strictly, that each environment variable it names is set, that the
// case passes [CaseCheck] and its evidence directory is ignored by git, that the store
// path is writable, owned by this user and opens, the build and DuckDB versions, the
// plugin allowlist (without launching any plugin), and for every outbound service
// whether it is enabled and what would leave the machine.
//
// Doctor is read-only. It writes nothing, starts no plugin and, unless Online is set,
// sends nothing. A failed check is in the result, not in the error: the error is the
// context's, when it ended before the checks did, and the result is then partial. Read
// [DoctorResult.OK] and [DoctorResult.Complete] before telling anyone the environment
// is ready.
func Doctor(ctx context.Context, opts DoctorOptions) (*DoctorResult, error) {
	if opts.Env == nil {
		opts.Env = config.OSEnv
	}
	a := &doctorAdapter{env: opts.Env, now: opts.Now}
	deps := app.DoctorDeps{Configs: a, Cases: a, Env: a, Stores: a, Plugins: a, Build: doctorBuild(opts)}
	if opts.Online {
		deps.Reach = &tcpReach{env: opts.Env, timeout: DoctorReachTimeout}
	}
	rep := app.Doctor(ctx, deps, app.DoctorRequest{CaseDir: opts.Case, ConfigPath: opts.Config})
	res := DoctorResult(rep)
	return &res, ctx.Err()
}

func doctorBuild(opts DoctorOptions) app.DoctorBuild {
	v, c, d := opts.Version, opts.Commit, opts.Date
	if bi, ok := debug.ReadBuildInfo(); ok {
		mv := bi.Main.Version
		for _, dep := range bi.Deps {
			if dep.Path == "github.com/iksnerd/json-bourne" {
				mv = dep.Version
			}
		}
		if v == "" && mv != "" && mv != "(devel)" {
			v = mv
		}
		for _, s := range bi.Settings {
			switch {
			case s.Key == "vcs.revision" && c == "":
				c = s.Value
			case s.Key == "vcs.time" && d == "":
				d = s.Value
			}
		}
	}
	if v == "" {
		v = "dev"
	}
	b := app.DoctorBuild{Version: v, Commit: c, Date: d, Go: runtime.Version(), DuckDBDriver: duckdb.DriverVersion()}
	if e, err := duckdb.EngineVersion(); err != nil {
		b.DuckDBErr = err.Error()
	} else {
		b.DuckDBEngine = e
	}
	return b
}

// doctorAdapter implements the doctor ports over config, casefile and the store.
type doctorAdapter struct {
	env config.Env
	now func() time.Time
	c   *casefile.Case // set by Inspect; the configs are then loaded as the case's
}

// IsSet reports set and non-empty. It is the only thing doctor learns about a variable.
func (a *doctorAdapter) IsSet(name string) bool {
	v, ok := a.env(name)
	return ok && v != ""
}

// Load reads one config. Once Inspect has loaded a case, the store is placed as the case
// places it.
func (a *doctorAdapter) Load(ref string) (app.DoctorConfig, error) {
	cfg, err := config.Load(ref)
	if err != nil {
		return app.DoctorConfig{}, err
	}
	if a.c != nil {
		config.PlaceCaseStore(a.c, cfg)
	}
	out := app.DoctorConfig{StorePath: cfg.StorePath()}
	for _, n := range cfg.DisabledSources() {
		out.Disabled = append(out.Disabled, app.Disabled{Kind: "source", Name: n})
	}
	for _, n := range cfg.DisabledDetectors() {
		out.Disabled = append(out.Disabled, app.Disabled{Kind: "detector", Name: n})
	}
	for _, s := range cfg.Services() {
		out.Services = append(out.Services, app.DoctorService{
			Kind: s.Kind, Type: s.Type, Name: s.Name, Enabled: s.Enabled, EnvVars: s.EnvVars,
			Host: s.Host, HostEnv: s.HostEnv, Resolver: s.Resolver, Leaves: s.Leaves,
		})
	}
	return out, nil
}

func (a *doctorAdapter) Inspect(dir, configFlag string) (app.DoctorCase, error) {
	rep, c := checkCase(dir)
	if rep.Error != "" {
		return app.DoctorCase{}, errors.New(oneLine(rep.Error))
	}
	a.c = c
	out := app.DoctorCase{ID: rep.ID}
	item := func(name string, ok bool, detail string) {
		st := app.CheckOK
		if !ok {
			st = app.CheckFail
		}
		out.Items = append(out.Items, app.CaseItem{Name: name, Status: st, Detail: oneLine(detail)})
	}
	item("case.yaml", true, rep.ID+": "+rep.Title)
	switch {
	case rep.Guard.OK && rep.Guard.Result == guardNotWorkTree:
		out.Items = append(out.Items, app.CaseItem{Name: "evidence guard", Status: app.CheckWarn,
			Detail: rep.Evidence + " is not inside a git work tree, so nothing can be committed by accident yet; run doctor again once the case is under git"})
	default:
		d := rep.Evidence + ": " + rep.Guard.Result
		if !rep.Guard.OK {
			d = rep.Evidence + ": " + rep.Guard.Error
		}
		item("evidence guard", rep.Guard.OK, d)
	}
	if rep.Actors != nil {
		if rep.Actors.OK {
			item("actors", true, fmt.Sprintf("%d loaded", len(rep.Actors.IDs)))
		} else {
			item("actors", false, rep.Actors.Error)
		}
	}
	if rep.Estate != nil {
		if rep.Estate.OK {
			item("estate", true, fmt.Sprintf("%d loaded", len(rep.Estate.IDs)))
		} else {
			item("estate", false, rep.Estate.Error)
		}
	}
	for _, cr := range rep.Configs {
		if cr.OK {
			item("case config "+cr.Path, true, "loads and its detectors build")
		} else {
			item("case config "+cr.Path, false, cr.Error)
		}
	}
	if configFlag != "" {
		p, err := config.ChooseCaseConfig(c, configFlag, "")
		if err != nil {
			return app.DoctorCase{}, err
		}
		out.ConfigRefs = []string{p}
		return out, nil
	}
	if len(c.Config) == 0 {
		out.Items = append(out.Items, app.CaseItem{Name: "case configs", Status: app.CheckWarn, Detail: "the case lists no config; pass --config FILE"})
	}
	for _, rel := range c.Config {
		out.ConfigRefs = append(out.ConfigRefs, filepath.Join(c.Dir, filepath.FromSlash(rel)))
	}
	return out, nil
}

// Plugins reads the operator's allowlist (jb's own location, never a case) and checks
// each entry's file, directory and pin. It launches nothing.
func (a *doctorAdapter) Plugins() (string, []app.DoctorPlugin, error) {
	al, err := config.PluginAllowlist()
	if err != nil {
		return "", nil, err
	}
	var out []app.DoctorPlugin
	for _, st := range al.Inspect() {
		out = append(out, app.DoctorPlugin{Name: st.Name, Path: st.Path, Pin: st.Pin, Err: st.Err})
	}
	return al.Source, out, nil
}

func (a *doctorAdapter) Probe(ctx context.Context, path string) app.DoctorStore {
	s := app.DoctorStore{Path: path, BuildSchema: duckdb.Version}
	st, err := os.Stat(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.WriteErr = err.Error()
			return s
		}
		// Not created yet: the first run creates it, so the nearest existing directory
		// must be writable, and nothing is written here to find out.
		dir := filepath.Dir(path)
		for {
			if di, derr := os.Stat(dir); derr == nil && di.IsDir() {
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
		if err := writableDir(dir); err != nil {
			s.WriteErr = "cannot create the store under " + dir + ": " + err.Error()
		}
		return s
	}
	s.Exists = true
	if st.IsDir() {
		s.WriteErr = "the store path is a directory"
		return s
	}
	if err := writableFile(path); err != nil {
		s.WriteErr = err.Error()
	}
	s.OwnerMismatch = ownerMismatch(st)
	if m := st.Mode().Perm(); m&0o022 != 0 {
		s.LooseMode = fmt.Sprintf("%04o", uint32(m))
	}
	h, err := duckdb.OpenContext(ctx, path, true, duckdb.OpenOptions{LockWait: DoctorLockWait})
	if err != nil {
		s.OpenErr = oneLine(err.Error())
		switch {
		case errors.Is(err, duckdb.ErrLocked):
			s.OpenKind = "locked"
		case errors.Is(err, duckdb.ErrSchemaAhead):
			s.OpenKind = "ahead"
		case errors.Is(err, duckdb.ErrSchemaBehind):
			s.OpenKind = "behind"
		default:
			s.OpenKind = "other"
		}
		return s
	}
	defer h.Close()
	if v, verr := h.SchemaVersion(); verr == nil {
		s.Schema = v
	}
	now := time.Now()
	if a.now != nil {
		now = a.now()
	}
	ov, oerr := app.SourceOverlaps(ctx, h, core.Window{From: now.Add(-doctorOverlapSpan), To: now})
	if oerr != nil {
		s.OverlapErr = oneLine(oerr.Error())
	}
	s.Overlaps = ov
	return s
}

// tcpReach makes one bounded TCP connect per host and sends nothing over it.
type tcpReach struct {
	env     config.Env
	timeout time.Duration
}

// Target is host:port only. For a webhook the URL is read from its variable, and only
// the scheme's host and port are kept: the path, query and user info are secrets.
func (r *tcpReach) Target(s app.DoctorService) (string, string) {
	if s.HostEnv != "" {
		raw, ok := r.env(s.HostEnv)
		if !ok || raw == "" {
			return "", "the URL variable is unset, so there is no host to reach"
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return "", "the URL variable does not hold a usable URL"
		}
		port := u.Port()
		if port == "" {
			port = "443"
			if u.Scheme == "http" {
				port = "80"
			}
		}
		return net.JoinHostPort(u.Hostname(), port), ""
	}
	if s.Host == "" {
		return "", "no host is named in the config"
	}
	return s.Host, ""
}

func (r *tcpReach) Probe(ctx context.Context, target string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		var ne net.Error
		switch {
		case errors.As(err, &ne) && ne.Timeout():
			return errors.New("timed out")
		default:
			// The dial error names the address and the cause, never anything we sent.
			return errors.New(strings.TrimPrefix(oneLine(err.Error()), "dial tcp "+target+": "))
		}
	}
	_ = c.Close()
	return nil
}
