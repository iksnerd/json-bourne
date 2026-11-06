package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

// reachTimeout bounds one --online connection.
const reachTimeout = 4 * time.Second

func newDoctorCmdWith(d deps) *cobra.Command {
	var (
		cfgPath string
		caseDir string
		output  string
		online  bool
	)
	cmd := &cobra.Command{
		Use:   "doctor [--case DIR | --config FILE] [--online]",
		Short: "Check the environment and the config before a run (read-only)",
		Long: "doctor answers \"will the next hunt, watch or intel run work, and what would it send?\" without\n" +
			"running any of them. It is read-only and sends nothing by default. It checks that the config loads\n" +
			"strictly; that each environment variable the config names is set (reported as set or unset, never\n" +
			"its value or length); that the case passes `jb case check` and its evidence directory is ignored by\n" +
			"git; that the store path is writable by this user, owned by this user and opens; the jb build and\n" +
			"the DuckDB driver and engine versions; the plugin allowlist ($JB_PLUGINS_FILE or ~/.jb/plugins.yaml):\n" +
			"each plugin's path, pin state and file mode checks, without launching any; and, for every outbound\n" +
			"service, whether it is enabled and what would leave the machine.\n\n" +
			"--online adds one TCP connect per distinct service host, bounded to " + reachTimeout.String() + ". The connection sends no\n" +
			"bytes: no request, no credential, no webhook URL path. A host that is reached through a DNS\n" +
			"resolver (dnsbl, estate dns) is listed but not probed.\n\n" +
			"Exit 0 only if no check failed. A thing that is not configured or not asked for is `skipped`, which\n" +
			"is not a pass. doctor does not inventory external binaries; the only programs jb starts are the allowlisted plugins listed above and git.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			a := &doctorAdapter{env: d.env, caseDir: caseDir, now: d.now}
			deps := app.DoctorDeps{Configs: a, Cases: a, Env: a, Stores: a, Plugins: a, Build: doctorBuild()}
			if online {
				deps.Reach = &tcpReach{env: d.env, timeout: reachTimeout}
			}
			rep := app.Doctor(cmd.Context(), deps, app.DoctorRequest{CaseDir: caseDir, ConfigPath: cfgPath})
			var err error
			if output == "json" {
				err = writeDoctorJSON(cmd.OutOrStdout(), rep)
			} else {
				err = writeDoctorTable(cmd.OutOrStdout(), rep)
			}
			if err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			if !rep.OK() {
				return fmt.Errorf("doctor: %d check(s) failed", rep.Failed())
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfgPath, "config", "", "path to the YAML config (with --case, one of the case's configs; default: all of them)")
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md)")
	f.BoolVar(&online, "online", false, "also make one TCP connect per service host (sends nothing)")
	f.StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

func doctorBuild() app.DoctorBuild {
	v, c, dt := buildInfo()
	b := app.DoctorBuild{Version: v, Commit: c, Date: dt, Go: runtime.Version(), DuckDBDriver: duckdb.DriverVersion()}
	if e, err := duckdb.EngineVersion(); err != nil {
		b.DuckDBErr = err.Error()
	} else {
		b.DuckDBEngine = e
	}
	return b
}

// doctorAdapter implements the doctor ports over config, casefile and the store.
type doctorAdapter struct {
	env     config.Env
	caseDir string
	now     func() time.Time
	c       *casefile.Case // set by Inspect; the configs are then loaded as the case's
}

// IsSet reports set and non-empty. It is the only thing doctor learns about a variable.
func (a *doctorAdapter) IsSet(name string) bool {
	v, ok := a.env(name)
	return ok && v != ""
}

func (a *doctorAdapter) Load(ref string) (app.DoctorConfig, error) {
	cfg, err := config.Load(ref)
	if err != nil {
		return app.DoctorConfig{}, err
	}
	if a.c != nil {
		(&casePlan{c: a.c}).placeStore(io.Discard, cfg)
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
	rep := checkCase(dir)
	if rep.Error != "" {
		return app.DoctorCase{}, errors.New(oneLine(rep.Error))
	}
	c, _, err := inspectCase(dir)
	if err != nil {
		return app.DoctorCase{}, err
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
	case rep.Guard.OK && rep.Guard.Result == casefile.GuardNotWorkTree.String():
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
		p, err := chooseCaseConfig(c, configFlag)
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

// doctorLockWait is how long doctor waits for a writer that holds the store, much shorter
// than the 15s a command that must do its work waits: doctor reports, it does not queue.
// A held lock still FAILS the check, but only after this budget, so a `jb watch` cycle
// that happens to be writing at that instant does not make the report flap.
const doctorLockWait = 3 * time.Second

// doctorOverlapSpan is how far back the source-label overlap check looks.
const doctorOverlapSpan = 24 * time.Hour

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
	h, err := duckdb.OpenContext(ctx, path, true, duckdb.OpenOptions{LockWait: doctorLockWait})
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

func writeDoctorJSON(w io.Writer, r app.DoctorReport) error {
	out := struct {
		OK       bool                `json:"ok"`
		Checks   []app.Check         `json:"checks"`
		Services []app.ServiceReport `json:"services"`
	}{OK: r.OK(), Checks: r.Checks, Services: r.Services}
	if out.Checks == nil {
		out.Checks = []app.Check{}
	}
	if out.Services == nil {
		out.Services = []app.ServiceReport{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeDoctorTable(w io.Writer, r app.DoctorReport) error {
	var group []app.Check
	flush := func() error {
		if len(group) == 0 {
			return nil
		}
		fmt.Fprintf(w, "\n%s\n", strings.ToUpper(group[0].Group))
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, c := range group {
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", strings.ToUpper(string(c.Status)), c.Name, c.Detail)
		}
		group = nil
		return tw.Flush()
	}
	for _, c := range r.Checks {
		if len(group) > 0 && group[0].Group != c.Group {
			if err := flush(); err != nil {
				return err
			}
		}
		group = append(group, c)
	}
	if err := flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nSERVICES (what would leave this machine if the command that uses it ran)\n")
	if len(r.Services) == 0 {
		fmt.Fprintf(w, "  none: no config was loaded\n")
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, s := range r.Services {
		who := s.Kind + " " + s.Name
		if s.Config != "" {
			who += " (" + s.Config + ")"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", strings.ToUpper(s.State), who, s.Leaves)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if r.OK() {
		fmt.Fprintf(w, "\nRESULT  OK. SKIPPED is not a pass: read those lines for what was not checked.\n")
	} else {
		fmt.Fprintf(w, "\nRESULT  FAIL: %d check(s) failed.\n", r.Failed())
	}
	return nil
}
