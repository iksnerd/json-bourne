package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/iksnerd/json-bourne/internal/core"
)

// CheckStatus is the outcome of one doctor check. Skipped means the thing is not
// configured or not applicable: it is never counted as a pass.
type CheckStatus string

const (
	CheckOK      CheckStatus = "ok"
	CheckFail    CheckStatus = "fail"
	CheckWarn    CheckStatus = "warn"
	CheckSkipped CheckStatus = "skipped"
)

// Check is one line of the doctor report. Detail never holds a credential: the ports
// that feed it return flags and names, not values (see DoctorEnv).
type Check struct {
	Group  string      `json:"group"`
	Name   string      `json:"name"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail,omitempty"`
}

// ServiceReport is an outbound service the config names, with its state and what would
// leave the machine if it ran.
type ServiceReport struct {
	Config  string   `json:"config,omitempty"`
	Kind    string   `json:"kind"`
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	State   string   `json:"state"` // enabled or disabled
	EnvVars []string `json:"env_vars,omitempty"`
	Leaves  string   `json:"leaves"`
}

// DoctorReport is the whole result. It passes only if no check failed.
type DoctorReport struct {
	Checks   []Check         `json:"checks"`
	Services []ServiceReport `json:"services"`
}

// OK is true when no check failed. Warnings and skips do not fail the run, and a
// skip is not a pass: it is shown as skipped.
func (r DoctorReport) OK() bool {
	for _, c := range r.Checks {
		if c.Status == CheckFail {
			return false
		}
	}
	return true
}

// Failed counts failed checks.
func (r DoctorReport) Failed() int {
	n := 0
	for _, c := range r.Checks {
		if c.Status == CheckFail {
			n++
		}
	}
	return n
}

// DoctorBuild is what the binary knows about itself.
type DoctorBuild struct {
	Version, Commit, Date string
	Go                    string
	DuckDBDriver          string
	DuckDBEngine          string
	DuckDBErr             string // why the engine version could not be read, if it could not
}

// DoctorService is one outbound service as the config layer describes it. It holds
// names and flags only.
type DoctorService struct {
	Kind, Type, Name string
	Enabled          bool
	EnvVars          []string // names of required environment variables
	Host             string   // host:port to reach, "" when unknown
	HostEnv          string   // variable whose URL holds the host (webhook); never read unless --online
	Resolver         bool     // reached through a DNS resolver, not by connecting
	Leaves           string
}

// DoctorConfig is one config file, loaded.
type DoctorConfig struct {
	Services  []DoctorService
	StorePath string
	// Disabled is what the config switched off with `enabled: false`. doctor lists each
	// by name: a component that is not built is never reported as ok.
	Disabled []Disabled
}

// DoctorConfigs loads a config strictly (unknown keys and types are errors).
type DoctorConfigs interface {
	Load(ref string) (DoctorConfig, error)
}

// CaseItem is one result of checking a case.
type CaseItem struct {
	Name   string
	Status CheckStatus
	Detail string
}

// DoctorCase is a case directory inspected.
type DoctorCase struct {
	ID         string
	Items      []CaseItem // case.yaml, the evidence git guard, actors, estate, each config
	ConfigRefs []string   // the configs doctor should load, in order
}

// DoctorCases inspects a case (the same checks as `jb case check`) and says which
// configs belong to it.
type DoctorCases interface {
	Inspect(dir, configFlag string) (DoctorCase, error)
}

// DoctorEnv answers whether a variable is set and non-empty. It returns a bool and
// nothing else, so no value and no length can reach a report through it.
type DoctorEnv interface {
	IsSet(name string) bool
}

// DoctorStore is what the filesystem and the engine say about the evidence database.
type DoctorStore struct {
	Path          string
	Exists        bool
	WriteErr      string // "": the file (or, when absent, its nearest existing directory) is writable by this user
	OwnerMismatch string // "": owned by this user; otherwise a description
	LooseMode     string // "": fine; otherwise the mode that lets group or others write
	OpenErr       string // "": opened read-only
	OpenKind      string // "", "ahead", "behind", "locked" or "other"
	Schema        int
	BuildSchema   int
	// Overlaps and OverlapErr are the source-label overlap check over the recent past, run
	// only when the store opened. Advice: they never fail a check.
	Overlaps   []core.SourceOverlap
	OverlapErr string
}

// DoctorStores probes a store path without writing to it. It may wait for a lock held
// by another process, within a short budget, and stops when ctx ends.
type DoctorStores interface {
	Probe(ctx context.Context, path string) DoctorStore
}

// DoctorReach is the optional reachability port, used only with --online. Target
// resolves where a service would be asked (for a webhook that means reading the URL
// variable, and it returns host:port only, never the path); Probe makes one bounded
// TCP connection and sends nothing.
type DoctorReach interface {
	Target(svc DoctorService) (target, skip string)
	Probe(ctx context.Context, target string) error
}

// DoctorPlugin is one allowlisted plugin as doctor shows it: names, paths and states,
// never an environment value.
type DoctorPlugin struct {
	Name, Path string
	Pin        string // "none", "ok" or "MISMATCH"
	Err        string // "": every trust check passed (mode, location, pin); else the first that failed
}

// DoctorPlugins lists the operator's plugin allowlist and checks each entry without
// launching anything. Source is the file the list was read from ("" when none exists).
type DoctorPlugins interface {
	Plugins() (source string, list []DoctorPlugin, err error)
}

// DoctorDeps are the ports Doctor works through.
type DoctorDeps struct {
	Build   DoctorBuild
	Configs DoctorConfigs
	Cases   DoctorCases
	Env     DoctorEnv
	Stores  DoctorStores
	Reach   DoctorReach   // nil unless --online
	Plugins DoctorPlugins // nil: the plugin check is skipped
}

// DoctorRequest says what to check. Both empty checks the environment only.
type DoctorRequest struct {
	CaseDir    string
	ConfigPath string
}

// Doctor checks the environment and the config. It is read-only and sends nothing
// unless deps.Reach is set.
func Doctor(ctx context.Context, d DoctorDeps, req DoctorRequest) DoctorReport {
	var r DoctorReport
	add := func(group, name string, st CheckStatus, format string, a ...any) {
		r.Checks = append(r.Checks, Check{Group: group, Name: name, Status: st, Detail: fmt.Sprintf(format, a...)})
	}

	// Build.
	add("build", "jb", CheckOK, "%s", join(d.Build.Version, shortCommit(d.Build.Commit), d.Build.Date))
	add("build", "go", CheckOK, "%s", d.Build.Go)
	if d.Build.DuckDBErr != "" {
		add("build", "duckdb", CheckFail, "driver %s; the engine did not start: %s", d.Build.DuckDBDriver, d.Build.DuckDBErr)
	} else {
		add("build", "duckdb", CheckOK, "driver %s, engine %s", d.Build.DuckDBDriver, d.Build.DuckDBEngine)
	}

	// Case.
	refs := []string{}
	if req.ConfigPath != "" {
		refs = []string{req.ConfigPath}
	}
	if req.CaseDir != "" {
		c, err := d.Cases.Inspect(req.CaseDir, req.ConfigPath)
		if err != nil {
			add("case", req.CaseDir, CheckFail, "%v", err)
		} else {
			for _, it := range c.Items {
				add("case", it.Name, it.Status, "%s", it.Detail)
			}
			refs = c.ConfigRefs
		}
	} else {
		add("case", "case", CheckSkipped, "no --case; the evidence directory guard needs a case")
	}

	// Configs.
	if len(refs) == 0 {
		add("config", "config", CheckSkipped, "no --config or --case; nothing to load")
	}
	var stores []string
	var enabled []DoctorService
	for _, ref := range refs {
		cfg, err := d.Configs.Load(ref)
		if err != nil {
			add("config", ref, CheckFail, "%v", err)
			continue
		}
		add("config", ref, CheckOK, "loads strictly: %d outbound service(s) named", len(cfg.Services))
		stores = append(stores, cfg.StorePath)
		for _, off := range cfg.Disabled {
			add("config", off.Kind+" "+off.Name, CheckSkipped, "DISABLED: enabled: false in %s; it is not built, not read, not run, and nothing is sent for it", ref)
		}
		label := ""
		if len(refs) > 1 {
			label = ref
		}
		for _, s := range cfg.Services {
			state := "disabled"
			if s.Enabled {
				state = "enabled"
			}
			if s.Enabled {
				enabled = append(enabled, s)
			}
			r.Services = append(r.Services, ServiceReport{Config: label, Kind: s.Kind, Type: s.Type, Name: s.Name, State: state, EnvVars: s.EnvVars, Leaves: s.Leaves})
			for _, v := range s.EnvVars {
				name := s.Kind + " " + s.Name + ": $" + v
				switch {
				case !s.Enabled:
					add("env", name, CheckSkipped, "service is disabled")
				case d.Env.IsSet(v):
					add("env", name, CheckOK, "set")
				default:
					add("env", name, CheckFail, "unset or empty; the command that uses %s %s refuses to run without it", s.Name, "(jb "+usedBy(s.Kind)+")")
				}
			}
		}
	}

	// Plugins.
	pluginChecks(add, d.Plugins)

	// Store.
	if len(stores) == 0 {
		add("store", "store", CheckSkipped, "no config loaded, so the store path is unknown")
	}
	seen := map[string]bool{}
	for _, p := range stores {
		if seen[p] {
			continue
		}
		seen[p] = true
		storeChecks(add, d.Stores.Probe(ctx, p), overlapScope(req))
	}

	// Online.
	if d.Reach == nil {
		add("online", "reachability", CheckSkipped, "not asked; pass --online for one TCP connect per service host (nothing is sent over it)")
		return r
	}
	targets := map[string][]string{}
	var order []string
	for _, sv := range enabled {
		who := sv.Kind + " " + sv.Name
		if sv.Resolver {
			add("online", who, CheckSkipped, "asked through a DNS resolver over UDP; a TCP connect would not test it")
			continue
		}
		t, skip := d.Reach.Target(sv)
		if t == "" {
			add("online", who, CheckSkipped, "%s", skip)
			continue
		}
		if _, dup := targets[t]; !dup {
			order = append(order, t)
		}
		targets[t] = append(targets[t], who)
	}
	for _, t := range order {
		if err := d.Reach.Probe(ctx, t); err != nil {
			add("online", t, CheckFail, "unreachable (%v); used by %s", err, strings.Join(targets[t], ", "))
			continue
		}
		add("online", t, CheckOK, "TCP connect succeeded, nothing sent; used by %s", strings.Join(targets[t], ", "))
	}
	return r
}

func pluginChecks(add func(group, name string, st CheckStatus, format string, a ...any), p DoctorPlugins) {
	if p == nil {
		add("plugins", "plugins", CheckSkipped, "not checked")
		return
	}
	src, list, err := p.Plugins()
	if err != nil {
		add("plugins", "allowlist", CheckFail, "%v", err)
		return
	}
	if src == "" || len(list) == 0 {
		where := "no allowlist file"
		if src != "" {
			where = src
		}
		add("plugins", "allowlist", CheckSkipped, "no plugin is allowlisted (%s); a mapper: plugin:<name> would be refused", where)
		return
	}
	add("plugins", "allowlist", CheckOK, "%s: %d plugin(s)", src, len(list))
	for _, pl := range list {
		if pl.Err != "" {
			add("plugins", pl.Name, CheckFail, "%s; pin: %s; %s", pl.Path, pl.Pin, pl.Err)
			continue
		}
		add("plugins", pl.Name, CheckOK, "%s; pin: %s; file and directory are not writable by group or others, no symlink out of the directory", pl.Path, pl.Pin)
	}
}

func usedBy(kind string) string {
	switch kind {
	case "source":
		return "hunt, watch"
	case "feed":
		return "intel"
	case "alert":
		return "watch"
	}
	return "estate"
}

// overlapScope is the --case/--config part of the command the overlap warning suggests.
func overlapScope(req DoctorRequest) string {
	var parts []string
	if req.CaseDir != "" {
		parts = append(parts, "--case "+ShellQuote(req.CaseDir))
	}
	if req.ConfigPath != "" {
		parts = append(parts, "--config "+ShellQuote(req.ConfigPath))
	}
	return strings.Join(parts, " ")
}

func storeChecks(add func(group, name string, st CheckStatus, format string, a ...any), s DoctorStore, scope string) {
	name := s.Path
	if s.WriteErr != "" {
		add("store", name, CheckFail, "not writable by this user: %s", s.WriteErr)
	} else {
		add("store", name, CheckOK, "writable by this user")
	}
	if !s.Exists {
		add("store", name+" (file)", CheckSkipped, "not created yet; the first run creates it")
		return
	}
	if s.OwnerMismatch != "" {
		add("store", name+" (owner)", CheckFail, "%s", s.OwnerMismatch)
	} else {
		add("store", name+" (owner)", CheckOK, "owned by this user")
	}
	if s.LooseMode != "" {
		add("store", name+" (mode)", CheckWarn, "mode %s lets others write the evidence", s.LooseMode)
	}
	switch {
	case s.OpenErr == "":
		add("store", name+" (open)", CheckOK, "opens read-only, schema %d (this build: %d)", s.Schema, s.BuildSchema)
	case s.OpenKind == "behind":
		add("store", name+" (open)", CheckWarn, "schema %d is older than this build (%d); the next writing command migrates it", s.Schema, s.BuildSchema)
	case s.OpenKind == "ahead":
		add("store", name+" (open)", CheckFail, "schema %d is newer than this build (%d): upgrade jb", s.Schema, s.BuildSchema)
	case s.OpenKind == "locked":
		add("store", name+" (open)", CheckFail, "%s", s.OpenErr)
	default:
		add("store", name+" (open)", CheckFail, "does not open read-only: %s", s.OpenErr)
	}
	switch {
	case s.OverlapErr != "":
		add("store", name+" (source labels)", CheckSkipped, "the overlap check did not run: %s", s.OverlapErr)
	case len(s.Overlaps) > 0:
		add("store", name+" (source labels)", CheckWarn, "%s", strings.TrimSpace(SourceOverlapWarning(s.Overlaps, scope)))
	}
}

func join(parts ...string) string {
	var keep []string
	for _, p := range parts {
		if p != "" {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, " ")
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}
