package jb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/alertlog"
	"github.com/iksnerd/json-bourne/internal/adapters/bgp"
	"github.com/iksnerd/json-bourne/internal/adapters/crtsh"
	"github.com/iksnerd/json-bourne/internal/adapters/dnsfwd"
	"github.com/iksnerd/json-bourne/internal/adapters/dnsptr"
	"github.com/iksnerd/json-bourne/internal/adapters/rdap"
	"github.com/iksnerd/json-bourne/internal/adapters/watchstate"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

// The estate functions record who holds and runs infrastructure into the case's estate
// files (docs/CASE-SPEC.md section 4.5). They are passive: questions go to a DNS
// resolver, an RDAP service and, for the services a case switches on under
// `estate.external` (docs/POLICY.md), a BGP data API, a certificate transparency search
// and the domain's resolvers. No target host or address is ever contacted.

// Notes that travel with every result of the estate functions.
const (
	// EstateNote is carried by [EstateIPResult].
	EstateNote = "An estate map shows who holds and runs infrastructure, not who typed the commands. " +
		"A CDN or proxy edge address's ownership says nothing about the visitor behind it. " +
		"Lookups went to a DNS resolver and an RDAP service only; no address was contacted."
	// EstateExternalNote is carried by [EstateExternalResult] and [EstateRefreshResult].
	EstateExternalNote = "These are candidates and observations, not proof. A name on a certificate may not be live. " +
		"An address, prefix or origin AS that belongs to a CDN, proxy or shared host says nothing about who runs the site or the visitor behind it. " +
		"An estate map shows infrastructure, not who typed the commands. No target host was contacted: the question went to the service named below."
	// EstateDriftNote is carried by [EstateDiffResult].
	EstateDriftNote = "Drift is a difference between two passive observations of the estate, not proof of compromise and not attribution: " +
		"an address, prefix or origin AS that belongs to a CDN, proxy or shared host changes for reasons that say nothing about ownership. " +
		"Only observations made by the same source and the same method are compared; anything else is listed as not comparable. " +
		"A name on a certificate is a candidate, not a live host. An estate map shows infrastructure, not who typed the commands."
)

// Defaults and ceilings of the estate functions. They are the defaults of the CLI
// commands of the same name, which take them from here.
const (
	// EstateDefaultFile is the estate file inside the case's estate directory.
	EstateDefaultFile = "estate.yaml"
	// EstateDefaultMax and EstateMax bound the addresses of [EstateIP] and the
	// distinct targets of [EstateRefresh] in one run. A longer list is refused, never cut.
	EstateDefaultMax = 20
	EstateMax        = 100
	// EstateExternalDefaultMax and EstateExternalMax bound the targets of [EstateASN],
	// [EstateDNS] and [EstateCT] in one run.
	EstateExternalDefaultMax = 10
	EstateExternalMax        = 50
	// EstateDefaultTimeout is the timeout of each lookup of [EstateIP] and [EstateRefresh].
	EstateDefaultTimeout = 10 * time.Second
	// EstateMaxNames is the most names per domain [EstateCT] may be asked to keep.
	EstateMaxNames = 2000
)

const (
	driftStateFile = "estate-drift-state.json"
	driftLogFile   = "estate-drift.log"
)

// EstatePorts replace the network adapters of the estate functions. Their types come
// from internal packages, so a program outside this module cannot name an
// implementation: the zero value, which builds the real adapters from the options, is
// the only value it can use. The module's own tests set them to answer from memory.
// The enable switch of `estate.external` is checked whether or not a port is set.
type EstatePorts struct {
	PTR  core.PTRResolver
	RDAP core.RDAPRegistry
	BGP  core.BGPSource
	CT   core.CTSource
	DNS  core.DNSForward
	// Sleep replaces the wait between two requests to a service.
	Sleep func(ctx context.Context, d time.Duration) error
}

// EstateOptions are the options every estate function shares.
type EstateOptions struct {
	// File is the estate file inside the case's estate directory. Empty means
	// [EstateDefaultFile]. For [EstateDiff] it is the default From; for [EstateRefresh]
	// it is the baseline whose targets are asked again; for [EstatePromote] it is the
	// baseline replaced.
	File string
	// Env resolves the variables the case's config names, such as a webhook of
	// [EstateDiffOptions.Alert]. Nil reads the process environment.
	Env Env
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
	// Ports replace the network adapters; see [EstatePorts].
	Ports EstatePorts
}

func (o EstateOptions) file() string {
	if o.File == "" {
		return EstateDefaultFile
	}
	return o.File
}

func (o EstateOptions) now() func() time.Time {
	if o.Now == nil {
		return time.Now
	}
	return o.Now
}

// EstateAdded counts what a run added to the estate file.
type EstateAdded struct {
	Nodes    int `json:"nodes"`
	Edges    int `json:"edges"`
	Absences int `json:"absences"`
}

// ---- shared helpers ----

func addedOf(mr casefile.MergeResult) EstateAdded {
	return EstateAdded{Nodes: mr.AddedNodes, Edges: mr.AddedEdges, Absences: mr.AddedAbsences}
}

// within returns v, or def when v is zero, and whether it lies in [lo, hi].
func within[T ~int | ~int64](v, def, lo, hi T) (T, bool) {
	if v == 0 {
		v = def
	}
	return v, v >= lo && v <= hi
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func checkEstateFile(file string) error {
	if err := casefile.ValidEstateName(file); err != nil {
		return usagef("estate file name: %v", err)
	}
	return nil
}

// loadEstateBase returns the estate file to merge into, or a new one when it does not
// exist. A file that exists but cannot be read is an error: it may hold evidence.
func loadEstateBase(c *casefile.Case, file string) (*casefile.Estate, error) {
	base := &casefile.Estate{APIVersion: casefile.EstateAPIVersion, ID: "estate", Caveat: casefile.DefaultEstateCaveat}
	existing, err := casefile.LoadEstateFile(c, file)
	switch {
	case err == nil:
		return existing, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%w", err)
	}
	return base, nil
}

// mergeEstate merges the claims into the file and writes it when something was added.
func mergeEstate(c *casefile.Case, file string, base, claims *casefile.Estate) (casefile.MergeResult, bool, error) {
	merged, mr := casefile.MergeEstate(base, claims)
	wrote := mr.AddedNodes+mr.AddedEdges+mr.AddedAbsences > 0
	if wrote {
		if err := casefile.SaveEstateFile(c, file, merged); err != nil {
			return mr, false, fmt.Errorf("%w", err)
		}
	}
	return mr, wrote, nil
}

func loadEstateCase(caseDir string) (*casefile.Case, error) {
	c, err := casefile.Load(caseDir)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return c, nil
}

// estateConfig loads the case's config that carries the `estate:` section. A case with
// no usable config yields nil: the switches then read as all off.
func estateConfig(c *casefile.Case, name string) (*config.File, error) {
	path, err := config.ChooseCaseConfig(c, name, "estate")
	if err != nil {
		if core.IsUsage(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return cfg, nil
}

func splitHostPort(spec string) (host string, err error) {
	host, port, err := net.SplitHostPort(spec)
	if err != nil {
		return "", fmt.Errorf("%q must be HOST:PORT", spec)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%q has no valid port", spec)
	}
	return host, nil
}

func dialTo(spec string) func(ctx context.Context, network, _ string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, spec)
	}
}

// ptrResolver returns the PTR adapter. A custom resolver is a host:port that is not one
// of the addresses being looked up.
func ptrResolver(spec string, timeout time.Duration, targets []netip.Addr) (core.PTRResolver, error) {
	r := dnsptr.New(nil, "system resolver")
	r.Timeout = timeout
	if spec == "" {
		return r, nil
	}
	host, err := splitHostPort(spec)
	if err != nil {
		return nil, err
	}
	if a, err := netip.ParseAddr(host); err == nil {
		for _, t := range targets {
			if a.Unmap() == t {
				return nil, fmt.Errorf("%s is one of the addresses being investigated; it cannot be the resolver", host)
			}
		}
	}
	r.R = &net.Resolver{PreferGo: true, Dial: dialTo(spec)}
	r.Label = "resolver " + spec
	return r, nil
}

// forwardResolver returns the forward-DNS adapter and where it asks. A custom resolver
// is HOST:PORT, and not a name inside any domain being profiled.
func forwardResolver(spec string, timeout time.Duration, domains []string) (*dnsfwd.Resolver, string, error) {
	r := dnsfwd.New(nil, "system resolver (the local hosts file may answer address and CNAME questions first)")
	r.Timeout = timeout
	if spec == "" {
		return r, "the system resolver", nil
	}
	host, err := splitHostPort(spec)
	if err != nil {
		return nil, "", err
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if _, err := netip.ParseAddr(h); err != nil {
		for _, dom := range domains {
			dom, derr := app.NormaliseDomain(dom)
			if derr == nil && (h == dom || strings.HasSuffix(h, "."+dom)) {
				return nil, "", fmt.Errorf("%s is inside %s, the domain being profiled; it cannot be the resolver", host, dom)
			}
		}
	}
	r.R = &net.Resolver{PreferGo: true, Dial: dialTo(spec)}
	r.Label = "resolver " + spec + " (the local hosts file may answer address and CNAME questions first)"
	return r, "resolver " + spec, nil
}

// ---- EstateIP ----

// EstateIPOptions are the options of [EstateIP].
type EstateIPOptions struct {
	EstateOptions
	// RDAPURL is the RDAP service base URL. Empty means the rdap.org bootstrap, which
	// redirects to the registry that holds the address.
	RDAPURL string
	// Resolver is a DNS resolver HOST:PORT for the PTR lookups, not one of the
	// addresses asked about. Empty means the system resolver.
	Resolver string
	// Timeout is the timeout of each lookup, 1s to 1m. Zero means [EstateDefaultTimeout].
	Timeout time.Duration
	// MaxIPs is the most addresses in one run, at most [EstateMax]. Zero means
	// [EstateDefaultMax]. A longer list is refused, not truncated.
	MaxIPs int
}

// EstateIPFailure is a lookup of [EstateIP] that got no answer.
type EstateIPFailure struct {
	IP     string `json:"ip"`
	Lookup string `json:"lookup"` // "rdns" or "rdap"
	Error  string `json:"error"`
}

// EstateIPResult is the account of one [EstateIP] run.
type EstateIPResult struct {
	Note string
	// File is the estate file, relative to the case directory.
	File string
	// Wrote is true when the file changed.
	Wrote     bool
	Addresses int
	Added     EstateAdded
	// Unchanged counts claims that were already recorded.
	Unchanged int
	// Failures are lookups that got no answer: not data, nothing stored for them.
	Failures []EstateIPFailure
	// Conflicts are claims that disagree with one already in the file. The recorded one stays.
	Conflicts []string
}

// Complete reports whether every question got an answer. A real not-found is an answer.
func (r EstateIPResult) Complete() bool { return len(r.Failures) == 0 }

// MarshalJSON prints what `jb estate --output json` prints.
func (r EstateIPResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Note      string            `json:"note"`
		File      string            `json:"file"`
		Complete  bool              `json:"complete"`
		Wrote     bool              `json:"wrote"`
		Addresses int               `json:"addresses"`
		Added     EstateAdded       `json:"added"`
		Unchanged int               `json:"unchanged"`
		Failures  []EstateIPFailure `json:"failures"`
		Conflicts []string          `json:"conflicts"`
	}{r.Note, r.File, r.Complete(), r.Wrote, r.Addresses, r.Added, r.Unchanged, orEmpty(r.Failures), orEmpty(r.Conflicts)})
}

// EstateIP records, for each address, its reverse DNS name and the registration of the
// range that covers it (RDAP) into the case's estate file, as `jb estate --case DIR IP...`
// does. Every node, edge and absence is stamped with its source, the method (the exact
// query) and the time; the file is merged into, never replaced.
//
// The HTTP dialer refuses a connection to the address. Lookups are timed out and
// responses are size-limited. A lookup that failed, timed out, was rate limited or got a
// non-2xx answer is in [EstateIPResult.Failures] and nothing is stored for it, so the
// result is not [EstateIPResult.Complete]. A conflict with a recorded claim is listed
// and the recorded claim stays; check Conflicts as well as Complete.
func EstateIP(ctx context.Context, caseDir string, ips []string, opts EstateIPOptions) (*EstateIPResult, error) {
	if caseDir == "" {
		return nil, usagef("a case directory is required")
	}
	if len(ips) == 0 {
		return nil, usagef("give at least one IP address")
	}
	maxIPs, ok := within(opts.MaxIPs, EstateDefaultMax, 1, EstateMax)
	if !ok {
		return nil, usagef("most addresses per run must be 1 to %d, got %d", EstateMax, opts.MaxIPs)
	}
	timeout, ok := within(opts.Timeout, EstateDefaultTimeout, time.Second, time.Minute)
	if !ok {
		return nil, usagef("timeout must be 1s to 1m, got %s", opts.Timeout)
	}
	file := opts.file()
	if err := checkEstateFile(file); err != nil {
		return nil, err
	}
	addrs := make([]netip.Addr, 0, len(ips))
	for _, a := range ips {
		ip, err := netip.ParseAddr(strings.TrimSpace(a))
		if err != nil || ip.Zone() != "" {
			return nil, usagef("%q is not an IP address", a)
		}
		addrs = append(addrs, ip.Unmap())
	}

	// The options are checked even when a test replaces the adapters.
	rdapURL := opts.RDAPURL
	if rdapURL == "" {
		rdapURL = rdap.DefaultBaseURL
	}
	rc, err := rdap.New(rdapURL)
	if err != nil {
		return nil, usagef("RDAP URL: %v", err)
	}
	rc.Timeout = timeout
	pr, err := ptrResolver(opts.Resolver, timeout, addrs)
	if err != nil {
		return nil, usagef("resolver: %v", err)
	}
	var reg core.RDAPRegistry = rc
	ptr := pr
	if opts.Ports.RDAP != nil {
		reg = opts.Ports.RDAP
	}
	if opts.Ports.PTR != nil {
		ptr = opts.Ports.PTR
	}

	c, err := loadEstateCase(caseDir)
	if err != nil {
		return nil, err
	}
	base, err := loadEstateBase(c, file)
	if err != nil {
		return nil, err
	}
	res, err := app.CollectEstate(ctx, app.EstateDeps{PTR: ptr, RDAP: reg, Now: opts.now()}, app.EstateRequest{IPs: ips, MaxIPs: maxIPs})
	if err != nil {
		if errors.Is(err, app.ErrTooManyIPs) {
			return nil, usagef("%v", err)
		}
		return nil, fmt.Errorf("%w", err)
	}
	mr, wrote, err := mergeEstate(c, file, base, res.Estate)
	if err != nil {
		return nil, err
	}
	out := &EstateIPResult{Note: EstateNote, File: c.Paths.Estate + "/" + file, Wrote: wrote, Addresses: len(res.IPs),
		Added: addedOf(mr), Unchanged: mr.Unchanged, Conflicts: mr.Conflicts}
	for _, f := range res.Failures {
		out.Failures = append(out.Failures, EstateIPFailure{f.IP, f.Lookup, errString(f.Err)})
	}
	return out, nil
}

// ---- external services: EstateASN, EstateDNS, EstateCT ----

// extCollect is the collector of one external service.
type extCollect func(context.Context, app.ExternalDeps, app.ExternalRequest) (app.ExternalResult, error)

// extBuild is what a service adapter is built from.
type extBuild struct {
	timeout  time.Duration
	resolver string
	maxNames int
	targets  []string
}

// extService is what differs between the three external collectors.
type extService struct {
	name     string        // the estate.external entry that enables it
	what     string        // what leaves the machine, for the refusal message
	interval time.Duration // default spacing between requests
	timeout  time.Duration // default timeout of each request
	// build returns the collector and the place the question goes, after the gate.
	build func(cfg *config.File, p EstatePorts, now func() time.Time, o extBuild) (extCollect, app.ExternalDeps, string, error)
}

var extServices = []extService{
	{
		name: config.EstateBGP, what: "the AS numbers and addresses asked about",
		interval: time.Second, timeout: 10 * time.Second,
		build: func(cfg *config.File, p EstatePorts, now func() time.Time, o extBuild) (extCollect, app.ExternalDeps, string, error) {
			base := cfg.Estate.BGPURL
			if base == "" {
				base = bgp.DefaultBaseURL
			}
			c, err := bgp.New(base)
			if err != nil {
				return nil, app.ExternalDeps{}, "", fmt.Errorf("estate.bgp_url: %w", err)
			}
			c.Timeout = o.timeout
			var src core.BGPSource = c
			if p.BGP != nil {
				src = p.BGP
			}
			return app.CollectASN, app.ExternalDeps{BGP: src, Now: now}, base, nil
		},
	},
	{
		name: config.EstateDNS, what: "the domain names asked about",
		interval: 250 * time.Millisecond, timeout: 5 * time.Second,
		build: func(_ *config.File, p EstatePorts, now func() time.Time, o extBuild) (extCollect, app.ExternalDeps, string, error) {
			r, dest, err := forwardResolver(o.resolver, o.timeout, o.targets)
			if err != nil {
				return nil, app.ExternalDeps{}, "", fmt.Errorf("resolver: %w", err)
			}
			var fw core.DNSForward = r
			if p.DNS != nil {
				fw = p.DNS
			}
			return app.CollectDNS, app.ExternalDeps{DNS: fw, Now: now}, dest, nil
		},
	},
	{
		name: config.EstateCrtsh, what: "the domain names asked about",
		interval: time.Second, timeout: 30 * time.Second,
		build: func(cfg *config.File, p EstatePorts, now func() time.Time, o extBuild) (extCollect, app.ExternalDeps, string, error) {
			base := cfg.Estate.CrtshURL
			if base == "" {
				base = crtsh.DefaultBaseURL
			}
			c, err := crtsh.New(base)
			if err != nil {
				return nil, app.ExternalDeps{}, "", fmt.Errorf("estate.crtsh_url: %w", err)
			}
			c.Timeout = o.timeout
			c.MaxNames = o.maxNames
			var src core.CTSource = c
			if p.CT != nil {
				src = p.CT
			}
			return app.CollectCT, app.ExternalDeps{CT: src, Now: now}, base, nil
		},
	},
}

func extServiceByName(name string) *extService {
	for i := range extServices {
		if extServices[i].name == name {
			return &extServices[i]
		}
	}
	return nil
}

// EstateExternalDefaults returns the default timeout and the default spacing between
// requests of an external service: "bgp", "dns" or "crt.sh". Both are zero for any
// other name.
func EstateExternalDefaults(service string) (timeout, minInterval time.Duration) {
	if s := extServiceByName(service); s != nil {
		return s.timeout, s.interval
	}
	return 0, 0
}

// EstateExternalOptions are the options of [EstateASN], [EstateDNS] and [EstateCT].
type EstateExternalOptions struct {
	EstateOptions
	// Config names the case's config with the `estate:` section, as in
	// [CaseHuntOptions.Config]. Empty means the case's only config.
	Config string
	// Timeout is the timeout of each request, 1s to 2m. Zero means the service's default
	// (see [EstateExternalDefaults]).
	Timeout time.Duration
	// MinInterval is the least time between two requests, 0 to 1m. Zero means the
	// service's default; set NoMinInterval to send requests back to back.
	MinInterval   time.Duration
	NoMinInterval bool
	// MaxTargets is the most targets in one run, at most [EstateExternalMax]. Zero means
	// [EstateExternalDefaultMax]. A longer list is refused, not truncated.
	MaxTargets int
	// Resolver is the DNS resolver HOST:PORT, not a name inside a domain being
	// profiled. Only [EstateDNS] takes it. Empty means the system resolver.
	Resolver string
	// MaxNames is the most distinct names kept per domain, 1 to [EstateMaxNames]. Only
	// [EstateCT] takes it. Zero means the adapter's default; more ends the run incomplete.
	MaxNames int
}

// EstateExternalFailure is a question of an external service that got no full answer.
type EstateExternalFailure struct {
	Target string `json:"target"`
	Lookup string `json:"lookup"` // "bgp", "crt.sh" or "dns/<type>"
	Error  string `json:"error"`
}

// EstateExternalResult is the account of one [EstateASN], [EstateDNS] or [EstateCT] run.
type EstateExternalResult struct {
	Note string
	// Notes are reading caveats that belong next to the data.
	Notes []string
	// Service is the estate.external entry that was used: "bgp", "dns" or "crt.sh".
	Service string
	// Asked says where the questions went.
	Asked string
	// File is the estate file, relative to the case directory.
	File  string
	Wrote bool
	// Targets are the canonical forms of what was asked about.
	Targets   []string
	Added     EstateAdded
	Unchanged int
	// Failures are questions that failed, timed out, were rate limited, got a non-2xx
	// answer or were cut at a cap. Nothing is stored for a failed one; a truncated one
	// keeps what was read.
	Failures  []EstateExternalFailure
	Conflicts []string
}

// Complete reports whether every question got an answer in full.
func (r EstateExternalResult) Complete() bool { return len(r.Failures) == 0 }

// MarshalJSON prints what `jb estate asn|dns|ct --output json` prints.
func (r EstateExternalResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Note      string                  `json:"note"`
		Notes     []string                `json:"notes"`
		Service   string                  `json:"service"`
		Asked     string                  `json:"asked"`
		File      string                  `json:"file"`
		Complete  bool                    `json:"complete"`
		Wrote     bool                    `json:"wrote"`
		Targets   []string                `json:"targets"`
		Added     EstateAdded             `json:"added"`
		Unchanged int                     `json:"unchanged"`
		Failures  []EstateExternalFailure `json:"failures"`
		Conflicts []string                `json:"conflicts"`
	}{r.Note, orEmpty(r.Notes), r.Service, r.Asked, r.File, r.Complete(), r.Wrote, orEmpty(r.Targets), r.Added, r.Unchanged,
		orEmpty(r.Failures), orEmpty(r.Conflicts)})
}

// EstateASN records the prefixes an AS announces and who holds it, or the route that
// covers an address and the AS that originates it (a public BGP data API, source
// "bgp"), as `jb estate asn` does. Targets are AS numbers or addresses. They are sent
// to the API, a third party. The case's config must list "bgp" under `estate.external`,
// or the call is refused with a usage error and nothing is sent.
func EstateASN(ctx context.Context, caseDir string, targets []string, opts EstateExternalOptions) (*EstateExternalResult, error) {
	return estateExternal(ctx, config.EstateBGP, caseDir, targets, opts)
}

// EstateDNS records the A, AAAA, CNAME, MX, NS and SPF records of each domain (source
// "dns"), as `jb estate dns` does. Other TXT values are never read into the file. Use
// it for a domain you own or are authorised to profile: the names are sent to the
// resolver, which asks the domain's name servers on your behalf; jb never connects to
// the domain or to an address it resolves to. The case's config must list "dns" under
// `estate.external`, or the call is refused and nothing is sent.
func EstateDNS(ctx context.Context, caseDir string, targets []string, opts EstateExternalOptions) (*EstateExternalResult, error) {
	return estateExternal(ctx, config.EstateDNS, caseDir, targets, opts)
}

// EstateCT records candidate subdomains from a certificate transparency search (source
// "crt.sh") as domain-to-host edges, as `jb estate ct` does. The edges are inferred,
// never stated. The domains are sent to the search, a third party. A result larger than
// opts.MaxNames is cut and the result is incomplete: the names kept are real, the rest
// unknown. The case's config must list "crt.sh" under `estate.external`, or the call is
// refused and nothing is sent.
func EstateCT(ctx context.Context, caseDir string, targets []string, opts EstateExternalOptions) (*EstateExternalResult, error) {
	return estateExternal(ctx, config.EstateCrtsh, caseDir, targets, opts)
}

func estateExternal(ctx context.Context, service, caseDir string, targets []string, opts EstateExternalOptions) (*EstateExternalResult, error) {
	svc := extServiceByName(service)
	if caseDir == "" {
		return nil, usagef("a case directory is required")
	}
	if len(targets) == 0 {
		return nil, usagef("give at least one target")
	}
	maxTargets, ok := within(opts.MaxTargets, EstateExternalDefaultMax, 1, EstateExternalMax)
	if !ok {
		return nil, usagef("most targets per run must be 1 to %d, got %d", EstateExternalMax, opts.MaxTargets)
	}
	timeout, ok := within(opts.Timeout, svc.timeout, time.Second, 2*time.Minute)
	if !ok {
		return nil, usagef("timeout must be 1s to 2m, got %s", opts.Timeout)
	}
	interval := opts.MinInterval
	switch {
	case opts.NoMinInterval:
		interval = 0
	case interval == 0:
		interval = svc.interval
	}
	if interval < 0 || interval > time.Minute {
		return nil, usagef("minimum interval must be 0 to 1m, got %s", opts.MinInterval)
	}
	if opts.Resolver != "" && service != config.EstateDNS {
		return nil, usagef("a resolver applies to the dns service only")
	}
	maxNames := opts.MaxNames
	if service == config.EstateCrtsh {
		var ok bool
		if maxNames, ok = within(maxNames, crtsh.DefaultMaxNames, 1, EstateMaxNames); !ok {
			return nil, usagef("most names per domain must be 1 to %d, got %d", EstateMaxNames, opts.MaxNames)
		}
	} else if maxNames != 0 {
		return nil, usagef("a name limit applies to the crt.sh service only")
	}
	file := opts.file()
	if err := checkEstateFile(file); err != nil {
		return nil, err
	}
	c, err := loadEstateCase(caseDir)
	if err != nil {
		return nil, err
	}
	// The gate comes before any adapter is built and before any request.
	cfg, err := estateConfig(c, opts.Config)
	if err != nil {
		return nil, err
	}
	if cfg == nil || !cfg.EstateEnabled(service) {
		return nil, usagef("the %q service is not enabled, so nothing was sent. It is off by default because %s would leave this machine. "+
			"List it under `estate: {external: [%s]}` in the case's config to allow it (docs/CONFIG.md)", service, svc.what, service)
	}
	collect, deps, dest, err := svc.build(cfg, opts.Ports, opts.now(), extBuild{timeout: timeout, resolver: opts.Resolver, maxNames: maxNames, targets: targets})
	if err != nil {
		return nil, usagef("%v", err)
	}
	deps.Sleep = opts.Ports.Sleep

	base, err := loadEstateBase(c, file)
	if err != nil {
		return nil, err
	}
	res, err := collect(ctx, deps, app.ExternalRequest{Targets: targets, MaxTargets: maxTargets, Interval: interval})
	if err != nil {
		return nil, usagef("%v", err) // the collectors fail only on bad input; a lookup failure is in res.Failures
	}
	mr, wrote, err := mergeEstate(c, file, base, res.Estate)
	if err != nil {
		return nil, err
	}
	out := &EstateExternalResult{Note: EstateExternalNote, Notes: res.Notes, Service: service, Asked: dest,
		File: c.Paths.Estate + "/" + file, Wrote: wrote, Targets: res.Targets, Added: addedOf(mr), Unchanged: mr.Unchanged, Conflicts: mr.Conflicts}
	for _, f := range res.Failures {
		out.Failures = append(out.Failures, EstateExternalFailure{f.Target, f.Lookup, errString(f.Err)})
	}
	return out, nil
}

// ---- EstateRefresh ----

// EstateRefreshOptions are the options of [EstateRefresh].
type EstateRefreshOptions struct {
	EstateOptions
	// Config names the case's config with the `estate:` section. Empty means the
	// case's only config; a case with none switches every external service off.
	Config string
	// RDAPURL, Resolver and Timeout are as in [EstateIPOptions]. Refresh with the same
	// Resolver and RDAPURL as the baseline: another resolver is another method, and its
	// answers are listed as not comparable.
	RDAPURL  string
	Resolver string
	Timeout  time.Duration
	// MaxTargets is the most distinct targets in one run, at most [EstateMax]. Zero
	// means [EstateDefaultMax]. A longer list is refused, not truncated.
	MaxTargets int
}

type (
	// EstateService says whether one collector of a refresh ran, was skipped or had no
	// target. A skipped service means nothing was sent for its targets.
	EstateService = casefile.SnapshotService
	// EstateSnapshotFailure is a lookup of a refresh that did not get a full answer.
	EstateSnapshotFailure = casefile.SnapshotFailure
)

// EstateRefreshResult is the account of one [EstateRefresh] run: the new snapshot.
type EstateRefreshResult struct {
	Note string
	// Snapshot is the id of the new snapshot, a UTC time such as 20261106T100000Z.
	Snapshot string
	// File is the snapshot file, relative to the case directory.
	File string
	// BasedOn is the baseline estate file whose targets were asked again. It is not modified.
	BasedOn  string
	Nodes    int
	Edges    int
	Absences int
	Services []EstateService
	// Failures are the lookups that did not get a full answer. A snapshot with any is
	// written, marked incomplete, and refused by [EstateDiff] and [EstatePromote].
	Failures []EstateSnapshotFailure
}

// Complete reports whether every question was asked and answered in full.
func (r EstateRefreshResult) Complete() bool { return len(r.Failures) == 0 }

// MarshalJSON prints what `jb estate refresh --output json` prints.
func (r EstateRefreshResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Note     string                  `json:"note"`
		Snapshot string                  `json:"snapshot"`
		File     string                  `json:"file"`
		BasedOn  string                  `json:"based_on"`
		Complete bool                    `json:"complete"`
		Nodes    int                     `json:"nodes"`
		Edges    int                     `json:"edges"`
		Absences int                     `json:"absences"`
		Services []EstateService         `json:"services"`
		Failures []EstateSnapshotFailure `json:"failures"`
	}{r.Note, r.Snapshot, r.File, r.BasedOn, r.Complete(), r.Nodes, r.Edges, r.Absences, r.Services, orEmpty(r.Failures)})
}

// EstateRefresh asks again what the baseline estate file records (the domains,
// addresses and AS numbers it was built from) and writes the answers to a new dated
// snapshot, <estate>/snapshots/<UTC time>.yaml, as `jb estate refresh` does. The
// baseline is not touched: a snapshot becomes the baseline only through
// [EstatePromote]. An existing snapshot is never overwritten.
//
// Reverse DNS and RDAP for addresses always run; BGP, DNS and certificate transparency
// run only for the services the case's config lists under `estate.external`. A service
// that is off is skipped and listed in [EstateRefreshResult.Services], and nothing is
// sent for it. A target list longer than opts.MaxTargets is refused whole. Any lookup
// that failed, was cut at a cap or was not asked makes the result incomplete; the
// snapshot is still written.
func EstateRefresh(ctx context.Context, caseDir string, opts EstateRefreshOptions) (*EstateRefreshResult, error) {
	if caseDir == "" {
		return nil, usagef("a case directory is required")
	}
	maxTargets, ok := within(opts.MaxTargets, EstateDefaultMax, 1, EstateMax)
	if !ok {
		return nil, usagef("most targets per run must be 1 to %d, got %d", EstateMax, opts.MaxTargets)
	}
	timeout, ok := within(opts.Timeout, EstateDefaultTimeout, time.Second, time.Minute)
	if !ok {
		return nil, usagef("timeout must be 1s to 1m, got %s", opts.Timeout)
	}
	file := opts.file()
	if err := checkEstateFile(file); err != nil {
		return nil, err
	}
	c, err := loadEstateCase(caseDir)
	if err != nil {
		return nil, err
	}
	base, err := casefile.LoadEstateFile(c, file)
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err) // a missing or corrupt baseline is never an empty one
	}
	targets := app.EstateTargets(base)

	// The switches come from the case's config. No config means nothing external.
	cfg, err := estateConfig(c, opts.Config)
	if err != nil {
		return nil, err
	}
	enabled := func(s string) bool { return cfg != nil && cfg.EstateEnabled(s) }

	now := opts.now()
	rd := app.RefreshDeps{Enabled: enabled, Now: now}
	rd.Estate.Now = now
	rd.Ext.Now, rd.Ext.Sleep = now, opts.Ports.Sleep
	// Address lookups (rdns, rdap).
	var addrs []netip.Addr
	for _, a := range targets.Addresses {
		ip, perr := netip.ParseAddr(a)
		if perr != nil {
			return nil, fmt.Errorf("estate file records %q as an address target, which does not parse", a)
		}
		addrs = append(addrs, ip)
	}
	if len(addrs) > 0 {
		rdapURL := opts.RDAPURL
		if rdapURL == "" {
			rdapURL = rdap.DefaultBaseURL
		}
		rc, err := rdap.New(rdapURL)
		if err != nil {
			return nil, usagef("RDAP URL: %v", err)
		}
		rc.Timeout = timeout
		pr, err := ptrResolver(opts.Resolver, timeout, addrs)
		if err != nil {
			return nil, usagef("resolver: %v", err)
		}
		rd.Estate.PTR, rd.Estate.RDAP = pr, rc
		if opts.Ports.PTR != nil {
			rd.Estate.PTR = opts.Ports.PTR
		}
		if opts.Ports.RDAP != nil {
			rd.Estate.RDAP = opts.Ports.RDAP
		}
	}
	// External collectors: built only when enabled and there is something to ask.
	req := app.RefreshRequest{Base: base, BasedOn: c.Paths.Estate + "/" + file, MaxTargets: maxTargets}
	for i := range extServices {
		s := &extServices[i]
		if !enabled(s.name) {
			continue
		}
		var list []string
		switch s.name {
		case config.EstateBGP:
			list = append(append(list, targets.BGPIPs...), targets.BGPASNs...)
		case config.EstateDNS:
			list = targets.DNS
		case config.EstateCrtsh:
			list = targets.CT
		}
		if len(list) == 0 {
			continue
		}
		_, ed, _, berr := s.build(cfg, opts.Ports, now, extBuild{timeout: timeout, resolver: opts.Resolver, maxNames: crtsh.DefaultMaxNames, targets: list})
		if berr != nil {
			return nil, usagef("%v", berr)
		}
		switch s.name {
		case config.EstateBGP:
			rd.Ext.BGP, req.BGPInterval = ed.BGP, s.interval
		case config.EstateDNS:
			rd.Ext.DNS, req.DNSInterval = ed.DNS, s.interval
		case config.EstateCrtsh:
			rd.Ext.CT, req.CTInterval = ed.CT, s.interval
		}
	}

	snap, err := app.RefreshEstate(ctx, rd, req)
	if err != nil {
		if errors.Is(err, app.ErrTooManyTargets) || errors.Is(err, app.ErrNoTargets) {
			return nil, usagef("%v", err)
		}
		return nil, fmt.Errorf("%w", err)
	}
	rel, err := casefile.WriteEstateSnapshot(c, snap)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return &EstateRefreshResult{Note: EstateExternalNote, Snapshot: snap.ID, File: rel, BasedOn: snap.BasedOn,
		Nodes: len(snap.Estate.Nodes), Edges: len(snap.Estate.Edges), Absences: len(snap.Estate.Absences),
		Services: snap.Services, Failures: snap.Failures}, nil
}

// ---- EstateDiff ----

type (
	// EstateComparison is the comparison of two estate states: what was added, removed
	// and changed, and what could not be compared. Only observations made by the same
	// source and the same method are compared.
	EstateComparison = app.EstateDiff
	// EstateChange is one difference between two observations of the same question.
	EstateChange = app.EstateChange
	// EstateNotComparable is a question that exists on one side only.
	EstateNotComparable = app.NotComparable
	// EstateAlertDelivery counts the alerts of one [EstateDiff] run.
	EstateAlertDelivery = app.DriftDelivery
)

// EstateChangeCounts counts changes by kind.
type EstateChangeCounts struct {
	Added   int `json:"added"`
	Removed int `json:"removed"`
	Changed int `json:"changed"`
}

// EstateDriftFinding is a finding of the estate_drift detector. Its summary holds the
// subject and counts only, never a value.
type EstateDriftFinding struct {
	Detector string         `json:"detector"`
	Tag      string         `json:"tag"`
	Severity string         `json:"severity"`
	Summary  string         `json:"summary"`
	Detail   map[string]any `json:"detail"`
}

// EstateDiffOptions are the options of [EstateDiff].
type EstateDiffOptions struct {
	EstateOptions
	// From and To are the two states: a snapshot id (20261106T100000Z), an estate file
	// name (estate.yaml) or snapshots/<id>.yaml. From defaults to the baseline file
	// (EstateOptions.File), To to the newest snapshot.
	From, To string
	// Alert sends findings that are new to the case's alert sinks: the log in the
	// evidence directory, and any webhook in the config's `alerts:`.
	Alert bool
	// Config names the config whose `alerts:` apply with Alert. Empty means the case's only config.
	Config string
	// TTL is how long an alerted tag stays quiet unless its severity rises, as in
	// [WatchOptions.TTL]. Zero means 3 hours.
	TTL time.Duration
	// Out receives each alert as it is raised. Nil discards: alerts are always
	// appended to the log in the case's evidence directory as well.
	Out io.Writer
}

// EstateDiffResult is the comparison and what it found.
type EstateDiffResult struct {
	Note string `json:"note"`
	EstateComparison
	Counts   map[string]EstateChangeCounts `json:"counts"`
	Findings []EstateDriftFinding          `json:"findings"`
	// Alerts is set when opts.Alert was true.
	Alerts *EstateAlertDelivery `json:"alerts,omitempty"`
}

// EstateDiff reports what changed on the estate between two states, comparing like
// with like, as `jb estate diff` does. It reads two files and sends nothing.
//
// Only observations made by the same source and the same method are compared. A
// question that exists on one side only, because the method or the resolver changed or
// a service was skipped, is in NotComparable with its counts; it is never counted as
// drift and never hidden. Facts are compared as a set of values per node, key, source
// and method; assessments are opinion and are not compared. An incomplete snapshot on
// either side is refused, because its
// missing answers would read as removals, and a corrupt or unknown file is an error,
// never an empty baseline. A nil error means the comparison ran, whether or not it
// found drift. With opts.Alert, a failure to deliver is returned with the result.
func EstateDiff(ctx context.Context, caseDir string, opts EstateDiffOptions) (*EstateDiffResult, error) {
	if caseDir == "" {
		return nil, usagef("a case directory is required")
	}
	ttl := opts.TTL
	if ttl == 0 {
		ttl = app.DefaultWatchTTL
	}
	if ttl < 0 {
		return nil, usagef("ttl must be positive, got %s", opts.TTL)
	}
	file := opts.file()
	if err := checkEstateFile(file); err != nil {
		return nil, err
	}
	c, err := loadEstateCase(caseDir)
	if err != nil {
		return nil, err
	}
	from, to := opts.From, opts.To
	if from == "" {
		from = file
	}
	if to == "" {
		latest, err := casefile.LatestEstateSnapshot(c)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
		if latest == nil {
			return nil, usagef("there is no snapshot to compare with; run `jb estate refresh` (EstateRefresh) for the case first, or name one (--to, To)")
		}
		to = latest.ID
	}
	fs, err := casefile.LoadEstateState(c, from)
	if err != nil {
		return nil, fmt.Errorf("from: %w", err)
	}
	ts, err := casefile.LoadEstateState(c, to)
	if err != nil {
		return nil, fmt.Errorf("to: %w", err)
	}
	diff, err := app.DiffEstates(fs, ts)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	findings := app.DriftFindings(diff)

	cnt := func(typ string) EstateChangeCounts {
		return EstateChangeCounts{diff.Count(app.ChangeAdded, typ), diff.Count(app.ChangeRemoved, typ), diff.Count(app.ChangeChanged, typ)}
	}
	res := &EstateDiffResult{Note: EstateDriftNote, EstateComparison: diff,
		Counts:   map[string]EstateChangeCounts{"all": cnt(""), "nodes": cnt(app.ItemNode), "edges": cnt(app.ItemEdge), "absences": cnt(app.ItemAbsence), "facts": cnt(app.ItemFact)},
		Findings: make([]EstateDriftFinding, 0, len(findings))}
	for _, f := range findings {
		res.Findings = append(res.Findings, EstateDriftFinding{f.Detector, f.Tag, core.SeverityName(f.Severity), f.Summary, f.Detail})
	}
	if !opts.Alert {
		return res, nil
	}
	delivery, derr := deliverDrift(ctx, opts, c, ttl, findings)
	res.Alerts = delivery
	return res, derr
}

func deliverDrift(ctx context.Context, opts EstateDiffOptions, c *casefile.Case, ttl time.Duration, findings []core.Finding) (*app.DriftDelivery, error) {
	if _, err := casefile.Guard(c.EvidenceDir()); err != nil {
		return nil, fmt.Errorf("refusing to write alerts into %s: %w", c.Paths.Evidence, err)
	}
	cfgFile, err := config.ChooseCaseConfig(c, opts.Config, "estate")
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	extra, err := cfg.BuildAlerts(opts.Env)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	evidence := c.EvidenceDir()
	if err := os.MkdirAll(evidence, 0o700); err != nil {
		return nil, fmt.Errorf("evidence directory: %w", err)
	}
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	logSink := &alertlog.Sink{Out: out, Path: filepath.Join(evidence, driftLogFile)}
	var sink core.AlertSink = logSink
	if len(extra) > 0 {
		sink = core.FanOut{Required: logSink, Optional: extra}
	}
	now := opts.now()()
	res, err := app.DeliverDrift(ctx, watchstate.Store{Path: filepath.Join(evidence, driftStateFile)}, sink, now, ttl,
		"estate-drift-"+casefile.SnapshotID(now), findings)
	if err != nil {
		err = fmt.Errorf("%w", err)
	}
	return &res, err
}

// ---- EstatePromote ----

// EstatePromoteResult says what [EstatePromote] did.
type EstatePromoteResult struct {
	// Promoted is the snapshot id that is now the baseline.
	Promoted string `json:"promoted"`
	// Baseline is the baseline estate file, relative to the case directory.
	Baseline string `json:"baseline"`
	// Archived is where the previous baseline was kept.
	Archived string `json:"archived"`
}

// EstatePromote copies the estate map out of a complete snapshot into the baseline
// estate file (opts.File), so later diffs are measured from it, as `jb estate promote`
// does. It is the only way a snapshot becomes the baseline, and it takes effect when
// called: the CLI has no dry run for it, so neither does this function. The current
// baseline is first written to <estate>/archive/ and is never overwritten there.
//
// An incomplete snapshot is refused, and so is one that skipped a service, because the
// new baseline would silently lose that service's claims; both are usage errors.
// Promoting accepts the drift the snapshot shows: the next [EstateDiff] will not report it.
func EstatePromote(caseDir, snapshotID string, opts EstateOptions) (*EstatePromoteResult, error) {
	if caseDir == "" {
		return nil, usagef("a case directory is required")
	}
	file := opts.file()
	if err := checkEstateFile(file); err != nil {
		return nil, err
	}
	if !casefile.ValidSnapshotID(snapshotID) {
		return nil, usagef("%q is not a snapshot id (20261106T100000Z)", snapshotID)
	}
	c, err := loadEstateCase(caseDir)
	if err != nil {
		return nil, err
	}
	archived, err := app.PromoteSnapshot(c, snapshotID, file, opts.now()())
	if err != nil {
		if errors.Is(err, app.ErrNotPromotable) {
			return nil, usagef("%v", err)
		}
		return nil, fmt.Errorf("%w", err)
	}
	return &EstatePromoteResult{Promoted: snapshotID, Baseline: c.Paths.Estate + "/" + file, Archived: archived}, nil
}
