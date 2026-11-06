package jb

import (
	"context"
	"time"

	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/ops"
)

// The estate operations. They take a duration as text (10s) and an address, a domain or
// an AS number as an element of an array property. Every one of them but the diff
// writes the estate file or a snapshot and, except promote, asks a third party.

type estateIPInput struct {
	Case     string   `jb:"case" required:"true" desc:"case directory (docs/CASE-SPEC.md) (required)"`
	IPs      []string `jb:"ips" required:"true" desc:"IP addresses to record"`
	File     string   `jb:"file" default:"estate.yaml" desc:"estate file name inside the case's estate directory (created if missing, merged into if present)"`
	RDAPURL  string   `jb:"rdap_url" default:"https://rdap.org" desc:"RDAP service base URL (the rdap.org bootstrap redirects to the registry that holds the address)"`
	Resolver string   `jb:"resolver" desc:"DNS resolver HOST:PORT for the PTR lookups (default: the system resolver)"`
	Timeout  string   `jb:"timeout" desc:"timeout for each lookup, 1s to 1m (default 10s)"`
	MaxIPs   int      `jb:"max_ips" default:"20" min:"1" max:"100" desc:"most addresses in one run, at most 100; more is refused, not truncated"`
}

// EstateExtInput is shared by the three external collectors. Timeout and MinInterval
// default to the service's own (see [EstateExternalDefaults]).
type estateExtInput struct {
	Case        string   `jb:"case" required:"true" desc:"case directory (docs/CASE-SPEC.md) (required)"`
	Targets     []string `jb:"targets" required:"true" desc:"what to ask about: AS numbers or addresses for estate_asn, domains for estate_dns and estate_ct"`
	Config      string   `jb:"config" desc:"config with the estate: section (default: the config whose commands: lists this command, else the case's only config)"`
	File        string   `jb:"file" default:"estate.yaml" desc:"estate file name inside the case's estate directory (created if missing, merged into if present)"`
	Timeout     string   `jb:"timeout" desc:"timeout for each request, 1s to 2m (default: the service's own)"`
	MinInterval string   `jb:"min_interval" desc:"least time between two requests, 0 to 1m (default: the service's own; 0s sends requests back to back)"`
	MaxTargets  int      `jb:"max_targets" default:"10" min:"1" max:"50" desc:"most targets in one run, at most 50; more is refused, not truncated"`
}

type estateDNSInput struct {
	estateExtInput
	Resolver string `jb:"resolver" desc:"DNS resolver HOST:PORT (default: the system resolver)"`
}

type estateCTInput struct {
	estateExtInput
	MaxNames int `jb:"max_names" default:"500" min:"1" max:"2000" desc:"most distinct names kept per domain, at most 2000; more ends the run INCOMPLETE"`
}

type estateRefreshInput struct {
	Case       string `jb:"case" required:"true" desc:"case directory (docs/CASE-SPEC.md) (required)"`
	Config     string `jb:"config" desc:"config with the estate: section (default: the config whose commands: lists this command, else the case's only config)"`
	File       string `jb:"file" default:"estate.yaml" desc:"the baseline estate file whose targets are re-asked"`
	RDAPURL    string `jb:"rdap_url" default:"https://rdap.org" desc:"RDAP service base URL"`
	Resolver   string `jb:"resolver" desc:"DNS resolver HOST:PORT for PTR and forward lookups (default: the system resolver)"`
	Timeout    string `jb:"timeout" desc:"timeout for each request, 1s to 1m (default 10s)"`
	MaxTargets int    `jb:"max_targets" default:"20" min:"1" max:"100" desc:"most distinct targets in one run, at most 100; more is refused, not truncated"`
}

// estateDiffInput: alert, config and ttl write to the alert sinks, so only the command
// line and the Go API accept them (cli.only); a tool call never alerts.
type estateDiffInput struct {
	Case   string `jb:"case" required:"true" desc:"case directory (docs/CASE-SPEC.md) (required)"`
	File   string `jb:"file" default:"estate.yaml" desc:"the baseline estate file, the default from"`
	From   string `jb:"from" desc:"the earlier state: snapshot id, or estate file name (default: file)"`
	To     string `jb:"to" desc:"the later state: snapshot id, or estate file name (default: the newest snapshot)"`
	Alert  bool   `jb:"alert" cli:"only" desc:"send findings that are new to the case's alert sinks (log in the evidence directory, and any webhook)"`
	Config string `jb:"config" cli:"only" desc:"with alert: the config whose alerts: apply (default: the config whose commands: lists this command, else the case's only config)"`
	TTL    string `jb:"ttl" cli:"only" desc:"with alert: how long an alerted tag stays quiet unless its severity rises (7d, 3h)"`
}

type estatePromoteInput struct {
	Case     string `jb:"case" required:"true" desc:"case directory (docs/CASE-SPEC.md) (required)"`
	File     string `jb:"file" default:"estate.yaml" desc:"the baseline estate file to replace"`
	Snapshot string `jb:"snapshot" required:"true" desc:"the id of a complete snapshot, such as 20261106T100000Z"`
}

// extOptions reads the options of the external collectors that need conversion.
func extOptions(in estateExtInput, env Env, a argv) (EstateExternalOptions, error) {
	timeout, err := durationArg(a, "timeout", in.Timeout)
	if err != nil {
		return EstateExternalOptions{}, err
	}
	o := EstateExternalOptions{EstateOptions: EstateOptions{File: in.File, Env: env}, Config: in.Config, Timeout: timeout, MaxTargets: in.MaxTargets}
	if a.has("min_interval") {
		d, err := time.ParseDuration(in.MinInterval)
		if err != nil {
			return o, usagef("min_interval %q: not a duration such as 250ms: %v", in.MinInterval, err)
		}
		o.MinInterval, o.NoMinInterval = d, d == 0
	}
	return o, nil
}

func estateOperations() []registered {
	return []registered{
		register("estate_ip", "Record the registration and reverse DNS of addresses",
			"Record, for each address, its reverse DNS name and the registration of the range that covers it (RDAP) into the case's estate file, stamped with source, method and time. The file is merged into, never replaced. Lookups go to a resolver and an RDAP service, never to the address. A lookup that failed is listed and nothing is stored for it (complete is false); a claim that disagrees with a recorded one is a conflict and the recorded one stays. Writes the estate file and contacts third-party services.",
			false, ops.CLI{Command: []string{"estate"}, Positional: []string{"ips"}},
			func(ctx context.Context, in estateIPInput, env Env, a argv) (any, error) {
				timeout, err := durationArg(a, "timeout", in.Timeout)
				if err != nil {
					return nil, err
				}
				return both(EstateIP(ctx, in.Case, in.IPs, EstateIPOptions{EstateOptions: EstateOptions{File: in.File, Env: env},
					RDAPURL: in.RDAPURL, Resolver: in.Resolver, Timeout: timeout, MaxIPs: in.MaxIPs}))
			}),
		register("estate_asn", "Record BGP routes and AS holders",
			"Record the prefixes an AS announces and who holds it, or the route that covers an address and the AS that originates it, from a public BGP data API, into the case's estate file. The targets are sent to that third party. The case's config must list bgp under estate.external, or the call is refused and nothing is sent. Writes the estate file.",
			false, ops.CLI{Command: []string{"estate", "asn"}, Positional: []string{"targets"}},
			func(ctx context.Context, in estateExtInput, env Env, a argv) (any, error) {
				o, err := extOptions(in, env, a)
				if err != nil {
					return nil, err
				}
				return both(EstateASN(ctx, in.Case, in.Targets, o))
			}),
		register("estate_dns", "Record the forward DNS records of domains",
			"Record the A, AAAA, CNAME, MX, NS and SPF records of each domain into the case's estate file. Use it only for a domain you own or are authorised to profile: the names go to a resolver, which asks the domain's name servers on your behalf; jb never connects to the domain. The case's config must list dns under estate.external, or the call is refused and nothing is sent. Writes the estate file.",
			false, ops.CLI{Command: []string{"estate", "dns"}, Positional: []string{"targets"}},
			func(ctx context.Context, in estateDNSInput, env Env, a argv) (any, error) {
				o, err := extOptions(in.estateExtInput, env, a)
				if err != nil {
					return nil, err
				}
				o.Resolver = in.Resolver
				return both(EstateDNS(ctx, in.Case, in.Targets, o))
			}),
		register("estate_ct", "Record candidate subdomains from certificate transparency",
			"Record candidate subdomains from a certificate transparency search as domain-to-host edges in the case's estate file. The edges are inferred, never stated. The domains are sent to the search, a third party. A result larger than max_names is cut and the result is incomplete. The case's config must list crt.sh under estate.external, or the call is refused and nothing is sent. Writes the estate file.",
			false, ops.CLI{Command: []string{"estate", "ct"}, Positional: []string{"targets"}},
			func(ctx context.Context, in estateCTInput, env Env, a argv) (any, error) {
				o, err := extOptions(in.estateExtInput, env, a)
				if err != nil {
					return nil, err
				}
				o.MaxNames = in.MaxNames
				return both(EstateCT(ctx, in.Case, in.Targets, o))
			}),
		register("estate_refresh", "Take a new estate snapshot",
			"Ask again what the baseline estate file records (its domains, addresses and AS numbers) and write the answers to a new dated snapshot. The baseline is not touched; a snapshot becomes the baseline only through estate_promote. Reverse DNS and RDAP always run; BGP, DNS and certificate transparency run only for services the case's config lists under estate.external. Any lookup that failed or was not asked makes the snapshot incomplete. Writes a snapshot file and contacts third-party services.",
			false, ops.CLI{Command: []string{"estate", "refresh"}},
			func(ctx context.Context, in estateRefreshInput, env Env, a argv) (any, error) {
				timeout, err := durationArg(a, "timeout", in.Timeout)
				if err != nil {
					return nil, err
				}
				return both(EstateRefresh(ctx, in.Case, EstateRefreshOptions{EstateOptions: EstateOptions{File: in.File, Env: env},
					Config: in.Config, RDAPURL: in.RDAPURL, Resolver: in.Resolver, Timeout: timeout, MaxTargets: in.MaxTargets}))
			}),
		register("estate_diff", "Compare two estate states",
			"Report what changed on the estate between two states (snapshot ids or estate files), comparing observations made by the same source and the same method only. A question that exists on one side only is listed as not comparable, never counted as drift. An incomplete snapshot on either side is refused. Reads two files and sends nothing."+untrusted,
			true, ops.CLI{Command: []string{"estate", "diff"}},
			func(ctx context.Context, in estateDiffInput, env Env, a argv) (any, error) {
				o := EstateDiffOptions{EstateOptions: EstateOptions{File: in.File, Env: env}, From: in.From, To: in.To, Alert: in.Alert, Config: in.Config}
				if a.has("ttl") {
					ttl, err := config.ParseWindow(in.TTL)
					if err != nil {
						return nil, usagef("ttl: %v", err)
					}
					if ttl <= 0 {
						return nil, usagef("ttl must be positive, got %s", ttl)
					}
					o.TTL = ttl
				}
				return both(EstateDiff(ctx, in.Case, o))
			}),
		register("estate_promote", "Adopt a snapshot as the baseline",
			"Copy the estate map out of a complete snapshot into the baseline estate file, so later diffs are measured from it. The current baseline is first written to the archive and never overwritten there. An incomplete snapshot, or one that skipped a service, is refused. Promoting accepts the drift the snapshot shows: the next diff will not report it. It takes effect when called; there is no dry run.",
			false, ops.CLI{Command: []string{"estate", "promote"}, Positional: []string{"snapshot"}},
			func(_ context.Context, in estatePromoteInput, env Env, _ argv) (any, error) {
				return both(EstatePromote(in.Case, in.Snapshot, EstateOptions{File: in.File, Env: env}))
			}),
	}
}
