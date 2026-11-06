package jb

import (
	"context"

	"github.com/iksnerd/json-bourne/internal/ops"
)

// hunt, activity and intel. The CLI flag --no-store of RFC 0009 is the property store
// here, read positively (default true): a property may not start with no_.

type huntInput struct {
	Case        string   `jb:"case" desc:"case directory to hunt in (docs/CASE-SPEC.md)"`
	Config      string   `jb:"config" desc:"path to the YAML config (required without case; with case, one of the case's configs)"`
	Window      string   `jb:"window" desc:"length of the window to hunt, ending now (or at until): 90m, 24h or 7d (default 60m; with case, the case's windows.default when it sets one)"`
	Until       string   `jb:"until" desc:"hunt the past window ending at this time (RFC 3339 with a zone, not after now) instead of the one ending now"`
	Search      []string `jb:"search" desc:"narrow every source by a phrase match of this term for this run; send up to 4 terms, ANDed"`
	SearchField string   `jb:"search_field" desc:"field search matches against (default: the source's search_field, else message)"`
	Store       bool     `jb:"store" default:"true" desc:"write the run to the evidence database; false runs over a private temporary store that is deleted when the call returns, so nothing is written (RFC 0009)"`
}

type activityInput struct {
	Case   string `jb:"case" required:"true" desc:"case directory (docs/CASE-SPEC.md); required"`
	Config string `jb:"config" desc:"one of the case's configs (default: the config whose commands: lists this command, else the case's only config)"`
	Window string `jb:"window" desc:"length of the window, ending now (or at until): 90m, 24h or 7d (default 24h, never the case's windows.default)"`
	Until  string `jb:"until" desc:"ask about the past window ending at this time (RFC 3339 with a zone, not after now) instead of the one ending now"`
	Store  bool   `jb:"store" default:"true" desc:"write the run to the evidence database; false runs over a private temporary store that is deleted when the call returns, so nothing is written (RFC 0009)"`
}

type intelInput struct {
	Case   string   `jb:"case" desc:"case directory (docs/CASE-SPEC.md)"`
	Config string   `jb:"config" desc:"path to the YAML config (required without --case; with --case, one of the case's configs)"`
	IPs    []string `jb:"ips" desc:"addresses to look up; none means the distinct values of the config's intel.ip_fields in the latest stored hunt, most frequent first"`
}

// storeArg reads the positive store property. Absent means true, as on the command line.
func storeArg(a argv, in bool) bool { return !a.has("store") || in }

func runOperations() []registered {
	return []registered{
		register("hunt", "Hunt a window",
			"Fetch the last window of events (and the window before it, as the baseline), store them as evidence and run every configured detector. The result is clean only when complete is true: a source or detector that read nothing or failed says so, never an empty success. Over MCP the run is never stored."+untrusted,
			true, ops.CLI{Command: []string{"hunt"}},
			func(ctx context.Context, in huntInput, env Env, a argv) (any, error) {
				window, err := windowArg(a, "window", in.Window)
				if err != nil {
					return nil, err
				}
				until, err := untilArg(a, "until", in.Until)
				if err != nil {
					return nil, err
				}
				opts := HuntOptions{Window: window, Until: until, Env: env, Search: in.Search, SearchField: in.SearchField, NoStore: !storeArg(a, in.Store)}
				if in.Case != "" {
					return both(HuntCase(ctx, in.Case, CaseHuntOptions{HuntOptions: opts, Config: in.Config}))
				}
				if in.Config == "" {
					return nil, usagef("one of case or config is required")
				}
				cfg, err := LoadConfig(in.Config)
				if err != nil {
					return nil, err
				}
				return both(Hunt(ctx, cfg, opts))
			}).fixed("store", false),
		register("activity", "Ask whether an actor is active",
			"Ask whether the actors a case names are active from any client: fetch the window and run the case's fingerprint and behaviour detectors. The verdict is QUIET only when every source and detector completed over the whole window; otherwise it is INCOMPLETE, which is not quiet. Over MCP the run is never stored."+untrusted,
			true, ops.CLI{Command: []string{"activity"}},
			func(ctx context.Context, in activityInput, env Env, a argv) (any, error) {
				window, err := windowArg(a, "window", in.Window)
				if err != nil {
					return nil, err
				}
				until, err := untilArg(a, "until", in.Until)
				if err != nil {
					return nil, err
				}
				return both(Activity(ctx, in.Case, ActivityOptions{Config: in.Config, Window: window, Until: until, Env: env, NoStore: !storeArg(a, in.Store)}))
			}).fixed("store", false),
		register("intel", "Look addresses up in reputation feeds",
			"Ask the reputation feeds of the config (feeds:) about addresses and append each answer, with the time and the feed, to the evidence database. Requests go to the feeds' APIs only, never to the address. A lookup that failed, timed out or was not made is listed and never stored, and complete is then false. Writes the reputation table and contacts third-party services."+untrusted,
			false, ops.CLI{Command: []string{"intel"}, Positional: []string{"ips"}},
			func(ctx context.Context, in intelInput, env Env, _ argv) (any, error) {
				if in.Case == "" && in.Config == "" {
					return nil, usagef("one of case or config is required")
				}
				return both(Intel(ctx, in.Case, in.IPs, IntelOptions{Config: in.Config, Env: env}))
			}),
	}
}
