// Package feedloop is the lookup loop shared by the feeds that ask one remote
// question per IP address (greynoise, sansisc). It parses each indicator, stops
// asking after a rate-limit refusal, enforces the per-run cap, honours the context
// and spaces the questions. Answers go in the slice; failures are joined
// *core.LookupError. The standard library and core only.
package feedloop

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Config holds what the loop needs from the feed.
type Config struct {
	MaxLookups  int                                              // questions per run; <= 0 allows none
	MinInterval time.Duration                                    // pause between two questions
	Sleep       func(ctx context.Context, d time.Duration) error // waits d or returns the context's error
	Scrub       func(string) string                              // applied to every failure detail; nil keeps it as is
}

// Run asks one about each indicator, in order. A core.ErrRateLimited answer from one
// stops all later questions.
func Run(ctx context.Context, c Config, indicators []string, one func(ctx context.Context, ind string, addr netip.Addr) (core.Reputation, error)) ([]core.Reputation, error) {
	var (
		out     []core.Reputation
		errs    []error
		asked   int
		stopped error // set after a 429: nothing more is sent
	)
	fail := func(ind string, cause error, detail string) {
		if c.Scrub != nil {
			detail = c.Scrub(detail)
		}
		errs = append(errs, &core.LookupError{Indicator: ind, Err: fmt.Errorf("%w: %s", cause, detail)})
	}
	for _, ind := range indicators {
		addr, perr := netip.ParseAddr(ind)
		if perr != nil || addr.Zone() != "" {
			fail(ind, core.ErrFeedFailed, "not an IP address, not sent")
			continue
		}
		if stopped != nil {
			fail(ind, stopped, "not asked after the feed refused a request")
			continue
		}
		if asked >= c.MaxLookups {
			fail(ind, core.ErrBudgetExceeded, fmt.Sprintf("not asked: the per-run cap is %d lookups", c.MaxLookups))
			continue
		}
		if err := ctx.Err(); err != nil {
			fail(ind, core.ErrFeedFailed, "not asked: "+err.Error())
			continue
		}
		if asked > 0 && c.MinInterval > 0 {
			if err := c.Sleep(ctx, c.MinInterval); err != nil {
				fail(ind, core.ErrFeedFailed, "not asked: "+err.Error())
				continue
			}
		}
		asked++
		rep, err := one(ctx, ind, addr)
		if err != nil {
			if errors.Is(err, core.ErrRateLimited) {
				stopped = core.ErrRateLimited
			}
			errs = append(errs, &core.LookupError{Indicator: ind, Err: err})
			continue
		}
		out = append(out, rep)
	}
	return out, errors.Join(errs...)
}
