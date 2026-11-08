// Package greynoise is a core.Feed for GreyNoise-style community lookups
// (GET <base>/v3/community/<ip>).
//
// What it will and will not do:
//
//   - Passive. It asks the feed's API about an address. It never contacts the address.
//     Only a syntactically valid IP is ever put in a request path.
//   - Failure is not silence. A timeout, a rate limit, a non-200 other than 404, a body
//     that is too large or does not parse, a cancelled context and an exhausted lookup
//     budget each become a core.LookupError for that indicator. Only a real 404 (or a
//     200 saying the address was not observed) is a not_found answer.
//   - Bounded. At most MaxLookups requests per Lookup call, MinInterval between them,
//     Timeout per request, MaxBody bytes per response. After a 429 nothing more is sent.
//   - The key goes in a request header and nowhere else. It is scrubbed from everything
//     this package returns, and String and GoString never include it.
//
// A reputation snapshot is context about an address. It is not attribution: a CDN or
// proxy edge address says nothing about the visitor behind it.
package greynoise

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/feedloop"
)

// DefaultBaseURL is the public GreyNoise API.
const DefaultBaseURL = "https://api.greynoise.io"

// SourceName is recorded in the reputation table's source column.
const SourceName = "greynoise:community"

const userAgent = "json-bourne-intel"

var _ core.Feed = (*Feed)(nil)

// Feed looks addresses up in the community API.
type Feed struct {
	BaseURL     string        // scheme://host[:port], no path
	Key         string        // optional; sent in the "key" header, never anywhere else
	MaxLookups  int           // requests per Lookup call; <= 0 allows none
	MinInterval time.Duration // pause between two requests
	Timeout     time.Duration // per request
	MaxBody     int64         // bytes read from a response; larger is a failure

	Now    func() time.Time                                 // observation time; default time.Now
	Sleep  func(ctx context.Context, d time.Duration) error // default: wait or ctx end
	Client *http.Client                                     // default: built from Timeout, no redirects
}

func (f *Feed) Name() string { return SourceName }

// String and GoString keep the key out of any formatted dump of the feed.
func (f *Feed) String() string {
	return fmt.Sprintf("greynoise.Feed{BaseURL:%s keyed:%t MaxLookups:%d}", f.BaseURL, f.Key != "", f.MaxLookups)
}
func (f *Feed) GoString() string { return f.String() }

func (f *Feed) now() time.Time {
	if f.Now != nil {
		return f.Now().UTC()
	}
	return time.Now().UTC()
}

func (f *Feed) sleep(ctx context.Context, d time.Duration) error {
	if f.Sleep != nil {
		return f.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (f *Feed) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{
		Timeout: f.Timeout,
		// A redirect would carry the key header to another host. Treat it as a failure.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// scrub removes the key from text that came from outside or from the network stack.
func (f *Feed) scrub(s string) string {
	if f.Key == "" {
		return s
	}
	return strings.ReplaceAll(s, f.Key, "[redacted]")
}

// Lookup asks the feed about each indicator, in order. See the package comment for the
// contract: answers in the slice, failures as joined *core.LookupError.
func (f *Feed) Lookup(ctx context.Context, indicators []string) ([]core.Reputation, error) {
	return feedloop.Run(ctx, feedloop.Config{MaxLookups: f.MaxLookups, MinInterval: f.MinInterval, Sleep: f.sleep, Scrub: f.scrub}, indicators, f.one)
}

func (f *Feed) one(ctx context.Context, ind string, addr netip.Addr) (core.Reputation, error) {
	url := strings.TrimRight(f.BaseURL, "/") + "/v3/community/" + addr.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return core.Reputation{}, fmt.Errorf("%w: build request", core.ErrFeedFailed)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	if f.Key != "" {
		req.Header.Set("key", f.Key)
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return core.Reputation{}, fmt.Errorf("%w: %s", core.ErrFeedFailed, f.scrub(err.Error()))
	}
	defer resp.Body.Close()

	// Never trust the body of anything but a 200 or a 404; do not quote it either,
	// because a proxy or an error page can reflect request headers.
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return core.Reputation{}, fmt.Errorf("%w: HTTP 429", core.ErrRateLimited)
	case resp.StatusCode == http.StatusNotFound:
		return f.rep(ind, core.VerdictNotFound), nil
	case resp.StatusCode != http.StatusOK:
		return core.Reputation{}, fmt.Errorf("%w: HTTP %d", core.ErrFeedFailed, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, f.MaxBody+1))
	if err != nil {
		return core.Reputation{}, fmt.Errorf("%w: read body: %s", core.ErrFeedFailed, f.scrub(err.Error()))
	}
	if int64(len(body)) > f.MaxBody {
		return core.Reputation{}, fmt.Errorf("%w: response larger than %d bytes", core.ErrFeedFailed, f.MaxBody)
	}
	var d struct {
		Noise          *bool   `json:"noise"`
		Riot           *bool   `json:"riot"`
		Classification *string `json:"classification"`
		LastSeen       string  `json:"last_seen"`
		Message        string  `json:"message"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return core.Reputation{}, fmt.Errorf("%w: response is not the expected JSON object", core.ErrFeedFailed)
	}
	if strings.Contains(strings.ToLower(d.Message), "not observed") {
		return f.rep(ind, core.VerdictNotFound), nil
	}
	if d.Noise == nil && d.Classification == nil {
		// A 200 that says neither "seen" nor "not observed" is not an answer.
		return core.Reputation{}, fmt.Errorf("%w: response has no classification", core.ErrFeedFailed)
	}
	class := "unknown"
	if d.Classification != nil {
		class = f.clean(*d.Classification, 40)
	}
	verdict := fmt.Sprintf("classification=%s;noise=%t;riot=%t;last_seen=%s",
		class, d.Noise != nil && *d.Noise, d.Riot != nil && *d.Riot, f.clean(d.LastSeen, 40))
	return f.rep(ind, verdict), nil
}

func (f *Feed) rep(ind, verdict string) core.Reputation {
	return core.Reputation{Indicator: ind, Verdict: verdict, Observed: f.now(), Source: SourceName}
}

// clean makes a remote string safe to store in a key=value verdict: the key is scrubbed
// first, then only letters, digits and . _ : - are kept, and the length is capped.
func (f *Feed) clean(s string, max int) string {
	s = f.scrub(s)
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == ':', r == '-':
			b.WriteRune(r)
		}
	}
	return b.String()
}
