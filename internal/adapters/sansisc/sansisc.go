// Package sansisc is a core.Feed for the SANS Internet Storm Center IP API
// (GET <base>/api/ip/<ip>?json). The API needs no key.
//
// What it will and will not do:
//
//   - Passive. It asks the ISC about an address. It never contacts the address. Only a
//     syntactically valid IP is ever put in a request path. The address is sent to the
//     ISC, a third party, which is why the feed exists only when the operator lists it.
//   - Failure is not silence. A timeout, a rate limit, a non-200 other than 404, a body
//     that is too large or does not parse, a cancelled context and an exhausted lookup
//     budget each become a core.LookupError for that indicator. Only a real 404, or a 200
//     that says the ISC holds no report for exactly the address asked, is not_found.
//   - Bounded. At most MaxLookups requests per Lookup call, MinInterval between them,
//     Timeout per request, MaxBody bytes per response. After a 429 nothing more is sent.
//   - No credential exists, so none can leak; redirects are still not followed, because
//     a redirect is a request to a host the operator did not name.
//
// A reputation snapshot is context about an address. It is not attribution: a CDN or
// proxy edge address says nothing about the visitor behind it.
package sansisc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/feedloop"
)

// DefaultBaseURL is the public ISC.
const DefaultBaseURL = "https://isc.sans.edu"

// SourceName is recorded in the reputation table's source column.
const SourceName = "sans-isc"

const userAgent = "json-bourne-intel"

// maxFeedNames bounds how many threat feed names are copied into a verdict.
const maxFeedNames = 5

var _ core.Feed = (*Feed)(nil)

// Feed looks addresses up in the ISC IP API.
type Feed struct {
	BaseURL     string        // scheme://host[:port], no path
	MaxLookups  int           // requests per Lookup call; <= 0 allows none
	MinInterval time.Duration // pause between two requests
	Timeout     time.Duration // per request
	MaxBody     int64         // bytes read from a response; larger is a failure

	Now    func() time.Time                                 // observation time; default time.Now
	Sleep  func(ctx context.Context, d time.Duration) error // default: wait or ctx end
	Client *http.Client                                     // default: built from Timeout, no redirects
}

func (f *Feed) Name() string { return SourceName }

func (f *Feed) String() string {
	return fmt.Sprintf("sansisc.Feed{BaseURL:%s MaxLookups:%d}", f.BaseURL, f.MaxLookups)
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
		Timeout:       f.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Lookup asks the feed about each indicator, in order. Answers are in the slice,
// failures are joined *core.LookupError.
func (f *Feed) Lookup(ctx context.Context, indicators []string) ([]core.Reputation, error) {
	return feedloop.Run(ctx, feedloop.Config{MaxLookups: f.MaxLookups, MinInterval: f.MinInterval, Sleep: f.sleep}, indicators, f.one)
}

// flex is a JSON value that is null, a number or a string; anything else is an error.
type flex struct {
	set bool
	s   string
}

func (v *flex) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch {
	case string(b) == "null":
		return nil
	case len(b) > 0 && b[0] == '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		v.set, v.s = true, s
	case len(b) > 0 && (b[0] == '-' || (b[0] >= '0' && b[0] <= '9')):
		v.set, v.s = true, string(b)
	default:
		return errors.New("expected null, a number or a string")
	}
	return nil
}

func (f *Feed) one(ctx context.Context, ind string, addr netip.Addr) (core.Reputation, error) {
	url := strings.TrimRight(f.BaseURL, "/") + "/api/ip/" + addr.String() + "?json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return core.Reputation{}, fmt.Errorf("%w: build request", core.ErrFeedFailed)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := f.client().Do(req)
	if err != nil {
		return core.Reputation{}, fmt.Errorf("%w: %s", core.ErrFeedFailed, err)
	}
	defer resp.Body.Close()

	// Never trust or quote the body of anything but a 200: an error page can reflect
	// what the request carried.
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
		return core.Reputation{}, fmt.Errorf("%w: read body: %s", core.ErrFeedFailed, err)
	}
	if int64(len(body)) > f.MaxBody {
		return core.Reputation{}, fmt.Errorf("%w: response larger than %d bytes", core.ErrFeedFailed, f.MaxBody)
	}
	var d struct {
		IP *struct {
			Number      string                     `json:"number"`
			Count       flex                       `json:"count"`
			Attacks     flex                       `json:"attacks"`
			MinDate     flex                       `json:"mindate"`
			MaxDate     flex                       `json:"maxdate"`
			ThreatFeeds map[string]json.RawMessage `json:"threatfeeds"`
		} `json:"ip"`
	}
	if err := json.Unmarshal(body, &d); err != nil || d.IP == nil {
		return core.Reputation{}, fmt.Errorf("%w: response is not the expected JSON object", core.ErrFeedFailed)
	}
	got, perr := netip.ParseAddr(d.IP.Number)
	if perr != nil || got.Unmap() != addr.Unmap() {
		// An answer about another address, or about none, is not an answer about this one.
		return core.Reputation{}, fmt.Errorf("%w: response does not describe the address asked", core.ErrFeedFailed)
	}
	if !d.IP.Count.set && !d.IP.Attacks.set && len(d.IP.ThreatFeeds) == 0 {
		return f.rep(ind, core.VerdictNotFound), nil // the ISC holds no report for it
	}
	names := make([]string, 0, len(d.IP.ThreatFeeds))
	for k := range d.IP.ThreatFeeds {
		if c := clean(k, 40); c != "" {
			names = append(names, c)
		}
	}
	sort.Strings(names)
	if len(names) > maxFeedNames {
		names = names[:maxFeedNames]
	}
	feeds := strings.Join(names, ",")
	if feeds == "" {
		feeds = "none"
	}
	verdict := fmt.Sprintf("count=%s;attacks=%s;mindate=%s;maxdate=%s;feeds=%s",
		val(d.IP.Count), val(d.IP.Attacks), val(d.IP.MinDate), val(d.IP.MaxDate), feeds)
	return f.rep(ind, verdict), nil
}

func (f *Feed) rep(ind, verdict string) core.Reputation {
	return core.Reputation{Indicator: ind, Verdict: verdict, Observed: f.now(), Source: SourceName}
}

func val(v flex) string {
	if !v.set {
		return "none"
	}
	if c := clean(v.s, 40); c != "" {
		return c
	}
	return "none"
}

// clean makes a remote string safe to store in a key=value verdict: only letters,
// digits and . _ : - are kept, and the length is capped.
func clean(s string, max int) string {
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
