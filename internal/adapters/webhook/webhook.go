// Package webhook is a core.AlertSink that POSTs a small chat-style JSON body,
// {"text": "..."}, to one URL.
//
// What it will and will not do:
//
//   - The URL is a secret: chat webhooks carry their token in the path. It lives in
//     a Secret, which formats as "[redacted]" under every verb, and it is never put in
//     an error, in the message text, or anywhere this package writes. Errors are built
//     from fixed words and a status code, never from the text of a net/http or net/url
//     error, and a last pass removes the URL and its parts from whatever is returned.
//   - https only. Plain http is accepted for a loopback host and only when
//     AllowInsecureLoopback is set, which exists for tests.
//   - A failure is an error, never a silent drop: a timeout, a network error, any
//     non-2xx status, a redirect (not followed; the token would travel with it) and a
//     response larger than MaxResponse.
//   - Bounded. One request at a time, Timeout each, MinInterval between two requests,
//     at most MaxPerCycle alerts per run (cycle); the rest are replaced by one summary
//     message that says how many were not sent. After a failure in a run nothing more
//     is sent in that run, so an outage costs one timeout, not one per alert.
//   - The message is the finding summary, tag, severity and run, with control
//     characters escaped, markup characters escaped and the length capped. Alerts that
//     are not findings (outages, state problems, the heartbeat) are sent as a fixed
//     sentence: their text is made of error messages from other components, which can
//     name internal hosts. The full text stays in the local log.
//   - Only the webhook host receives traffic.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/iksnerd/json-bourne/internal/core"
)

const userAgent = "json-bourne-alert"

// Secret is a string that never shows itself.
type Secret string

func (Secret) String() string                 { return "[redacted]" }
func (Secret) GoString() string               { return "[redacted]" }
func (Secret) Format(s fmt.State, _ rune)     { _, _ = io.WriteString(s, "[redacted]") }
func (s Secret) reveal() string               { return string(s) }
func (s Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// Limits applied when a Config leaves a value at zero.
const (
	DefaultTimeout     = 10 * time.Second
	DefaultMaxResponse = 4096
	DefaultMaxPerCycle = 10
	DefaultMinInterval = time.Second
	maxTextRunes       = 500
	maxTagRunes        = 100
)

// Config is what New needs.
type Config struct {
	URL         Secret
	MinSeverity core.Severity // alerts below this are not sent (not an error)
	Timeout     time.Duration // per request; zero means DefaultTimeout
	MaxResponse int64         // bytes read from a response; zero means DefaultMaxResponse
	MaxPerCycle int           // alerts per run; zero means DefaultMaxPerCycle
	MinInterval time.Duration // pause between requests; zero means DefaultMinInterval, negative none

	// AllowInsecureLoopback permits http to a loopback host. For tests only.
	AllowInsecureLoopback bool

	Sleep func(ctx context.Context, d time.Duration) error // default: wait or ctx end
}

// Sink delivers alerts to the webhook.
type Sink struct {
	cfg    Config
	url    Secret
	client *http.Client
	scrubs []Secret

	mu         sync.Mutex
	run        string
	sent       int
	suppressed int
	failed     bool
	lastSend   time.Time
	transport  http.RoundTripper // tests only, set before first use
}

var _ core.AlertSink = (*Sink)(nil)

// Validate checks a URL without ever including it in the error.
func Validate(raw Secret, allowInsecureLoopback bool) error {
	u, err := url.Parse(raw.reveal())
	switch {
	case err != nil || u.Host == "" || u.Opaque != "":
		return errors.New("the webhook URL is not an absolute URL")
	case u.User != nil:
		return errors.New("the webhook URL must not carry user info")
	case u.Fragment != "":
		return errors.New("the webhook URL must not carry a fragment")
	case u.Scheme == "https":
	case u.Scheme == "http" && allowInsecureLoopback && IsLoopback(u.Hostname()):
	default:
		return errors.New("the webhook URL must use https")
	}
	return nil
}

// IsLoopback reports whether host is localhost or a loopback address.
func IsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// New validates cfg and returns the sink. Its errors never contain the URL.
func New(cfg Config) (*Sink, error) {
	if err := Validate(cfg.URL, cfg.AllowInsecureLoopback); err != nil {
		return nil, err
	}
	if cfg.Timeout < 0 || cfg.MaxResponse < 0 || cfg.MaxPerCycle < 0 {
		return nil, errors.New("webhook: timeout, response cap and per-cycle cap must not be negative")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxResponse == 0 {
		cfg.MaxResponse = DefaultMaxResponse
	}
	if cfg.MaxPerCycle == 0 {
		cfg.MaxPerCycle = DefaultMaxPerCycle
	}
	if cfg.MinInterval == 0 {
		cfg.MinInterval = DefaultMinInterval
	}
	s := &Sink{cfg: cfg, url: cfg.URL}
	u, _ := url.Parse(s.url.reveal())
	s.scrubs = scrubList(s.url.reveal(), u)
	return s, nil
}

// String and GoString keep the URL out of any formatted dump of the sink.
func (s *Sink) String() string {
	return fmt.Sprintf("webhook.Sink{min_severity:%s max_per_cycle:%d}", core.SeverityName(s.cfg.MinSeverity), s.cfg.MaxPerCycle)
}
func (s *Sink) GoString() string { return s.String() }

func scrubList(raw string, u *url.URL) []Secret {
	set := []Secret{Secret(raw)}
	add := func(v string) {
		if v != "" {
			set = append(set, Secret(v))
		}
	}
	if u != nil {
		add(u.String())
		add(u.EscapedPath())
		add(u.Path)
		add(u.RawQuery)
		for _, seg := range strings.FieldsFunc(u.Path, func(r rune) bool { return r == '/' }) {
			if len(seg) >= 6 { // a token-sized path segment
				add(seg)
			}
		}
		for _, vals := range u.Query() {
			for _, v := range vals {
				if len(v) >= 6 {
					add(v)
				}
			}
		}
	}
	return set
}

// scrub removes the URL and its parts from text.
func (s *Sink) scrub(text string) string {
	for _, x := range s.scrubs {
		text = strings.ReplaceAll(text, x.reveal(), "[redacted]")
	}
	return text
}

func (s *Sink) fail(format string, args ...any) error {
	return errors.New(s.scrub(fmt.Sprintf("webhook: "+format, args...)))
}

func (s *Sink) sleep(ctx context.Context, d time.Duration) error {
	if s.cfg.Sleep != nil {
		return s.cfg.Sleep(ctx, d)
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

func (s *Sink) httpClient() *http.Client {
	if s.client == nil {
		s.client = &http.Client{
			Timeout:   s.cfg.Timeout,
			Transport: s.transport,
			// A redirect would carry the token path to another host. It is a failure.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return s.client
}

// Deliver sends a if it is severe enough. An alert that is below the threshold, or over
// the per-cycle cap, returns nil: it was deliberately not sent, and it is in the log.
func (s *Sink) Deliver(ctx context.Context, a core.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error
	if a.Run != s.run { // a new cycle
		if err := s.flushLocked(ctx); err != nil {
			errs = append(errs, err)
		}
		s.run, s.sent, s.suppressed, s.failed = a.Run, 0, 0, false
	}
	if sev, ok := core.ParseSeverity(a.Severity); !ok || sev >= s.cfg.MinSeverity {
		switch {
		case s.failed:
			errs = append(errs, s.fail("not sent: an earlier request in this cycle failed"))
		case s.sent >= s.cfg.MaxPerCycle:
			s.suppressed++
		default:
			s.sent++
			if err := s.post(ctx, Message(a)); err != nil {
				s.failed = true
				errs = append(errs, err)
			}
		}
	}
	// The heartbeat ends a cycle: say what the cap held back before the cycle is over.
	if a.Kind == core.AlertCycle {
		if err := s.flushLocked(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// flushLocked sends the summary of capped alerts, once. It does not count against the cap.
func (s *Sink) flushLocked(ctx context.Context) error {
	n := s.suppressed
	if n == 0 {
		return nil
	}
	s.suppressed = 0
	if s.failed {
		return s.fail("%d further alert(s) not sent; the webhook failed earlier in this cycle", n)
	}
	text := fmt.Sprintf("%d further alert%s not sent to webhook, see watch.log (run %s)", n, plural(n), escape(s.run, maxTagRunes))
	if err := s.post(ctx, text); err != nil {
		s.failed = true
		return err
	}
	return nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// Message is the text sent for a. It holds the finding summary, tag, severity and run,
// escaped and capped, and nothing else; any other kind of alert is a fixed sentence.
func Message(a core.Alert) string {
	sev := escape(a.Severity, 20)
	tag := escape(a.Tag, maxTagRunes)
	run := escape(a.Run, maxTagRunes)
	if a.Kind != core.AlertFinding {
		return fmt.Sprintf("[%s] %s: %s; details are in watch.log (run %s)", sev, tag, kindSentence(a.Kind), run)
	}
	return fmt.Sprintf("[%s] %s: %s (run %s)", sev, tag, escape(a.Text, maxTextRunes), run)
}

func kindSentence(kind string) string {
	switch kind {
	case core.AlertIncomplete:
		return "a source or detector did not finish, so the result is unknown, not quiet"
	case core.AlertError:
		return "the watch cycle hit an error"
	case core.AlertRecovered:
		return "a component that was reported down finished again"
	case core.AlertCycle:
		return "cycle finished"
	default:
		return "alert"
	}
}

// escape makes untrusted text safe for a chat message: backslash and control characters
// are written as escapes, the characters chat services treat as markup or mentions
// (& < >) as entities, and the result is cut to max runes.
func escape(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		var piece string
		switch {
		case r == '\\':
			piece = `\\`
		case r == '\n':
			piece = `\n`
		case r == '\r':
			piece = `\r`
		case r == '\t':
			piece = `\t`
		case r == '&':
			piece = "&amp;"
		case r == '<':
			piece = "&lt;"
		case r == '>':
			piece = "&gt;"
		case r == utf8.RuneError, r < 0x20, r == 0x7f, (r >= 0x80 && r <= 0x9f), r == 0x2028, r == 0x2029,
			(r >= 0x200b && r <= 0x200f), (r >= 0x202a && r <= 0x202e), (r >= 0x2066 && r <= 0x2069), r == 0xfeff:
			piece = fmt.Sprintf(`\u%04x`, r)
		default:
			piece = string(r)
		}
		if n >= max {
			b.WriteString("...[truncated]")
			break
		}
		b.WriteString(piece)
		n++
	}
	return b.String()
}

func (s *Sink) post(ctx context.Context, text string) error {
	if !s.lastSend.IsZero() && s.cfg.MinInterval > 0 {
		if wait := s.cfg.MinInterval - time.Since(s.lastSend); wait > 0 {
			if err := s.sleep(ctx, wait); err != nil {
				return s.fail("not sent: %s", ctxWord(err))
			}
		}
	}
	s.lastSend = time.Now()

	body, err := json.Marshal(struct {
		Text string `json:"text"`
	}{text})
	if err != nil {
		return s.fail("could not encode the message")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url.reveal(), bytes.NewReader(body))
	if err != nil {
		return s.fail("could not build the request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.httpClient().Do(req)
	if err != nil {
		// The text of a *url.Error contains the URL. Say only what kind of failure it was.
		return s.fail("request failed (%s)", classify(err))
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return s.fail("HTTP %d: redirects are not followed", resp.StatusCode)
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return s.fail("HTTP %d", resp.StatusCode)
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, s.cfg.MaxResponse+1))
	if err != nil {
		return s.fail("could not read the response (%s)", classify(err))
	}
	if n > s.cfg.MaxResponse {
		return s.fail("response larger than %d bytes", s.cfg.MaxResponse)
	}
	return nil
}

func ctxWord(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "cancelled"
}

// classify names a transport failure without quoting it.
func classify(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "connection closed"
	default:
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		var op *net.OpError
		if errors.As(err, &op) {
			return "network error: " + op.Op
		}
		return "network or TLS error"
	}
}
