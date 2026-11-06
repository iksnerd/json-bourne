// Package requestdump maps one application request-log document to one core.Event.
//
// It is a pure function of the document bytes and a Config: no I/O, no clock, no
// global state, standard library and internal/core only (the same contract as
// internal/logmap/keycloak, and the corpus in testdata/corpus is the proof).
//
// The document is a log record with an RFC 3339 "@timestamp" and a "message" that
// holds the request as a text dump, one item per line:
//
//	=== Request Info ===
//	method = POST
//	path = /v1/example/items?x=1
//	header = User-Agent    value = ExampleAgent/1.0
//	header = X-Edge-Client    value = 198.51.100.7
//
// The dump carries no response status (that is another log record) and no client
// address of its own: the address is a header the edge sets, and which header is the
// operator's to say (Config.ClientIPHeader). Rules, each of which answers a way this
// log can mislead or leak:
//
//   - Only what the Config names is emitted. Headers are an allowlist: the user agent,
//     the optional client-address header and the Config.HeaderFields markers. Every
//     other header, and the whole body of the dump, stays out of the event.
//   - Credential-bearing headers are never emitted, whatever the Config says: a name
//     containing auth, cookie, token, secret, password, session, credential, bearer,
//     jwt, csrf, xsrf or api-key is refused when the Config is built (Denied). The
//     same list redacts Raw: the evidence store keeps the dump with those header
//     values (and the query string of the path, where one-time codes and reset tokens
//     live) replaced by "[redacted]", and nothing else of the document but its time.
//   - A header value is attacker-chosen text. method and path are read only before the
//     first header line, so a header value cannot supply them. A header line is
//     recognised only in the exact shape above, and the first occurrence of a name
//     wins, except that a client-address header that occurs twice is ambiguous and
//     emits no client_ip: guessing which copy the edge wrote would let a request
//     choose its own address.
//   - client_ip is the address in the configured header, and only that. An absent,
//     repeated, list-valued or non-address value emits nothing; the peer address of
//     the connection is not in the dump and is never substituted.
//   - A value over its limit is not truncated into a different value: the document is
//     unparsable, except user_agent, which is cut to MaxUserAgentBytes at a rune
//     boundary (a prefix still matches a prefix pattern, and a client must not be able
//     to leave the log by sending a long one).
//   - Input is hostile: sizes are bounded, parsing is linear, nothing panics.
package requestdump

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Limits. A document over a limit is unparsable, never clipped (see the package comment
// for the one exception).
const (
	MaxDocBytes       = 256 << 10
	MaxMessageBytes   = 64 << 10
	MaxLines          = 512
	MaxHeaders        = 256
	MaxHeaderName     = 64
	MaxPathBytes      = 2048
	MaxMethodBytes    = 16
	MaxValueBytes     = 1024 // a header value read into a field
	MaxUserAgentBytes = 512
	MaxMarkerBytes    = 256
	MaxHeaderFields   = 16

	banner = "=== Request Info ==="
)

var (
	// ErrUnparsable marks a document that is not a request dump. The caller counts it
	// and goes on.
	ErrUnparsable = errors.New("requestdump: document does not parse")
	// ErrBadTime marks a document with no usable @timestamp, a fault in the document
	// set; the caller stops.
	ErrBadTime = errors.New("requestdump: bad or missing @timestamp")
)

func unparsable(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnparsable, fmt.Sprintf(format, a...))
}

// Config says which headers become fields. The zero value reads method, path and the
// user-agent header.
type Config struct {
	// ClientIPHeader names the header the edge sets with the client address. Empty:
	// events carry no client_ip.
	ClientIPHeader string `json:"client_ip_header"`
	// UserAgentHeader names the user-agent header; default "user-agent". The literal
	// "none" turns user_agent off.
	UserAgentHeader string `json:"user_agent_header"`
	// HeaderFields maps an event field name to a header name: the allowlist of markers
	// to expose (for a detector that flags a header no legitimate client sets). The
	// field is present, with the header's value (possibly empty), whenever the header
	// is in the request.
	HeaderFields map[string]string `json:"header_fields"`
}

// reserved are field names a mapper owns; HeaderFields may not shadow them.
var reserved = map[string]struct{}{
	"client_ip": {}, "method": {}, "path": {}, "status": {}, "user_agent": {}, "referer": {},
}

// deniedParts are substrings that mark a header as carrying a credential or session.
var deniedParts = []string{
	"auth", "cookie", "token", "secret", "password", "passwd", "session", "credential",
	"bearer", "jwt", "csrf", "xsrf", "api-key", "apikey", "api_key", "private",
}

// Denied reports whether a header name may never be emitted (see the package comment).
func Denied(name string) bool {
	n := strings.ToLower(name)
	for _, p := range deniedParts {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

// Mapper is a Config that has been checked.
type Mapper struct {
	clientIP string // lower-case header name, "" = none
	ua       string // lower-case header name, "" = none
	fields   map[string]string
	byHeader map[string][]string // header -> field names
}

func headerOK(s string) bool {
	if s == "" || len(s) > MaxHeaderName {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return s[0] != '-'
}

func fieldOK(s string) bool {
	if s == "" || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// New checks c. A header name is letters, digits and '-', compared without case;
// a credential-bearing name is refused (Denied).
func New(c Config) (*Mapper, error) {
	m := &Mapper{fields: map[string]string{}, byHeader: map[string][]string{}}
	check := func(what, h string) (string, error) {
		h = strings.ToLower(strings.TrimSpace(h))
		if !headerOK(h) {
			return "", fmt.Errorf("requestdump: %s %q is not a header name (letters, digits and '-', at most %d)", what, h, MaxHeaderName)
		}
		if Denied(h) {
			return "", fmt.Errorf("requestdump: %s %q looks like a credential or session header and is never emitted", what, h)
		}
		return h, nil
	}
	var err error
	if c.ClientIPHeader != "" {
		if m.clientIP, err = check("client_ip_header", c.ClientIPHeader); err != nil {
			return nil, err
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.UserAgentHeader)) {
	case "":
		m.ua = "user-agent"
	case "none":
	default:
		if m.ua, err = check("user_agent_header", c.UserAgentHeader); err != nil {
			return nil, err
		}
	}
	if len(c.HeaderFields) > MaxHeaderFields {
		return nil, fmt.Errorf("requestdump: header_fields has %d entries, at most %d", len(c.HeaderFields), MaxHeaderFields)
	}
	for f, h := range c.HeaderFields {
		if !fieldOK(f) {
			return nil, fmt.Errorf("requestdump: header_fields field %q must match ^[a-z][a-z0-9_]{0,63}$", f)
		}
		if _, bad := reserved[f]; bad {
			return nil, fmt.Errorf("requestdump: header_fields field %q is a name the mapper owns", f)
		}
		hn, err := check("header_fields."+f, h)
		if err != nil {
			return nil, err
		}
		m.fields[f] = hn
		m.byHeader[hn] = append(m.byHeader[hn], f)
	}
	return m, nil
}

// Fields lists the event field names this mapper can emit beyond method and path, so a
// config check can tell a detector's field is never produced.
func (m *Mapper) Fields() []string {
	out := []string{"method", "path"}
	if m.clientIP != "" {
		out = append(out, "client_ip")
	}
	if m.ua != "" {
		out = append(out, "user_agent")
	}
	for f := range m.fields {
		out = append(out, f)
	}
	return out
}

// ParseConfig decodes a plain-data map (the YAML mapper_config) strictly: an unknown
// key is an error.
func ParseConfig(raw map[string]any) (Config, error) {
	var c Config
	if raw == nil {
		return c, nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return c, fmt.Errorf("requestdump: config is not plain data: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("requestdump: mapper_config: %v", err)
	}
	return c, nil
}

// Map turns the JSON bytes of one document into an event.
//
// Fields (all strings): method, path (query and fragment removed), client_ip (canonical
// form), user_agent, and one field per Config.HeaderFields entry. A field is present
// only when the dump carries it. Time is @timestamp. Raw is the redacted dump (see the
// package comment), not the input.
func (m *Mapper) Map(doc []byte) (core.Event, error) {
	if len(doc) > MaxDocBytes {
		return core.Event{}, unparsable("document is %d bytes, limit %d", len(doc), MaxDocBytes)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(doc, &obj); err != nil || obj == nil {
		return core.Event{}, unparsable("not a JSON object")
	}
	var ts string
	if len(obj["@timestamp"]) == 0 || json.Unmarshal(obj["@timestamp"], &ts) != nil {
		return core.Event{}, ErrBadTime
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return core.Event{}, ErrBadTime
	}
	var msg string
	if len(obj["message"]) == 0 || json.Unmarshal(obj["message"], &msg) != nil {
		return core.Event{}, unparsable("no text field %q", "message")
	}
	if len(msg) > MaxMessageBytes {
		return core.Event{}, unparsable("message is %d bytes, limit %d", len(msg), MaxMessageBytes)
	}
	lines := strings.Split(strings.ReplaceAll(msg, "\r\n", "\n"), "\n")
	if len(lines) > MaxLines {
		return core.Event{}, unparsable("more than %d lines", MaxLines)
	}
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != banner {
		return core.Event{}, unparsable("not a request dump")
	}

	var method, path string
	seen := map[string]int{}    // header name -> occurrences, for the names we read
	vals := map[string]string{} // header name -> first value
	redacted := make([]string, 0, len(lines))
	redacted = append(redacted, lines[0])
	headers, inHeaders := 0, false
	for _, ln := range lines[1:] {
		if name, val, ok := headerLine(ln); ok {
			inHeaders = true
			headers++
			if headers > MaxHeaders {
				return core.Event{}, unparsable("more than %d headers", MaxHeaders)
			}
			low := strings.ToLower(name)
			if Denied(low) {
				redacted = append(redacted, "header = "+name+"    value = [redacted]")
				continue // never read, never kept
			}
			redacted = append(redacted, ln)
			if !m.wants(low) {
				continue
			}
			seen[low]++
			if seen[low] == 1 {
				if len(val) > MaxValueBytes && low != m.ua {
					return core.Event{}, unparsable("header %q is over %d bytes", low, MaxValueBytes)
				}
				vals[low] = val
			}
			continue
		}
		if !inHeaders {
			if v, ok := strings.CutPrefix(ln, "method = "); ok && method == "" {
				method = strings.TrimSpace(v)
			} else if v, ok := strings.CutPrefix(ln, "path = "); ok && path == "" {
				path = strings.TrimSpace(v)
				if i := strings.IndexAny(path, "?#"); i >= 0 {
					redacted = append(redacted, "path = "+path[:i]+"?[redacted]")
					continue
				}
			}
		}
		redacted = append(redacted, ln)
	}
	if !validMethod(method) {
		return core.Event{}, unparsable("no valid method")
	}
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if !validPath(path) {
		return core.Event{}, unparsable("no valid path")
	}
	f := map[string]any{"method": method, "path": path}

	if m.clientIP != "" && seen[m.clientIP] == 1 {
		if ip, err := netip.ParseAddr(vals[m.clientIP]); err == nil {
			f["client_ip"] = ip.Unmap().String()
		}
	}
	if m.ua != "" && seen[m.ua] > 0 {
		if ua := cleanUA(vals[m.ua]); ua != "" {
			f["user_agent"] = ua
		}
	}
	for h, names := range m.byHeader {
		if seen[h] == 0 {
			continue
		}
		v := strings.TrimSpace(vals[h])
		if len(v) > MaxMarkerBytes || !printable(v) {
			continue // not a value to carry; presence of an odd value is not worth a fabricated one
		}
		for _, n := range names {
			f[n] = v
		}
	}

	rawMsg, _ := json.Marshal(strings.Join(redacted, "\n"))
	rawTS, _ := json.Marshal(ts)
	raw := append(append(append([]byte(`{"@timestamp":`), rawTS...), `,"message":`...), rawMsg...)
	raw = append(raw, '}')
	return core.Event{Time: t, Fields: f, Raw: raw}, nil
}

func (m *Mapper) wants(low string) bool {
	if low == m.clientIP && low != "" || low == m.ua && low != "" {
		return true
	}
	_, ok := m.byHeader[low]
	return ok
}

// headerLine reads `header = NAME<blanks>value = VALUE` and nothing looser.
func headerLine(ln string) (name, val string, ok bool) {
	rest, ok := strings.CutPrefix(ln, "header = ")
	if !ok {
		return "", "", false
	}
	i := 0
	for i < len(rest) && isNameByte(rest[i]) {
		i++
	}
	if i == 0 || i > MaxHeaderName {
		return "", "", false
	}
	name, rest = rest[:i], rest[i:]
	j := 0
	for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t') {
		j++
	}
	if j == 0 {
		return "", "", false
	}
	v, ok := strings.CutPrefix(rest[j:], "value =")
	if !ok {
		return "", "", false
	}
	return name, strings.TrimSpace(v), true
}

func isNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

func validMethod(s string) bool {
	if s == "" || len(s) > MaxMethodBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

func validPath(s string) bool {
	return s != "" && len(s) <= MaxPathBytes && s[0] == '/' && printable(s)
}

// printable reports whether s has no control character.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 && s[i] != '\t' || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// cleanUA cuts a user agent to MaxUserAgentBytes on a rune boundary and drops it if it
// carries a control character.
func cleanUA(s string) string {
	s = strings.TrimSpace(s)
	if !printable(s) {
		return ""
	}
	if len(s) > MaxUserAgentBytes {
		s = s[:MaxUserAgentBytes]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
