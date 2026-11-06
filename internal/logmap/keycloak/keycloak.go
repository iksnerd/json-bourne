// Package keycloak maps one Keycloak event-log document to one core.Event.
//
// It is a pure function of the document bytes: no I/O, no clock, no global state,
// standard library and internal/core only. That is deliberate. The same contract
// (docs/WRITING-A-SOURCE.md, "Mapper contract") is what a mapper running as a
// separate process must meet, and the corpus in testdata/corpus is the proof: any
// implementation must produce the same output for every input file.
//
// The document is a log record with an RFC 3339 "@timestamp" and a "message" that
// holds Keycloak's event line, a comma-separated list of key="value" pairs:
//
//	type="LOGIN_ERROR", realmName="...", clientId="...", ipAddress="...", error="...", ...
//
// Rules, each of which answers a way this log can mislead:
//
//   - There is no HTTP status in a Keycloak event. None is invented: the mapper
//     emits the event type and the error string, and "outcome" derived from them.
//   - Keycloak does not escape values. A value an attacker controls (the username
//     typed into a login form) can contain '"' or ', error="x"'. The first
//     occurrence of a key wins, so text injected inside a later value cannot
//     override the type, the error or the address Keycloak wrote before it, and a
//     value ends at a quote that is followed by the end of the line or by the next
//     ", key=" pair. Keycloak writes its own keys (type, realm, client, user, session,
//     address, error) before any detail, so such a key after the first detail key is
//     injected text and is ignored: a username of `x", error="none` cannot turn a
//     successful login into an error or supply an address the line lacks.
//   - Only the keys named in Map are ever read. A TRACE-level line also carries
//     cookies and request URIs (session identifiers, one-time codes); they are not
//     emitted as fields, whatever the line holds.
//   - ipAddress is the peer address Keycloak saw. Behind a CDN or proxy that is the
//     edge, not the visitor, and the line carries no X-Forwarded-For value, so
//     client_ip is the peer and nothing else is consulted.
//   - A username or email is personal data. They are emitted as fields (a detector
//     needs them to group or to read a domain) and never anywhere else; the
//     detectors keep them out of findings.
//   - Input is hostile: sizes are bounded, parsing is linear, nothing panics.
package keycloak

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Limits. A document over a limit is unparsable, never truncated: a clipped line
// would put the wrong value in a field.
const (
	MaxDocBytes     = 64 << 10
	MaxMessageBytes = 16 << 10
	MaxPairs        = 64
	MaxKeyBytes     = 64
	MaxValueBytes   = 2048
)

var (
	// ErrUnparsable marks a document that is not a Keycloak event line. The caller
	// counts it and goes on.
	ErrUnparsable = errors.New("keycloak: document does not parse")
	// ErrBadTime marks a document with no usable @timestamp. It is a fault in the
	// document set, not one odd line, and the caller stops.
	ErrBadTime = errors.New("keycloak: bad or missing @timestamp")
)

func unparsable(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnparsable, fmt.Sprintf(format, a...))
}

// Map turns the JSON bytes of one document into an event.
//
// Fields emitted (all strings): event_type, outcome ("success" or "error"),
// error (when present), client_ip (canonical form of ipAddress, when present),
// username and email (only when present and not empty, "-" or "null"), realm
// (realmName, else realmId) and client_id (clientId). Time is @timestamp; Raw is
// the input bytes.
func Map(doc []byte) (core.Event, error) {
	if len(doc) > MaxDocBytes {
		return core.Event{}, unparsable("document is %d bytes, limit %d", len(doc), MaxDocBytes)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(doc, &obj); err != nil || obj == nil {
		return core.Event{}, unparsable("not a JSON object")
	}
	d := struct{ TS, Msg json.RawMessage }{obj["@timestamp"], obj["message"]}
	var ts string
	if len(d.TS) == 0 || json.Unmarshal(d.TS, &ts) != nil {
		return core.Event{}, ErrBadTime
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return core.Event{}, ErrBadTime
	}
	var msg string
	if len(d.Msg) == 0 || json.Unmarshal(d.Msg, &msg) != nil {
		return core.Event{}, unparsable("no text field %q", "message")
	}
	if len(msg) > MaxMessageBytes {
		return core.Event{}, unparsable("message is %d bytes, limit %d", len(msg), MaxMessageBytes)
	}
	pairs, err := parsePairs(strings.TrimRight(msg, " \t\r\n"))
	if err != nil {
		return core.Event{}, err
	}

	typ := pairs["type"]
	if !validType(typ) {
		return core.Event{}, unparsable("no event type")
	}
	f := map[string]any{"event_type": typ}
	errStr, hasErr := pairs["error"]
	if hasErr && !printable(errStr) {
		return core.Event{}, unparsable("error is not printable text")
	}
	if hasErr && errStr != "" {
		f["error"] = errStr
	}
	if strings.HasSuffix(typ, "_ERROR") || (hasErr && errStr != "") {
		f["outcome"] = "error"
	} else {
		f["outcome"] = "success"
	}
	if v, ok := pairs["ipAddress"]; ok && v != "" && v != "null" && v != "-" {
		ip, err := netip.ParseAddr(v)
		if err != nil {
			return core.Event{}, unparsable("ipAddress is not an IP address")
		}
		f["client_ip"] = ip.Unmap().String()
	}
	for src, dst := range map[string]string{"username": "username", "email": "email", "clientId": "client_id"} {
		if v := pairs[src]; present(v) {
			f[dst] = v
		}
	}
	if v := pairs["realmName"]; present(v) {
		f["realm"] = v
	} else if v := pairs["realmId"]; present(v) {
		f["realm"] = v
	}
	return core.Event{Time: t, Fields: f, Raw: bytes.Clone(doc)}, nil
}

func present(v string) bool { return v != "" && v != "-" && v != "null" }

func validType(s string) bool {
	if len(s) == 0 || len(s) > 64 || s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func printable(s string) bool {
	if len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// headerKeys are the keys Keycloak writes itself, before any user-influenced detail
// (type, realmId, realmName, clientId, userId, sessionId, ipAddress, error). A key from
// this set that turns up after the first key outside it is injected text, not a header:
// without this, a username of `x", error="none` on a successful login (which has no
// error key of its own) made the event an error, and one on a line with no ipAddress
// supplied the client address.
var headerKeys = map[string]struct{}{
	"type": {}, "realmId": {}, "realmName": {}, "clientId": {}, "userId": {},
	"sessionId": {}, "ipAddress": {}, "error": {},
}

// parsePairs reads `key="value", key="value"` left to right in one pass. The first
// occurrence of a key wins, and a header key after a detail key is ignored. Anything that is not that shape is unparsable.
func parsePairs(msg string) (map[string]string, error) {
	out := map[string]string{}
	i, n, count := 0, len(msg), 0
	inDetails := false
	for i < n {
		// key
		j := i
		for j < n && isKeyByte(msg[j]) {
			j++
		}
		if j == i || j-i > MaxKeyBytes || j+1 >= n || msg[j] != '=' || msg[j+1] != '"' {
			return nil, unparsable("not a key=\"value\" list")
		}
		key := msg[i:j]
		start := j + 2
		// value: ends at a quote followed by end of line or by ", key=\"".
		end := -1
		for k := start; k < n; k++ {
			if msg[k] != '"' {
				continue
			}
			if k+1 == n || nextPairAt(msg, k+1) {
				end = k
				break
			}
		}
		if end < 0 {
			return nil, unparsable("unterminated value")
		}
		if end-start > MaxValueBytes {
			return nil, unparsable("value of %q is over %d bytes", key, MaxValueBytes)
		}
		count++
		if count > MaxPairs {
			return nil, unparsable("more than %d pairs", MaxPairs)
		}
		// A header key after the first detail key is text a user put in a detail
		// value, never a second header: see headerKeys.
		if _, hdr := headerKeys[key]; !hdr {
			inDetails = true
		} else if inDetails {
			key = ""
		}
		if _, dup := out[key]; key != "" && !dup {
			out[key] = msg[start:end]
		}
		i = end + 1
		if i < n {
			i += 2 // ", " already checked by nextPairAt
		}
	}
	if count == 0 {
		return nil, unparsable("empty message")
	}
	return out, nil
}

// nextPairAt reports whether msg[p:] starts ", key=\"".
func nextPairAt(msg string, p int) bool {
	if p+1 >= len(msg) || msg[p] != ',' || msg[p+1] != ' ' {
		return false
	}
	q := p + 2
	r := q
	for r < len(msg) && isKeyByte(msg[r]) {
		r++
	}
	return r > q && r-q <= MaxKeyBytes && r+1 < len(msg) && msg[r] == '=' && msg[r+1] == '"'
}

func isKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.'
}
