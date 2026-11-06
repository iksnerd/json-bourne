package kibana

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/logmap/keycloak"
	"github.com/iksnerd/json-bourne/internal/logmap/requestdump"
)

// ErrUnparsable is returned (wrapped) by a Mapper for a document whose content is
// not in the format the mapper reads. The source counts it in Stats.Unparsable and
// goes on; any other mapper error stops the fetch. A mapper must not use it for a
// bad event time, which is a fault in the document set, not one odd line.
var ErrUnparsable = errors.New("kibana: document does not parse")

// The registry maps a config name to a Mapper. It is the one place a name is
// resolved: the config loader validates against it and the source never switches
// on a name. Later mappers (ecs) are one entry each.
//
// Every mapper emits the canonical field names (docs/CONFIG.md, "Mappers"), so a
// detector's key_field/status_field/path_field mean the same thing on any index.
var mappers = map[string]Mapper{
	"default":       DefaultMap,
	"keycloak":      KeycloakMap,
	"nginx_ingress": NginxIngressMap,
}

// configurable are the built-in mappers that take a mapper_config (data, never a path
// or a command). Each factory checks its config strictly and returns an error that
// names the fault. With no config the factory builds the mapper's defaults.
var configurable = map[string]func(cfg map[string]any) (Mapper, error){
	"request_dump": RequestDumpMapper,
}

// LookupMapper returns the mapper registered under name, with its defaults when the
// mapper is configurable.
func LookupMapper(name string) (Mapper, bool) {
	if m, ok := mappers[name]; ok {
		return m, true
	}
	if f, ok := configurable[name]; ok {
		m, err := f(nil)
		return m, err == nil
	}
	return nil, false
}

// NewMapper builds the mapper registered under name for a mapper_config. A mapper that
// takes no config refuses one, and a configurable mapper refuses a config it does not
// understand; neither is ignored.
func NewMapper(name string, cfg map[string]any) (Mapper, error) {
	if f, ok := configurable[name]; ok {
		return f(cfg)
	}
	m, ok := mappers[name]
	if !ok {
		return nil, fmt.Errorf("unknown mapper %q", name)
	}
	if cfg != nil {
		return nil, fmt.Errorf("mapper_config is only valid with mapper: plugin:<name> or a mapper that takes one (%s); %q takes none", strings.Join(ConfigurableMapperNames(), ", "), name)
	}
	return m, nil
}

// ConfigurableMapperNames lists the built-in mappers that take a mapper_config, sorted.
func ConfigurableMapperNames() []string {
	names := make([]string, 0, len(configurable))
	for n := range configurable {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// MapperFields returns the event fields a configured built-in mapper can emit, or nil
// when the mapper is not one whose output is known from its config.
func MapperFields(name string, cfg map[string]any) []string {
	if name != "request_dump" {
		return nil
	}
	c, err := requestdump.ParseConfig(cfg)
	if err != nil {
		return nil
	}
	m, err := requestdump.New(c)
	if err != nil {
		return nil
	}
	return m.Fields()
}

// MapperNames lists the registered names, sorted.
func MapperNames() []string {
	names := make([]string, 0, len(mappers)+len(configurable))
	for n := range mappers {
		names = append(names, n)
	}
	for n := range configurable {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// reNginx reads the ingress-nginx access line:
//
//	remote_addr - user [time] "METHOD target PROTO" status bytes "referer" "user_agent" ...
//
// Everything after the user agent (request time, upstream name and status, request
// id) is ignored on purpose: the second status in the line is the upstream's, not
// the client's. The referer and user agent are quote-delimited, so a space or a
// login path inside either cannot be mistaken for the request.
var reNginx = regexp.MustCompile(
	`^(\S+) \S+ \S+ \[[^\]]+\] "([A-Z]+) (\S+) [^"]+" (\d{3}) (?:\d+|-) "([^"]*)" "([^"]*)"`)

// NginxIngressMap parses the access line in the document's `message` field.
//
// client_ip is the address nginx accepted the connection from ($remote_addr, the
// first field). Behind a CDN or load balancer that is the edge, not the visitor,
// and X-Forwarded-For is not in this log format, so none is read: attributing a
// request to an address the log does not carry would be a guess.
//
// It emits client_ip, method, path (query string removed), status (an int),
// user_agent, and referer when there is one. "-", nginx's empty value, is omitted.
// Time is the document's @timestamp; Raw is the whole document.
func NginxIngressMap(src map[string]any) (core.Event, error) {
	ts, _ := src["@timestamp"].(string)
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return core.Event{}, fmt.Errorf("kibana: bad or missing @timestamp: %w", err)
	}
	msg, ok := src["message"].(string)
	if !ok {
		return core.Event{}, fmt.Errorf("%w: no text field %q", ErrUnparsable, "message")
	}
	m := reNginx.FindStringSubmatch(msg)
	if m == nil {
		return core.Event{}, fmt.Errorf("%w: message is not an nginx access line", ErrUnparsable)
	}
	ip, err := netip.ParseAddr(m[1])
	if err != nil {
		return core.Event{}, fmt.Errorf("%w: first field is not an IP address", ErrUnparsable)
	}
	status, err := strconv.Atoi(m[4])
	if err != nil {
		return core.Event{}, fmt.Errorf("%w: status", ErrUnparsable)
	}
	path := m[3]
	for i := 0; i < len(path); i++ {
		if path[i] == '?' || path[i] == '#' {
			path = path[:i]
			break
		}
	}
	f := map[string]any{
		"client_ip": ip.String(),
		"method":    m[2],
		"path":      path,
		"status":    status,
	}
	if m[6] != "" && m[6] != "-" {
		f["user_agent"] = m[6]
	}
	if m[5] != "" && m[5] != "-" {
		f["referer"] = m[5]
	}
	raw, err := json.Marshal(src)
	if err != nil {
		return core.Event{}, fmt.Errorf("kibana: marshal raw: %w", err)
	}
	return core.Event{Time: t, Fields: f, Raw: raw}, nil
}

// KeycloakMap adapts the pure Keycloak mapper (internal/logmap/keycloak) to the
// Mapper type: it hands the document over as JSON bytes and translates the
// package's two error kinds into this adapter's. The fields, limits and the reason
// each rule exists are in that package and in docs/WRITING-A-SOURCE.md.
func KeycloakMap(src map[string]any) (core.Event, error) {
	doc, err := json.Marshal(src)
	if err != nil {
		return core.Event{}, fmt.Errorf("kibana: marshal document: %w", err)
	}
	ev, err := keycloak.Map(doc)
	switch {
	case err == nil:
		return ev, nil
	case errors.Is(err, keycloak.ErrUnparsable):
		return core.Event{}, fmt.Errorf("%w: %s", ErrUnparsable, strings.TrimPrefix(err.Error(), keycloak.ErrUnparsable.Error()+": "))
	default:
		return core.Event{}, fmt.Errorf("kibana: %w", err)
	}
}

// RequestDumpMapper builds the request_dump mapper (internal/logmap/requestdump) from a
// mapper_config: client_ip_header, user_agent_header and header_fields. The mapper
// emits only the headers the config names and never a credential header.
func RequestDumpMapper(cfg map[string]any) (Mapper, error) {
	c, err := requestdump.ParseConfig(cfg)
	if err != nil {
		return nil, err
	}
	rd, err := requestdump.New(c)
	if err != nil {
		return nil, err
	}
	return func(src map[string]any) (core.Event, error) {
		doc, err := json.Marshal(src)
		if err != nil {
			return core.Event{}, fmt.Errorf("kibana: marshal document: %w", err)
		}
		ev, err := rd.Map(doc)
		switch {
		case err == nil:
			return ev, nil
		case errors.Is(err, requestdump.ErrUnparsable):
			return core.Event{}, fmt.Errorf("%w: %s", ErrUnparsable, strings.TrimPrefix(err.Error(), requestdump.ErrUnparsable.Error()+": "))
		default:
			return core.Event{}, fmt.Errorf("kibana: %w", err)
		}
	}, nil
}
