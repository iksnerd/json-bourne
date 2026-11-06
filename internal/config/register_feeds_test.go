package config

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/dnsbl"
	"github.com/iksnerd/json-bourne/internal/adapters/sansisc"
	"github.com/iksnerd/json-bourne/internal/core"
)

func TestSansISCDefaultsAndValidation(t *testing.T) {
	f, err := parseFeeds(t, "\nfeeds:\n  - type: sans-isc\n")
	if err != nil {
		t.Fatal(err)
	}
	feeds, err := f.BuildFeeds(envOf(nil))
	if err != nil || len(feeds) != 1 {
		t.Fatal(feeds, err)
	}
	s := feeds[0].(*sansisc.Feed)
	if s.BaseURL != sansisc.DefaultBaseURL || s.MaxLookups != 10 || s.MinInterval != time.Second || s.Timeout != 10*time.Second || s.MaxBody != 65536 {
		t.Fatalf("%v", s)
	}
	bad := map[string]string{
		"a key":        "    api_key_env: JB_X\n",
		"http remote":  "    base_url: http://feed.example.com\n",
		"credentials":  "    base_url: https://u:p@feed.example.com\n",
		"path in base": "    base_url: https://feed.example.com/api\n",
		"zero lookups": "    max_lookups: 0\n",
		"long timeout": "    timeout: 5m\n",
		"tiny body":    "    max_response_bytes: 10\n",
	}
	for name, body := range bad {
		if _, err := parseFeeds(t, "\nfeeds:\n  - type: sans-isc\n"+body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parseFeeds(t, "\nfeeds:\n  - type: sans-isc\n    base_url: http://127.0.0.1:9999\n"); err != nil {
		t.Errorf("loopback http must be accepted: %v", err)
	}
}

func dnsblFeed(body string) string {
	return "\nfeeds:\n  - type: dnsbl\n    zone: bl.example.test\n" + body
}

func TestDNSBLIsOffUnlessEnabled(t *testing.T) {
	f, err := parseFeeds(t, dnsblFeed(""))
	if err != nil {
		t.Fatal(err)
	}
	feeds, err := f.BuildFeeds(envOf(nil))
	if err != nil || len(feeds) != 0 {
		t.Fatalf("a dnsbl feed without enabled: true must not be built: %v %v", feeds, err)
	}
	if d := f.DisabledFeeds(); len(d) != 1 || d[0] != "dnsbl:bl.example.test" {
		t.Fatalf("disabled feeds must be reported: %v", d)
	}
	f, err = parseFeeds(t, dnsblFeed("    enabled: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if feeds, _ := f.BuildFeeds(nil); len(feeds) != 0 {
		t.Fatal("enabled: false must not be built")
	}
	f, err = parseFeeds(t, dnsblFeed("    enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	feeds, err = f.BuildFeeds(nil)
	if err != nil || len(feeds) != 1 || feeds[0].Name() != "dnsbl:bl.example.test" {
		t.Fatalf("%v %v", feeds, err)
	}
	d := feeds[0].(*dnsbl.Feed)
	if d.MaxLookups != 10 || d.IPv6 || d.Timeout != 5*time.Second || d.MinInterval != 250*time.Millisecond {
		t.Fatalf("defaults: %+v", d)
	}
}

func TestDNSBLCodesAndValidation(t *testing.T) {
	f, err := parseFeeds(t, dnsblFeed(`    enabled: true
    ipv6: true
    resolver: 192.0.2.53
    return_codes:
      "127.0.0.2": sbl
      "127.0.0.4": xbl
    error_codes: ["127.0.9.9"]
`))
	if err != nil {
		t.Fatal(err)
	}
	feeds, _ := f.BuildFeeds(nil)
	d := feeds[0].(*dnsbl.Feed)
	if d.Codes[netip.MustParseAddr("127.0.0.4")] != "xbl" || !d.IPv6 || len(d.ErrorCodes) != 1 {
		t.Fatalf("%+v", d)
	}
	bad := map[string]string{
		"no zone":        "",
		"bad zone":       "    zone: Bad_Zone\n",
		"upper zone":     "    zone: BL.Example.Test\n",
		"resolver name":  "    resolver: dns.example.com\n",
		"resolver port":  "    resolver: 192.0.2.53:0\n",
		"code not 127":   "    return_codes:\n      \"192.0.2.1\": x\n",
		"code refusal":   "    return_codes:\n      \"127.255.255.254\": x\n",
		"code not ip":    "    return_codes:\n      \"abc\": x\n",
		"label chars":    "    return_codes:\n      \"127.0.0.2\": \"a b;c\"\n",
		"error not 127":  "    error_codes: [\"192.0.2.1\"]\n",
		"zero lookups":   "    max_lookups: 0\n",
		"long timeout":   "    timeout: 5m\n",
		"neg interval":   "    min_interval: -1s\n",
		"unknown key":    "    api_key_env: JB_X\n",
		"http key typed": "    base_url: https://x.example.com\n",
	}
	for name, body := range bad {
		src := "\nfeeds:\n  - type: dnsbl\n"
		if name != "no zone" && name != "bad zone" && name != "upper zone" {
			src += "    zone: bl.example.test\n"
		}
		if _, err := parseFeeds(t, src+body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTwoFeedsWithTheSameNameAreRefused(t *testing.T) {
	two := "\nfeeds:\n  - type: dnsbl\n    zone: bl.example.test\n  - type: dnsbl\n    zone: bl.example.test\n    enabled: true\n"
	if _, err := parseFeeds(t, two); err == nil || !strings.Contains(err.Error(), "dnsbl:bl.example.test") {
		t.Fatalf("a duplicate would make the source column ambiguous: %v", err)
	}
	two = "\nfeeds:\n  - type: greynoise\n  - type: greynoise\n"
	if _, err := parseFeeds(t, two); err == nil {
		t.Fatal("two greynoise feeds share a source name")
	}
	ok := "\nfeeds:\n  - type: greynoise\n  - type: sans-isc\n  - type: dnsbl\n    zone: a.example.test\n  - type: dnsbl\n    zone: b.example.test\n"
	if _, err := parseFeeds(t, ok); err != nil {
		t.Fatalf("distinct names are fine: %v", err)
	}
}

// udpDNS answers every A question under the zone by rule and records the questions.
type udpDNS struct {
	pc    net.PacketConn
	mu    sync.Mutex
	asked []string
}

func newUDPDNS(t *testing.T, rule func(name string) (rcode int, a string)) *udpDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	s := &udpDNS{pc: pc}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			var parts []string
			end := 12
			for q[end] != 0 {
				l := int(q[end])
				parts = append(parts, string(q[end+1:end+1+l]))
				end += l + 1
			}
			end += 5
			name := strings.Join(parts, ".")
			s.mu.Lock()
			s.asked = append(s.asked, name)
			s.mu.Unlock()
			rc, a := rule(name)
			out := append([]byte(nil), q[:end]...)
			out[2], out[3] = 0x81, 0x80|byte(rc)
			out[6], out[7], out[8], out[9], out[10], out[11] = 0, 0, 0, 0, 0, 0
			if a != "" {
				out[7] = 1
				out = append(out, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				out = append(out, net.ParseIP(a).To4()...)
			}
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return s
}

func TestDNSBLBuiltFromConfigAsksOnlyTheConfiguredResolver(t *testing.T) {
	srv := newUDPDNS(t, func(name string) (int, string) {
		if strings.HasPrefix(name, "1.2.0.192.") {
			return 0, "127.0.0.2"
		}
		return 3, ""
	})
	f, err := parseFeeds(t, dnsblFeed("    enabled: true\n    min_interval: 0s\n    resolver: "+srv.pc.LocalAddr().String()+"\n    return_codes:\n      \"127.0.0.2\": sbl\n"))
	if err != nil {
		t.Fatal(err)
	}
	feeds, err := f.BuildFeeds(nil)
	if err != nil {
		t.Fatal(err)
	}
	rs, lerr := feeds[0].Lookup(context.Background(), []string{"192.0.2.1", "192.0.2.2"})
	if lerr != nil || len(rs) != 2 {
		t.Fatal(rs, lerr)
	}
	if rs[0].Verdict != "listed=true;zone=bl.example.test;codes=127.0.0.2:sbl" || rs[1].Verdict != core.VerdictNotFound {
		t.Fatalf("%+v", rs)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, q := range srv.asked {
		if !strings.HasSuffix(q, ".bl.example.test") {
			t.Fatalf("a question outside the zone: %q", q)
		}
	}
}

func TestServicesDescribeWhatLeavesTheMachineWithoutAnySecret(t *testing.T) {
	f, err := Parse([]byte(hunt + `
feeds:
  - type: greynoise
    api_key_env: JB_GREYNOISE_API_KEY
  - type: sans-isc
  - type: dnsbl
    zone: bl.example.test
alerts:
  - type: webhook
    url_env: JB_WEBHOOK_URL
estate:
  external: [bgp]
`))
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]ServiceInfo{}
	for _, s := range f.Services() {
		by[s.Kind+":"+s.Type] = s
		if s.Leaves == "" {
			t.Errorf("%s:%s says nothing about what leaves the machine", s.Kind, s.Type)
		}
	}
	if k := by["source:kibana"]; k.Host != "kibana.example.com:443" || !k.Enabled || len(k.EnvVars) != 1 || k.EnvVars[0] != "JB_KIBANA_API_KEY" {
		t.Errorf("kibana: %+v", k)
	}
	if g := by["feed:greynoise"]; g.Host != "api.greynoise.io:443" || len(g.EnvVars) != 1 {
		t.Errorf("greynoise: %+v", g)
	}
	if s := by["feed:sans-isc"]; s.Host != "isc.sans.edu:443" || len(s.EnvVars) != 0 {
		t.Errorf("sans-isc: %+v", s)
	}
	if d := by["feed:dnsbl"]; d.Enabled || d.Name != "dnsbl:bl.example.test" {
		t.Errorf("dnsbl must be listed as disabled: %+v", d)
	}
	if w := by["alert:webhook"]; w.Host != "" || w.HostEnv != "JB_WEBHOOK_URL" || len(w.EnvVars) != 1 {
		t.Errorf("webhook: the host is in a secret and is not known from the file: %+v", w)
	}
	if e := by["estate:bgp"]; !e.Enabled || e.Host != "stat.ripe.net:443" {
		t.Errorf("estate bgp: %+v", e)
	}
	if e := by["estate:crt.sh"]; e.Enabled {
		t.Errorf("crt.sh is off by default: %+v", e)
	}
}
