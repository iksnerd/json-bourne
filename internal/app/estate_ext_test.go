package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/core"
)

var extNow = func() time.Time { return time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC) }

// loads proves a result is something the estate loader accepts: every claim has a
// source on the allowlist, a method and a time, and every edge endpoint exists.
func loads(t *testing.T, e *casefile.Estate) *casefile.Estate {
	t.Helper()
	full := *e
	full.APIVersion, full.ID, full.Caveat = casefile.EstateAPIVersion, "estate", casefile.DefaultEstateCaveat
	if len(full.Nodes) == 0 {
		return &full
	}
	data, err := casefile.MarshalEstate(&full)
	if err != nil {
		t.Fatal(err)
	}
	got, err := casefile.ParseEstate(data)
	if err != nil {
		t.Fatalf("the loader rejects what the collector produced: %v\n%s", err, data)
	}
	return got
}

func hasEdge(e *casefile.Estate, from, to, rel, source string) (casefile.Edge, bool) {
	for _, x := range e.Edges {
		if x.From == from && x.To == to && x.Relation == rel && x.Source == source {
			return x, true
		}
	}
	return casefile.Edge{}, false
}

func hasNode(e *casefile.Estate, id string) bool {
	for _, n := range e.Nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

type sleeps struct{ d []time.Duration }

func (s *sleeps) sleep(_ context.Context, d time.Duration) error { s.d = append(s.d, d); return nil }

// ---- asn ----

type stubBGP struct {
	asnAns map[uint32]core.BGPAnnouncement
	asnErr map[uint32]error
	ipAns  map[string]core.BGPOrigin
	ipErr  map[string]error
	asked  []string
}

func (s *stubBGP) LookupASN(_ context.Context, n uint32) (core.BGPAnnouncement, error) {
	s.asked = append(s.asked, fmt.Sprintf("AS%d", n))
	a := s.asnAns[n]
	a.Query = fmt.Sprintf("GET https://bgp.example.com/AS%d", n)
	return a, s.asnErr[n]
}

func (s *stubBGP) LookupIP(_ context.Context, ip netip.Addr) (core.BGPOrigin, error) {
	s.asked = append(s.asked, ip.String())
	o := s.ipAns[ip.String()]
	o.Query = "GET https://bgp.example.com/" + ip.String()
	return o, s.ipErr[ip.String()]
}

func okBGP() *stubBGP {
	return &stubBGP{
		asnAns: map[uint32]core.BGPAnnouncement{64500: {
			Holder:   core.BGPHolder{Holder: "EXAMPLE-AS Example\nNetwork Operator"},
			Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")},
		}},
		ipAns: map[string]core.BGPOrigin{"192.0.2.10": {
			Prefix: netip.MustParsePrefix("192.0.2.0/24"),
			Origin: []core.BGPHolder{{ASN: 64500, Holder: "EXAMPLE-AS"}, {ASN: 64501, Holder: "OTHER-AS"}},
		}},
	}
}

func extDeps(b *stubBGP, ct core.CTSource, dns core.DNSForward, s *sleeps) ExternalDeps {
	d := ExternalDeps{CT: ct, DNS: dns, Now: extNow}
	if b != nil {
		d.BGP = b
	}
	if s != nil {
		d.Sleep = s.sleep
	}
	return d
}

func TestCollectASNRecordsPrefixesOriginAndHolder(t *testing.T) {
	res, err := CollectASN(context.Background(), extDeps(okBGP(), nil, nil, nil),
		ExternalRequest{Targets: []string{"AS64500", "64500", "192.0.2.10"}, MaxTargets: 5})
	if err != nil || !res.Complete() {
		t.Fatalf("%v %+v", err, res.Failures)
	}
	if len(res.Targets) != 2 {
		t.Errorf("AS64500 and 64500 are one target: %v", res.Targets)
	}
	e := loads(t, res.Estate)
	for _, want := range [][4]string{
		{"network:192.0.2.0/24", "asn:as64500", "originated_by", "bgp"},
		{"network:2001:db8::/32", "asn:as64500", "originated_by", "bgp"},
		{"asn:as64500", "org:example-as-example-network-operator", "held_by", "bgp"},
		{"ip:192.0.2.10", "network:192.0.2.0/24", "announced_in", "bgp"},
		{"network:192.0.2.0/24", "asn:as64501", "originated_by", "bgp"},
	} {
		if _, ok := hasEdge(e, want[0], want[1], want[2], want[3]); !ok {
			t.Errorf("missing edge %v", want)
		}
	}
	for _, n := range e.Nodes {
		if n.Source != "bgp" || n.Method == "" || n.Observed != "2026-11-06T10:00:00Z" {
			t.Errorf("node %+v lacks provenance", n)
		}
	}
	joined := strings.Join(res.Notes, "\n")
	for _, w := range []string{"CDN", "not who runs the site", "no address was contacted"} {
		if !strings.Contains(joined, w) {
			t.Errorf("notes lack %q: %s", w, joined)
		}
	}
}

func TestCollectASNNotFoundIsAnAbsenceAndFailureIsNeither(t *testing.T) {
	b := okBGP()
	b.asnErr = map[uint32]error{64500: fmt.Errorf("%w: no prefix", core.ErrNotFound), 64502: fmt.Errorf("%w: HTTP 503", core.ErrLookupFailed)}
	b.ipErr = map[string]error{"192.0.2.10": fmt.Errorf("%w: HTTP 500", core.ErrLookupFailed), "192.0.2.11": fmt.Errorf("%w: none", core.ErrNotFound)}
	res, err := CollectASN(context.Background(), extDeps(b, nil, nil, nil),
		ExternalRequest{Targets: []string{"AS64500", "AS64502", "192.0.2.10", "192.0.2.11"}, MaxTargets: 5})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() || len(res.Failures) != 2 {
		t.Fatalf("failures %+v", res.Failures)
	}
	e := loads(t, res.Estate)
	if len(e.Absences) != 2 {
		t.Errorf("absences %+v", e.Absences)
	}
	for _, id := range []string{"asn:as64502", "ip:192.0.2.10"} {
		if hasNode(e, id) {
			t.Errorf("%s was stored although its lookup failed", id)
		}
		for _, a := range e.Absences {
			if a.Subject == id {
				t.Errorf("a failure was recorded as an absence: %+v", a)
			}
		}
	}
	if !hasNode(e, "asn:as64500") || !hasNode(e, "ip:192.0.2.11") {
		t.Error("a real not-found records the subject it was asked about")
	}
}

func TestCollectASNTruncationIsIncompleteAndKeepsWhatWasRead(t *testing.T) {
	b := okBGP()
	a := b.asnAns[64500]
	a.Truncated = true
	b.asnAns[64500] = a
	res, _ := CollectASN(context.Background(), extDeps(b, nil, nil, nil), ExternalRequest{Targets: []string{"AS64500"}, MaxTargets: 1})
	if res.Complete() || len(res.Failures) != 1 || !errors.Is(res.Failures[0].Err, core.ErrTruncated) {
		t.Fatalf("a cut list must be a failure: %+v", res.Failures)
	}
	if e := loads(t, res.Estate); !hasNode(e, "network:192.0.2.0/24") {
		t.Error("the prefixes that were read are real and are kept")
	}
}

func TestCollectASNRateLimitStopsTheRun(t *testing.T) {
	b := okBGP()
	b.asnErr = map[uint32]error{64500: fmt.Errorf("%w: HTTP 429", core.ErrRateLimited)}
	res, _ := CollectASN(context.Background(), extDeps(b, nil, nil, nil), ExternalRequest{Targets: []string{"AS64500", "AS64501", "AS64502"}, MaxTargets: 5})
	if len(b.asked) != 1 {
		t.Errorf("asked %v after a 429", b.asked)
	}
	if len(res.Failures) != 3 {
		t.Errorf("every target not answered is a failure: %+v", res.Failures)
	}
}

func TestExternalRunsRefuseBadOrTooManyTargets(t *testing.T) {
	d := extDeps(okBGP(), &stubCT{}, &stubFwd{}, nil)
	for name, run := range map[string]func(string, ...string) error{
		"asn": func(_ string, t ...string) error {
			_, err := CollectASN(context.Background(), d, ExternalRequest{Targets: t, MaxTargets: 2})
			return err
		},
		"ct": func(_ string, t ...string) error {
			_, err := CollectCT(context.Background(), d, ExternalRequest{Targets: t, MaxTargets: 2})
			return err
		},
		"dns": func(_ string, t ...string) error {
			_, err := CollectDNS(context.Background(), d, ExternalRequest{Targets: t, MaxTargets: 2})
			return err
		},
	} {
		first := "example.com"
		if name == "asn" {
			first = "AS64500"
		}
		if err := run(name, first, "b.example.com", "c.example.com"); !errors.Is(err, ErrTooManyTargets) {
			if name != "asn" || !strings.Contains(fmt.Sprint(err), "neither") {
				t.Errorf("%s: more than the cap is refused whole: %v", name, err)
			}
		}
		if err := run(name); err == nil {
			t.Errorf("%s: no targets must be an error", name)
		}
		if err := run(name, "not a target!"); err == nil {
			t.Errorf("%s: a bad target must be an error before anything is asked", name)
		}
	}
	b := okBGP()
	if _, err := CollectASN(context.Background(), extDeps(b, nil, nil, nil), ExternalRequest{Targets: []string{"AS64500", "AS1", "AS2"}, MaxTargets: 2}); !errors.Is(err, ErrTooManyTargets) || len(b.asked) != 0 {
		t.Errorf("%v asked %v", err, b.asked)
	}
}

func TestRequestsAreSpaced(t *testing.T) {
	s := &sleeps{}
	b := okBGP()
	_, _ = CollectASN(context.Background(), extDeps(b, nil, nil, s), ExternalRequest{Targets: []string{"AS64500", "AS64501", "192.0.2.10"}, MaxTargets: 5, Interval: 750 * time.Millisecond})
	if len(s.d) != 2 || s.d[0] != 750*time.Millisecond {
		t.Errorf("sleeps %v: one wait between each pair of requests, none before the first", s.d)
	}
}

func TestACancelledRunAsksNothingAndSaysSo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := okBGP()
	res, _ := CollectASN(ctx, extDeps(b, nil, nil, nil), ExternalRequest{Targets: []string{"AS64500"}, MaxTargets: 1})
	if len(b.asked) != 0 || res.Complete() {
		t.Errorf("asked %v failures %+v", b.asked, res.Failures)
	}
}

// ---- ct ----

type stubCT struct {
	ans   map[string]core.CTAnswer
	errs  map[string]error
	asked []string
}

func (s *stubCT) LookupSubdomains(_ context.Context, d string) (core.CTAnswer, error) {
	s.asked = append(s.asked, d)
	a := s.ans[d]
	a.Query = "GET https://ct.example.com/?q=%25." + d
	return a, s.errs[d]
}

func TestCollectCTRecordsCandidatesAsInferredEdges(t *testing.T) {
	ct := &stubCT{ans: map[string]core.CTAnswer{"example.com": {Names: []string{"api.example.com", "www.example.com"}, Wildcards: 2, OutOfScope: 1}}}
	res, err := CollectCT(context.Background(), extDeps(nil, ct, nil, nil), ExternalRequest{Targets: []string{"Example.COM.", "example.com"}, MaxTargets: 3})
	if err != nil || !res.Complete() || len(ct.asked) != 1 {
		t.Fatalf("%v %+v asked %v", err, res.Failures, ct.asked)
	}
	e := loads(t, res.Estate)
	x, ok := hasEdge(e, "domain:example.com", "host:api.example.com", "ct_candidate", "crt.sh")
	if !ok || x.Confidence != "inferred" || !strings.Contains(x.InferredFrom, "candidate") {
		t.Fatalf("a CT name is a candidate, never a stated fact: %+v ok=%v", x, ok)
	}
	joined := strings.Join(res.Notes, "\n")
	for _, w := range []string{"candidates", "not confirmed live", "2 wildcard", "no host was contacted"} {
		if !strings.Contains(joined, w) {
			t.Errorf("notes lack %q:\n%s", w, joined)
		}
	}
}

func TestCollectCTTruncationIsIncomplete(t *testing.T) {
	ct := &stubCT{ans: map[string]core.CTAnswer{"example.com": {Names: []string{"a.example.com"}, Truncated: true}}}
	res, _ := CollectCT(context.Background(), extDeps(nil, ct, nil, nil), ExternalRequest{Targets: []string{"example.com"}, MaxTargets: 1})
	if res.Complete() || !errors.Is(res.Failures[0].Err, core.ErrTruncated) || !strings.Contains(res.Failures[0].Err.Error(), "kept the first 1") {
		t.Fatalf("a cut result is INCOMPLETE and says how much was kept: %+v", res.Failures)
	}
	if !hasNode(loads(t, res.Estate), "host:a.example.com") {
		t.Error("the names that were read are kept")
	}
}

func TestCollectCTFailureStoresNothingAndNotFoundIsAnAbsence(t *testing.T) {
	ct := &stubCT{
		ans:  map[string]core.CTAnswer{"ok.example.com": {Names: []string{"a.ok.example.com"}}},
		errs: map[string]error{"down.example.com": fmt.Errorf("%w: HTTP 503", core.ErrLookupFailed), "none.example.com": fmt.Errorf("%w: none", core.ErrNotFound)},
	}
	res, _ := CollectCT(context.Background(), extDeps(nil, ct, nil, nil), ExternalRequest{Targets: []string{"down.example.com", "none.example.com", "ok.example.com"}, MaxTargets: 5})
	e := loads(t, res.Estate)
	if len(res.Failures) != 1 || hasNode(e, "domain:down.example.com") {
		t.Errorf("failure %+v; nothing may be stored for it", res.Failures)
	}
	if len(e.Absences) != 1 || e.Absences[0].Subject != "domain:none.example.com" {
		t.Errorf("absences %+v", e.Absences)
	}
}

func TestCollectCTRateLimitStopsTheRun(t *testing.T) {
	ct := &stubCT{errs: map[string]error{"a.example.com": fmt.Errorf("%w: 429", core.ErrRateLimited)}}
	res, _ := CollectCT(context.Background(), extDeps(nil, ct, nil, nil), ExternalRequest{Targets: []string{"a.example.com", "b.example.com"}, MaxTargets: 5})
	if len(ct.asked) != 1 || len(res.Failures) != 2 {
		t.Errorf("asked %v failures %+v", ct.asked, res.Failures)
	}
}

// ---- dns ----

type stubFwd struct {
	ans   map[core.DNSType]core.DNSAnswer
	errs  map[core.DNSType]error
	asked []string
}

func (s *stubFwd) Lookup(_ context.Context, name string, t core.DNSType) (core.DNSAnswer, error) {
	s.asked = append(s.asked, string(t)+" "+name)
	a := s.ans[t]
	a.Query = fmt.Sprintf("%s %s via stub", t, name)
	if s.errs[t] == nil && len(a.Values) == 0 {
		return a, fmt.Errorf("%w: none", core.ErrNotFound)
	}
	return a, s.errs[t]
}

func fullFwd() *stubFwd {
	return &stubFwd{ans: map[core.DNSType]core.DNSAnswer{
		core.DNSA:     {Values: []string{"192.0.2.10"}},
		core.DNSAAAA:  {Values: []string{"2001:db8::10"}},
		core.DNSCNAME: {Values: []string{"edge.example.net"}},
		core.DNSMX:    {Values: []string{"mail.example.com"}},
		core.DNSNS:    {Values: []string{"ns1.example.com"}},
		core.DNSSPF:   {Values: []string{"v=spf1 ip4:192.0.2.0/24 ip4:192.0.2.55 ip6:2001:db8::/48 include:_spf.example.net a mx exists:%{i}.x.example.org -all"}},
	}}
}

func TestCollectDNSRecordsEveryType(t *testing.T) {
	f := fullFwd()
	res, err := CollectDNS(context.Background(), extDeps(nil, nil, f, nil), ExternalRequest{Targets: []string{"example.com"}, MaxTargets: 2})
	if err != nil || !res.Complete() {
		t.Fatalf("%v %+v", err, res.Failures)
	}
	if len(f.asked) != 6 {
		t.Errorf("asked %v", f.asked)
	}
	e := loads(t, res.Estate)
	for _, w := range [][3]string{
		{"domain:example.com", "ip:192.0.2.10", "resolves_to"},
		{"domain:example.com", "ip:2001:db8::10", "resolves_to"},
		{"domain:example.com", "host:edge.example.net", "cname"},
		{"domain:example.com", "host:mail.example.com", "mx"},
		{"domain:example.com", "host:ns1.example.com", "ns"},
		{"domain:example.com", "network:192.0.2.0/24", "spf_authorises"},
		{"domain:example.com", "ip:192.0.2.55", "spf_authorises"},
		{"domain:example.com", "network:2001:db8::/48", "spf_authorises"},
		{"domain:example.com", "domain:_spf.example.net", "spf_include"},
	} {
		x, ok := hasEdge(e, w[0], w[1], w[2], "dns")
		if !ok || x.Method == "" {
			t.Errorf("missing edge %v", w)
		}
	}
	if len(e.Edges) != 9 {
		t.Errorf("%d edges: a macro, a, mx and exists terms name nothing fixed and are not recorded", len(e.Edges))
	}
	joined := strings.Join(res.Notes, "\n")
	for _, w := range []string{"CDN", "shared hosting", "one resolver", "no host was contacted by jb"} {
		if !strings.Contains(joined, w) {
			t.Errorf("notes lack %q:\n%s", w, joined)
		}
	}
}

func TestCollectDNSEachLookupStandsAlone(t *testing.T) {
	f := fullFwd()
	f.errs = map[core.DNSType]error{core.DNSA: fmt.Errorf("%w: SERVFAIL", core.ErrLookupFailed)}
	delete(f.ans, core.DNSAAAA) // a real not-found
	res, _ := CollectDNS(context.Background(), extDeps(nil, nil, f, nil), ExternalRequest{Targets: []string{"example.com"}, MaxTargets: 2})
	if len(res.Failures) != 1 || res.Failures[0].Lookup != "dns/A" {
		t.Fatalf("%+v", res.Failures)
	}
	e := loads(t, res.Estate)
	if hasNode(e, "ip:192.0.2.10") {
		t.Error("a failed A lookup left a node")
	}
	if !hasNode(e, "host:mail.example.com") {
		t.Error("the other lookups still stand")
	}
	if len(e.Absences) != 1 || !strings.HasPrefix(e.Absences[0].Method, "AAAA ") {
		t.Errorf("only the real not-found is an absence: %+v", e.Absences)
	}
}

func TestCollectDNSRejectsValuesThatAreNotWhatTheyClaim(t *testing.T) {
	f := &stubFwd{ans: map[core.DNSType]core.DNSAnswer{
		core.DNSA:  {Values: []string{"not-an-ip", "2001:db8::1"}}, // the second is not an A value
		core.DNSMX: {Values: []string{"bad name!"}},
	}}
	res, _ := CollectDNS(context.Background(), extDeps(nil, nil, f, nil), ExternalRequest{Targets: []string{"example.com"}, MaxTargets: 2})
	e := loads(t, res.Estate)
	for _, n := range e.Nodes {
		if n.Kind == "ip" || n.Kind == "host" {
			t.Errorf("hostile value recorded: %+v", n)
		}
	}
	if len(res.Failures) != 2 {
		t.Errorf("each unusable answer is a failure: %+v", res.Failures)
	}
}

func TestCollectDNSTruncationIsIncomplete(t *testing.T) {
	f := fullFwd()
	a := f.ans[core.DNSNS]
	a.Truncated = true
	f.ans[core.DNSNS] = a
	res, _ := CollectDNS(context.Background(), extDeps(nil, nil, f, nil), ExternalRequest{Targets: []string{"example.com"}, MaxTargets: 2})
	if res.Complete() || !errors.Is(res.Failures[0].Err, core.ErrTruncated) {
		t.Fatalf("%+v", res.Failures)
	}
}

func TestNormaliseDomain(t *testing.T) {
	for in, want := range map[string]string{"Example.COM": "example.com", "a.b.example.com.": "a.b.example.com", " xn--bcher-kva.example ": "xn--bcher-kva.example"} {
		if got, err := NormaliseDomain(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "localhost", "192.0.2.1", "example.123", "-a.example.com", "a..example.com", "a b.example.com", "https://example.com", "example.com/path", "*.example.com", strings.Repeat("a", 64) + ".com", "a@example.com"} {
		if _, err := NormaliseDomain(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
