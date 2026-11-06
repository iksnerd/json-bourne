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

type estFakePTR struct {
	byIP  map[string]core.PTRAnswer
	errs  map[string]error
	asked []string
}

func (f *estFakePTR) LookupPTR(_ context.Context, ip netip.Addr) (core.PTRAnswer, error) {
	f.asked = append(f.asked, ip.String())
	a := f.byIP[ip.String()]
	if a.Query == "" {
		a.Query = "PTR " + ip.String() + " via fake"
	}
	return a, f.errs[ip.String()]
}

type estFakeRDAP struct {
	byIP  map[string]core.RDAPNetwork
	errs  map[string]error
	asked []string
}

func (f *estFakeRDAP) LookupIP(_ context.Context, ip netip.Addr) (core.RDAPNetwork, error) {
	f.asked = append(f.asked, ip.String())
	n := f.byIP[ip.String()]
	if n.Query == "" {
		n.Query = "GET https://rdap.example.com/ip/" + ip.String()
	}
	return n, f.errs[ip.String()]
}

var estT0 = time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)

func estDeps(p *estFakePTR, r *estFakeRDAP) EstateDeps {
	return EstateDeps{PTR: p, RDAP: r, Now: func() time.Time { return estT0 }}
}

func estHappy() (*estFakePTR, *estFakeRDAP) {
	return &estFakePTR{byIP: map[string]core.PTRAnswer{"192.0.2.10": {Names: []string{"edge.example.com"}}}},
		&estFakeRDAP{byIP: map[string]core.RDAPNetwork{"192.0.2.10": {
			Handle: "NET-192-0-2-0-1", Name: "EXAMPLE-NET", Start: "192.0.2.0", End: "192.0.2.255",
			Entities: []core.RDAPEntity{{Handle: "ORG-EX1", Name: "Example Network Operator", Roles: []string{"registrant"}},
				{Handle: "ABUSE-EX", Name: "Abuse Desk", Roles: []string{"abuse"}}},
		}}}
}

// assertLoads turns a fragment into a full estate and runs the real loader on it: what
// the collector produces must be something the loader accepts.
func assertLoads(t *testing.T, frag *casefile.Estate) *casefile.Estate {
	t.Helper()
	full := *frag
	full.APIVersion, full.ID, full.Caveat = casefile.EstateAPIVersion, "t", casefile.DefaultEstateCaveat
	out, err := casefile.MarshalEstate(&full)
	if err != nil {
		t.Fatalf("collector output does not validate: %v", err)
	}
	e, err := casefile.ParseEstate(out)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestCollectEstateHappyPath(t *testing.T) {
	p, r := estHappy()
	res, err := CollectEstate(context.Background(), estDeps(p, r), EstateRequest{IPs: []string{"192.0.2.10"}, MaxIPs: 5})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete() || len(res.Failures) != 0 {
		t.Fatalf("%+v", res.Failures)
	}
	e := assertLoads(t, res.Estate)
	ids := map[string]casefile.Node{}
	for _, n := range e.Nodes {
		ids[n.ID] = n
		if n.Source == "" || n.Method == "" || n.Observed != "2026-11-06T10:00:00Z" {
			t.Errorf("node without full provenance: %+v", n)
		}
	}
	for _, want := range []string{"ip:192.0.2.10", "host:edge.example.com", "network:net-192-0-2-0-1", "org:org-ex1"} {
		if _, ok := ids[want]; !ok {
			t.Errorf("node %s missing: %v", want, ids)
		}
	}
	if _, ok := ids["org:abuse-ex"]; ok {
		t.Error("only the registrant becomes an organisation node")
	}
	if got := ids["host:edge.example.com"].Method; !strings.Contains(got, "PTR") {
		t.Errorf("rDNS method does not carry the query: %q", got)
	}
	if got := ids["network:net-192-0-2-0-1"].Method; got != "GET https://rdap.example.com/ip/192.0.2.10" {
		t.Errorf("rdap method = %q", got)
	}
	rel := map[string]bool{}
	for _, ed := range e.Edges {
		rel[ed.From+" "+ed.Relation+" "+ed.To] = true
		if ed.Confidence != "stated" {
			t.Errorf("an edge read straight from a record is stated: %+v", ed)
		}
	}
	for _, want := range []string{"ip:192.0.2.10 ptr host:edge.example.com", "ip:192.0.2.10 within network:net-192-0-2-0-1", "network:net-192-0-2-0-1 registered_to org:org-ex1"} {
		if !rel[want] {
			t.Errorf("edge %q missing: %v", want, rel)
		}
	}
}

func TestCollectEstateFailureIsNeverANode(t *testing.T) {
	for name, err := range map[string]error{
		"timeout":      fmt.Errorf("%w: context deadline exceeded", core.ErrLookupFailed),
		"rate limited": fmt.Errorf("%w: HTTP 429", core.ErrRateLimited),
		"non-2xx":      fmt.Errorf("%w: HTTP 503", core.ErrLookupFailed),
		"plain error":  errors.New("boom"),
	} {
		t.Run(name, func(t *testing.T) {
			p := &estFakePTR{errs: map[string]error{"192.0.2.10": err}}
			r := &estFakeRDAP{errs: map[string]error{"192.0.2.10": err}}
			res, cerr := CollectEstate(context.Background(), estDeps(p, r), EstateRequest{IPs: []string{"192.0.2.10"}, MaxIPs: 5})
			if cerr != nil {
				t.Fatal(cerr)
			}
			if res.Complete() || len(res.Failures) != 2 {
				t.Fatalf("complete=%v failures=%v", res.Complete(), res.Failures)
			}
			if len(res.Estate.Nodes) != 0 || len(res.Estate.Edges) != 0 || len(res.Estate.Absences) != 0 {
				t.Fatalf("a failed lookup left data behind: %+v", res.Estate)
			}
		})
	}
}

func TestCollectEstateNotFoundIsARecordedAnswer(t *testing.T) {
	p := &estFakePTR{errs: map[string]error{"192.0.2.10": fmt.Errorf("%w: NXDOMAIN", core.ErrNotFound)}}
	r := &estFakeRDAP{errs: map[string]error{"192.0.2.10": fmt.Errorf("%w: HTTP 404", core.ErrNotFound)}}
	res, err := CollectEstate(context.Background(), estDeps(p, r), EstateRequest{IPs: []string{"192.0.2.10"}, MaxIPs: 5})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete() {
		t.Fatalf("a real not-found is an answer, not a failure: %v", res.Failures)
	}
	e := assertLoads(t, res.Estate)
	if len(e.Absences) != 2 || len(e.Nodes) != 1 || e.Nodes[0].ID != "ip:192.0.2.10" {
		t.Fatalf("%+v", e)
	}
	srcs := []string{e.Absences[0].Source, e.Absences[1].Source}
	if !(strings.Contains(strings.Join(srcs, ","), "rdap") && strings.Contains(strings.Join(srcs, ","), "rdns")) {
		t.Errorf("absence sources %v", srcs)
	}
	for _, a := range e.Absences {
		if a.Answer != "not_found" || a.Method == "" {
			t.Errorf("%+v", a)
		}
	}
}

func TestCollectEstateOneFailureDoesNotHideTheOtherAnswer(t *testing.T) {
	p, r := estHappy()
	r.errs = map[string]error{"192.0.2.10": fmt.Errorf("%w: HTTP 500", core.ErrLookupFailed)}
	res, err := CollectEstate(context.Background(), estDeps(p, r), EstateRequest{IPs: []string{"192.0.2.10"}, MaxIPs: 5})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() || len(res.Failures) != 1 || res.Failures[0].Lookup != "rdap" || res.Failures[0].IP != "192.0.2.10" {
		t.Fatalf("%+v", res.Failures)
	}
	e := assertLoads(t, res.Estate)
	if len(e.Nodes) != 2 { // ip + host from rDNS only
		t.Errorf("%+v", e.Nodes)
	}
}

func TestCollectEstateRateLimitStopsFurtherRegistryCalls(t *testing.T) {
	p, r := estHappy()
	r.errs = map[string]error{"192.0.2.10": fmt.Errorf("%w: HTTP 429", core.ErrRateLimited)}
	res, err := CollectEstate(context.Background(), estDeps(p, r), EstateRequest{IPs: []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"}, MaxIPs: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.asked) != 1 {
		t.Errorf("registry asked %v: nothing more may be sent after a 429", r.asked)
	}
	rdapFails := 0
	for _, f := range res.Failures {
		if f.Lookup == "rdap" {
			rdapFails++
		}
	}
	if rdapFails != 3 || res.Complete() {
		t.Errorf("every IP without an RDAP answer must be listed: %+v", res.Failures)
	}
}

func TestCollectEstateInputRules(t *testing.T) {
	p, r := estHappy()
	d := estDeps(p, r)
	ctx := context.Background()
	if _, err := CollectEstate(ctx, d, EstateRequest{IPs: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, MaxIPs: 2}); !errors.Is(err, ErrTooManyIPs) {
		t.Errorf("over the cap must be refused, not truncated: %v", err)
	}
	if len(p.asked)+len(r.asked) != 0 {
		t.Error("nothing may be asked when the input is refused")
	}
	for _, bad := range []string{"", "not-an-ip", "192.0.2.0/24", "fe80::1%eth0", "example.com"} {
		if _, err := CollectEstate(ctx, d, EstateRequest{IPs: []string{bad}, MaxIPs: 5}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := CollectEstate(ctx, d, EstateRequest{MaxIPs: 5}); err == nil {
		t.Error("no IPs accepted")
	}
	// Duplicates and a mapped form collapse to one lookup of the canonical address.
	res, err := CollectEstate(ctx, d, EstateRequest{IPs: []string{"192.0.2.10", "192.0.2.10", "::ffff:192.0.2.10"}, MaxIPs: 5})
	if err != nil || len(res.IPs) != 1 || len(p.asked) != 1 {
		t.Errorf("%v %v %v", err, res.IPs, p.asked)
	}
}

func TestCollectEstateSanitisesHostileRegistryText(t *testing.T) {
	p := &estFakePTR{}
	r := &estFakeRDAP{byIP: map[string]core.RDAPNetwork{"192.0.2.10": {
		Handle: "NET-1", Name: "Evil\nname: injected\x00 " + strings.Repeat("x", 400), Start: "192.0.2.0", End: "192.0.2.255",
		Entities: []core.RDAPEntity{{Handle: "ORG\n1", Name: "Org\r\nName", Roles: []string{"registrant"}}},
	}}}
	p.errs = map[string]error{"192.0.2.10": fmt.Errorf("%w: NXDOMAIN", core.ErrNotFound)}
	res, err := CollectEstate(context.Background(), estDeps(p, r), EstateRequest{IPs: []string{"192.0.2.10"}, MaxIPs: 5})
	if err != nil {
		t.Fatal(err)
	}
	assertLoads(t, res.Estate) // must still be a valid estate, one-line labels
	for _, n := range res.Estate.Nodes {
		if strings.ContainsAny(n.Label, "\r\n\x00") || len(n.Label) > 255 {
			t.Errorf("unsafe label %q", n.Label)
		}
	}
}
