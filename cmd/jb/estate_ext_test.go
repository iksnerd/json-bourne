package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/core"
)

type extStubs struct {
	bgp *cmdBGP
	ct  *cmdCT
	fwd *cmdFwd
	nap []time.Duration
}

type cmdBGP struct {
	asked []string
	err   error
}

func (s *cmdBGP) LookupASN(_ context.Context, n uint32) (core.BGPAnnouncement, error) {
	s.asked = append(s.asked, fmt.Sprint("AS", n))
	return core.BGPAnnouncement{Query: "GET https://bgp.example.com/AS", Holder: core.BGPHolder{ASN: n, Holder: "EXAMPLE-AS"},
		Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}, s.err
}

func (s *cmdBGP) LookupIP(_ context.Context, ip netip.Addr) (core.BGPOrigin, error) {
	s.asked = append(s.asked, ip.String())
	return core.BGPOrigin{Query: "GET https://bgp.example.com/ip", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Origin: []core.BGPHolder{{ASN: 64500, Holder: "EXAMPLE-AS"}}}, s.err
}

type cmdCT struct {
	asked     []string
	truncated bool
	err       error
}

func (s *cmdCT) LookupSubdomains(_ context.Context, d string) (core.CTAnswer, error) {
	s.asked = append(s.asked, d)
	return core.CTAnswer{Query: "GET https://ct.example.com/?q=%25." + d, Names: []string{"api." + d, "www." + d}, Wildcards: 1, Truncated: s.truncated}, s.err
}

type cmdFwd struct {
	asked []string
	fail  core.DNSType
}

func (s *cmdFwd) Lookup(_ context.Context, name string, t core.DNSType) (core.DNSAnswer, error) {
	s.asked = append(s.asked, string(t)+" "+name)
	a := core.DNSAnswer{Query: fmt.Sprintf("%s %s via stub", t, name)}
	switch {
	case t == s.fail:
		return a, fmt.Errorf("%w: SERVFAIL", core.ErrLookupFailed)
	case t == core.DNSA:
		a.Values = []string{"192.0.2.10"}
		return a, nil
	}
	return a, fmt.Errorf("%w: none", core.ErrNotFound)
}

func newExtStubs() *extStubs {
	return &extStubs{bgp: &cmdBGP{}, ct: &cmdCT{}, fwd: &cmdFwd{}}
}

func (s *extStubs) deps() deps {
	d := testDeps(nil)
	d.bgp, d.ct, d.fwd = s.bgp, s.ct, s.fwd
	d.sleep = func(_ context.Context, x time.Duration) error { s.nap = append(s.nap, x); return nil }
	return d
}

func (s *extStubs) calls() int { return len(s.bgp.asked) + len(s.ct.asked) + len(s.fwd.asked) }

// enableExt turns external estate services on in the example case's config.
func enableExt(t *testing.T, dir string, services ...string) {
	t.Helper()
	p := filepath.Join(dir, "config", "hunt.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, []byte("\nestate:\n  external: ["+strings.Join(services, ", ")+"]\n")...)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

var extCmds = []struct{ cmd, service, target string }{
	{"asn", "bgp", "AS64500"},
	{"dns", "dns", "example.com"},
	{"ct", "crt.sh", "example.com"},
}

// Nothing leaves the machine until the operator names the service. Run for every
// collector, with every other service on, so the switch is per service.
func TestEstateExternalServicesAreOffByDefault(t *testing.T) {
	for _, c := range extCmds {
		for _, others := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s others=%v", c.cmd, others), func(t *testing.T) {
				dir := copyExampleCase(t, "")
				if others {
					var on []string
					for _, o := range extCmds {
						if o.service != c.service {
							on = append(on, o.service)
						}
					}
					enableExt(t, dir, on...)
				}
				before, _ := os.ReadFile(filepath.Join(dir, "estate", "estate.yaml"))
				st := newExtStubs()
				code, stdout, stderr := run(t, st.deps(), "estate", c.cmd, "--case", dir, c.target)
				if code != exitUsage || st.calls() != 0 || stdout != "" {
					t.Fatalf("exit %d, %d call(s) made\nstdout: %s\nstderr: %s", code, st.calls(), stdout, stderr)
				}
				if !strings.Contains(stderr, `"`+c.service+`" service is not enabled`) || !strings.Contains(stderr, "nothing was sent") || !strings.Contains(stderr, "estate: {external: ["+c.service+"]}") {
					t.Errorf("the refusal must name the service and how to enable it: %s", stderr)
				}
				if _, err := os.Stat(filepath.Join(dir, "estate", "estate.yaml")); err == nil {
					after, _ := os.ReadFile(filepath.Join(dir, "estate", "estate.yaml"))
					if string(after) != string(before) {
						t.Error("a refused run changed the estate file")
					}
				}
			})
		}
	}
}

func TestEstateASNWritesAFileTheCheckAccepts(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "bgp")
	st := newExtStubs()
	code, stdout, stderr := run(t, st.deps(), "estate", "asn", "--case", dir, "AS64500", "192.0.2.10")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{"CDN", "not who typed", "No target host was contacted", "estate/estate.yaml", "service     bgp"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	e := caseEstate(t, dir, "estate.yaml")
	found := false
	for _, x := range e.Edges {
		found = found || (x.Source == "bgp" && x.Relation == "originated_by")
	}
	if !found {
		t.Errorf("no bgp edge: %+v", e.Edges)
	}
	if len(st.nap) != 1 || st.nap[0] != time.Second {
		t.Errorf("the second request waits the default interval: %v", st.nap)
	}
	if code, out, errs := run(t, testDeps(nil), "case", "check", dir); code != 0 {
		t.Fatalf("case check: %d\n%s\n%s", code, out, errs)
	}
	// A second identical run changes nothing.
	p := filepath.Join(dir, "estate", "estate.yaml")
	first, _ := os.ReadFile(p)
	if code, out, _ := run(t, st.deps(), "estate", "asn", "--case", dir, "AS64500", "192.0.2.10"); code != 0 {
		t.Fatalf("second run exit %d\n%s", code, out)
	}
	if second, _ := os.ReadFile(p); string(first) != string(second) {
		t.Error("a second identical run changed the file")
	}
}

func TestEstateCTTruncationEndsIncompleteAndSaysSo(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "crt.sh")
	st := newExtStubs()
	st.ct.truncated = true
	code, stdout, stderr := run(t, st.deps(), "estate", "ct", "--case", dir, "example.com")
	if code != exitFailure || !strings.Contains(stdout, "INCOMPLETE") || !strings.Contains(stdout, "truncated") || !strings.Contains(stderr, "incomplete") {
		t.Fatalf("a cut result must be INCOMPLETE and exit 1: %d\n%s\n%s", code, stdout, stderr)
	}
	for _, w := range []string{"candidate", "not confirmed live", "wildcard"} {
		if !strings.Contains(stdout, w) {
			t.Errorf("output lacks %q:\n%s", w, stdout)
		}
	}
	e := caseEstate(t, dir, "estate.yaml")
	var candidate bool
	for _, x := range e.Edges {
		if x.Relation == "ct_candidate" {
			candidate = true
			if x.Confidence != "inferred" {
				t.Errorf("a CT name is inferred, not stated: %+v", x)
			}
		}
	}
	if !candidate {
		t.Error("the names that were read are kept")
	}
}

func TestEstateDNSFailureEndsIncompleteAndStoresNothingForIt(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "dns")
	st := newExtStubs()
	st.fwd.fail = core.DNSA
	code, stdout, _ := run(t, st.deps(), "estate", "dns", "--case", dir, "example.com")
	if code != exitFailure || !strings.Contains(stdout, "dns/A") || !strings.Contains(stdout, "SERVFAIL") {
		t.Fatalf("%d\n%s", code, stdout)
	}
	for _, n := range caseEstate(t, dir, "estate.yaml").Nodes {
		if n.ID == "ip:192.0.2.10" {
			t.Error("a failed lookup left a node")
		}
	}
	if len(st.fwd.asked) != 6 {
		t.Errorf("one failure must not stop the other lookups: %v", st.fwd.asked)
	}
}

func TestEstateExternalRefusesTooManyTargetsWithoutAsking(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "bgp", "dns", "crt.sh")
	st := newExtStubs()
	code, _, stderr := run(t, st.deps(), "estate", "ct", "--case", dir, "--max-targets", "2", "a.example.com", "b.example.com", "c.example.com")
	if code != exitUsage || st.calls() != 0 || !strings.Contains(stderr, "the cap is 2") {
		t.Fatalf("%d %d calls %s", code, st.calls(), stderr)
	}
	for _, args := range [][]string{
		{"estate", "ct", "--case", dir, "--max-targets", "51", "example.com"},
		{"estate", "ct", "--case", dir, "--timeout", "0s", "example.com"},
		{"estate", "ct", "--case", dir, "--max-names", "0", "example.com"},
		{"estate", "asn", "--case", dir, "not-a-target"},
		{"estate", "dns", "--case", dir, "192.0.2.1"},
		{"estate", "dns", "--case", dir, "--resolver", "ns1.example.com:53", "example.com"},
		{"estate", "dns", "--case", dir, "--resolver", "noport", "example.com"},
		{"estate", "dns", "--case", dir},
	} {
		if code, _, stderr := run(t, st.deps(), args...); code != exitUsage || st.calls() != 0 {
			t.Errorf("%v: exit %d, %d calls\n%s", args, code, st.calls(), stderr)
		}
	}
}

func TestEstateExternalConflictIsReportedAndNotOverwritten(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "crt.sh")
	c, _ := casefile.Load(dir)
	seed := &casefile.Estate{APIVersion: casefile.EstateAPIVersion, ID: "estate", Caveat: casefile.DefaultEstateCaveat,
		Nodes: []casefile.Node{{ID: "host:api.example.com", Kind: "host", Label: "API.EXAMPLE.COM", Source: "rdns", Method: "PTR x", Observed: "2026-11-01T00:00:00Z"}}}
	if err := casefile.SaveEstateFile(c, "estate.yaml", seed); err != nil {
		t.Fatal(err)
	}
	st := newExtStubs()
	code, stdout, stderr := run(t, st.deps(), "estate", "ct", "--case", dir, "example.com")
	if code != exitFailure || !strings.Contains(stdout, "CONFLICT") || !strings.Contains(stderr, "conflict") {
		t.Fatalf("%d\n%s\n%s", code, stdout, stderr)
	}
	for _, n := range caseEstate(t, dir, "estate.yaml").Nodes {
		if n.ID == "host:api.example.com" && n.Label != "API.EXAMPLE.COM" {
			t.Errorf("recorded node overwritten: %+v", n)
		}
	}
}

func TestEstateExternalJSON(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "crt.sh")
	st := newExtStubs()
	st.ct.truncated = true
	_, stdout, _ := run(t, st.deps(), "estate", "ct", "--case", dir, "--output", "json", "example.com")
	var got struct {
		Complete bool
		Notes    []string
		Asked    string
		Failures []struct{ Target, Lookup, Error string }
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if got.Complete || len(got.Failures) != 1 || got.Failures[0].Lookup != "crt.sh" || len(got.Notes) == 0 || got.Asked == "" {
		t.Errorf("%+v", got)
	}
}

// The configured URL is used and the real adapter is wired: no stub, a local server in
// place of the public service. (That the domain itself is never dialled is proved at the
// adapter, in crtsh_test.go, where the target can be given the server's own address.)
func TestEstateCTUsesTheConfiguredService(t *testing.T) {
	var q atomic.Value
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q.Store(r.URL.Query().Get("q"))
		_, _ = w.Write([]byte(`[{"name_value":"www.example.com\n*.example.com"}]`))
	}))
	defer svc.Close()
	dir := copyExampleCase(t, "")
	p := filepath.Join(dir, "config", "hunt.yaml")
	b, _ := os.ReadFile(p)
	_ = os.WriteFile(p, append(b, []byte("\nestate:\n  external: [crt.sh]\n  crtsh_url: "+svc.URL+"\n")...), 0o600)
	d := testDeps(nil)
	d.sleep = func(context.Context, time.Duration) error { return nil }
	code, stdout, stderr := run(t, d, "estate", "ct", "--case", dir, "example.com")
	if code != 0 || q.Load() != "%.example.com" {
		t.Fatalf("exit %d q=%v\n%s\n%s", code, q.Load(), stdout, stderr)
	}
	if !strings.Contains(stdout, svc.URL) {
		t.Errorf("the output must say where the question went:\n%s", stdout)
	}
}
