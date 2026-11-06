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
	"testing"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/core"
)

type stubPTR struct {
	names map[string][]string
	errs  map[string]error
	asked []string
}

func (s *stubPTR) LookupPTR(_ context.Context, ip netip.Addr) (core.PTRAnswer, error) {
	s.asked = append(s.asked, ip.String())
	return core.PTRAnswer{Query: "PTR " + ip.String() + " via stub", Names: s.names[ip.String()]}, s.errs[ip.String()]
}

type stubRDAP struct {
	errs  map[string]error
	asked []string
	org   string
}

func (s *stubRDAP) LookupIP(_ context.Context, ip netip.Addr) (core.RDAPNetwork, error) {
	s.asked = append(s.asked, ip.String())
	org := s.org
	if org == "" {
		org = "Example Network Operator"
	}
	return core.RDAPNetwork{Query: "GET https://rdap.example.com/ip/" + ip.String(), Handle: "NET-1", Name: "EXAMPLE-NET",
		Start: "192.0.2.0", End: "192.0.2.255",
		Entities: []core.RDAPEntity{{Handle: "ORG-EX1", Name: org, Roles: []string{"registrant"}}}}, s.errs[ip.String()]
}

func estateDeps(p *stubPTR, r *stubRDAP) deps {
	d := testDeps(nil)
	d.ptr, d.rdap = p, r
	return d
}

func okPTR() *stubPTR {
	return &stubPTR{names: map[string][]string{"192.0.2.10": {"edge.example.com"}}}
}

func caseEstate(t *testing.T, dir, name string) *casefile.Estate {
	t.Helper()
	c, err := casefile.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, err := casefile.LoadEstateFile(c, name)
	if err != nil {
		t.Fatalf("the file the collector wrote does not load: %v", err)
	}
	return e
}

func TestEstateWritesAFileTheCheckAccepts(t *testing.T) {
	dir := copyExampleCase(t, "")
	code, stdout, stderr := run(t, estateDeps(okPTR(), &stubRDAP{}), "estate", "--case", dir, "192.0.2.10")
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	for _, want := range []string{"CDN", "not who typed", "no address was contacted", "estate/estate.yaml"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	e := caseEstate(t, dir, "estate.yaml")
	if e.Caveat == "" || len(e.Nodes) != 4 {
		t.Fatalf("%+v", e)
	}
	code, stdout, stderr = run(t, testDeps(nil), "case", "check", "--case", dir)
	if code != 0 || !strings.Contains(stdout, "estate") || !strings.Contains(stdout, "OK (2: ") {
		t.Fatalf("case check after estate: exit %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestEstateIsIdempotent(t *testing.T) {
	dir := copyExampleCase(t, "")
	d := estateDeps(okPTR(), &stubRDAP{})
	run(t, d, "estate", "--case", dir, "192.0.2.10")
	p := filepath.Join(dir, "estate", "estate.yaml")
	first, _ := os.ReadFile(p)
	code, stdout, _ := run(t, d, "estate", "--case", dir, "192.0.2.10")
	second, _ := os.ReadFile(p)
	if code != 0 || string(first) != string(second) {
		t.Fatalf("exit %d: a second identical run must change nothing\n%s", code, stdout)
	}
}

func TestEstateFailureEndsIncompleteAndStoresNoNegative(t *testing.T) {
	dir := copyExampleCase(t, "")
	r := &stubRDAP{errs: map[string]error{"192.0.2.10": fmt.Errorf("%w: HTTP 503", core.ErrLookupFailed)}}
	code, stdout, stderr := run(t, estateDeps(okPTR(), r), "estate", "--case", dir, "192.0.2.10")
	if code != exitFailure {
		t.Fatalf("exit %d, want 1\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "INCOMPLETE") || !strings.Contains(stdout, "HTTP 503") || strings.Count(stderr, "jb:") != 1 || !strings.Contains(stderr, "incomplete") {
		t.Errorf("stdout:\n%s\nstderr: %s", stdout, stderr)
	}
	e := caseEstate(t, dir, "estate.yaml") // the rDNS answer is real and is kept
	for _, n := range e.Nodes {
		if n.Kind == "network" || n.Kind == "org" {
			t.Errorf("node %s from the failed lookup", n.ID)
		}
	}
	if len(e.Absences) != 0 {
		t.Errorf("a failure was recorded as an absence: %+v", e.Absences)
	}
}

func TestEstateAllLookupsFailingWritesNothing(t *testing.T) {
	dir := copyExampleCase(t, "")
	boom := fmt.Errorf("%w: timeout", core.ErrLookupFailed)
	p := &stubPTR{errs: map[string]error{"192.0.2.10": boom}}
	r := &stubRDAP{errs: map[string]error{"192.0.2.10": boom}}
	code, stdout, _ := run(t, estateDeps(p, r), "estate", "--case", dir, "192.0.2.10")
	if code != exitFailure || !strings.Contains(stdout, "INCOMPLETE") {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, "estate", "estate.yaml")); !os.IsNotExist(err) {
		t.Errorf("a file was written with nothing to say: %v", err)
	}
}

func TestEstateNotFoundIsRecordedAndIsNotAFailure(t *testing.T) {
	dir := copyExampleCase(t, "")
	nf := fmt.Errorf("%w: 404", core.ErrNotFound)
	p := &stubPTR{errs: map[string]error{"192.0.2.10": nf}}
	r := &stubRDAP{errs: map[string]error{"192.0.2.10": nf}}
	code, stdout, stderr := run(t, estateDeps(p, r), "estate", "--case", dir, "192.0.2.10")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	e := caseEstate(t, dir, "estate.yaml")
	if len(e.Absences) != 2 || len(e.Nodes) != 1 {
		t.Fatalf("%+v", e)
	}
}

func TestEstateConflictIsReportedAndNothingIsOverwritten(t *testing.T) {
	dir := copyExampleCase(t, "")
	d := estateDeps(okPTR(), &stubRDAP{})
	run(t, d, "estate", "--case", dir, "192.0.2.10")
	p := filepath.Join(dir, "estate", "estate.yaml")
	before, _ := os.ReadFile(p)

	d = estateDeps(okPTR(), &stubRDAP{org: "A Different Operator Ltd"})
	code, stdout, stderr := run(t, d, "estate", "--case", dir, "192.0.2.10")
	if code != exitFailure || !strings.Contains(stdout, "CONFLICT") || !strings.Contains(stdout, "org:org-ex1") {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Error("a conflicting observation changed the file")
	}
}

func TestEstateRefusesToReplaceAFileItCannotRead(t *testing.T) {
	dir := copyExampleCase(t, "")
	p := filepath.Join(dir, "estate", "estate.yaml")
	if err := os.WriteFile(p, []byte("apiVersion: jb.estate/v2\nsurprise: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, estateDeps(okPTR(), &stubRDAP{}), "estate", "--case", dir, "192.0.2.10")
	b, _ := os.ReadFile(p)
	if code != exitFailure || !strings.Contains(stderr, "estate.yaml") || !strings.Contains(string(b), "surprise") {
		t.Fatalf("exit %d, stderr %q, file %q", code, stderr, b)
	}
}

func TestEstateJSON(t *testing.T) {
	dir := copyExampleCase(t, "")
	r := &stubRDAP{errs: map[string]error{"192.0.2.10": fmt.Errorf("%w: HTTP 429", core.ErrRateLimited)}}
	code, stdout, _ := run(t, estateDeps(okPTR(), r), "estate", "--case", dir, "--output", "json", "192.0.2.10")
	if code != exitFailure {
		t.Fatalf("exit %d", code)
	}
	var got struct {
		Note      string `json:"note"`
		Complete  bool   `json:"complete"`
		Failures  []struct{ IP, Lookup, Error string }
		Conflicts []string
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if got.Complete || got.Note == "" || len(got.Failures) != 1 || got.Failures[0].Lookup != "rdap" || got.Conflicts == nil {
		t.Errorf("%+v", got)
	}
}

func TestEstateUsageErrorsExitTwo(t *testing.T) {
	dir := copyExampleCase(t, "")
	d := estateDeps(okPTR(), &stubRDAP{})
	for name, args := range map[string][]string{
		"no case":              {"estate", "192.0.2.10"},
		"no addresses":         {"estate", "--case", dir},
		"not an address":       {"estate", "--case", dir, "example.com"},
		"a CIDR":               {"estate", "--case", dir, "192.0.2.0/24"},
		"over the cap":         {"estate", "--case", dir, "--max-ips", "1", "192.0.2.1", "192.0.2.2"},
		"cap too high":         {"estate", "--case", dir, "--max-ips", "100000", "192.0.2.1"},
		"bad file":             {"estate", "--case", dir, "--file", "../x.yaml", "192.0.2.1"},
		"bad output":           {"estate", "--case", dir, "--output", "xml", "192.0.2.1"},
		"bad rdap url":         {"estate", "--case", dir, "--rdap-url", "ftp://x", "192.0.2.1"},
		"bad resolver":         {"estate", "--case", dir, "--resolver", "not-a-hostport", "192.0.2.1"},
		"resolver is a target": {"estate", "--case", dir, "--resolver", "192.0.2.1:53", "192.0.2.1"},
		"bad timeout":          {"estate", "--case", dir, "--timeout", "0s", "192.0.2.1"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := run(t, d, args...)
			if code != exitUsage {
				t.Fatalf("exit %d, want 2\n%s", code, stderr)
			}
		})
	}
	p := d.ptr.(*stubPTR)
	if len(p.asked) != 0 {
		t.Errorf("a refused invocation asked %v", p.asked)
	}
}

// The real adapters, wired from flags: the registry is a local server, the resolver a
// port nobody listens on. Registry data is kept, the resolver failure ends the run
// incomplete, and the only host the registry saw a request for is its own.
func TestEstateRealAdaptersFromFlags(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = w.Write([]byte(`{"objectClassName":"ip network","handle":"NET-9","name":"N","startAddress":"192.0.2.0","endAddress":"192.0.2.255"}`))
	}))
	defer srv.Close()
	dir := copyExampleCase(t, "")
	code, stdout, stderr := run(t, testDeps(nil), "estate", "--case", dir, "--rdap-url", srv.URL, "--resolver", "127.0.0.1:1", "--timeout", "2s", "192.0.2.10")
	if code != exitFailure || !strings.Contains(stdout, "INCOMPLETE") || !strings.Contains(stdout, "rdns") {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if len(paths) != 1 || paths[0] != "/ip/192.0.2.10" {
		t.Errorf("registry paths %v", paths)
	}
	e := caseEstate(t, dir, "estate.yaml")
	found := false
	for _, n := range e.Nodes {
		found = found || n.ID == "network:net-9"
	}
	if !found {
		t.Errorf("%+v", e.Nodes)
	}
}
