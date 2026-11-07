package jb

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
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/estateseam"
)

// estateWorld is a synthetic estate the stubs answer for. Every question is recorded,
// so a test can prove that nothing was asked.
type estateWorld struct {
	asked  []string
	ns     []string
	failMX bool
	clock  time.Time
}

func newEstateWorld() *estateWorld {
	return &estateWorld{ns: []string{"ns1.example.com", "ns2.example.com"}, clock: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)}
}

func (w *estateWorld) LookupPTR(_ context.Context, ip netip.Addr) (core.PTRAnswer, error) {
	w.asked = append(w.asked, "ptr "+ip.String())
	return core.PTRAnswer{Query: "PTR " + ip.String() + " via stub", Names: []string{"edge.example.com"}}, nil
}

func (w *estateWorld) Lookup(_ context.Context, name string, t core.DNSType) (core.DNSAnswer, error) {
	w.asked = append(w.asked, "dns "+string(t)+" "+name)
	a := core.DNSAnswer{Query: fmt.Sprintf("%s %s via stub resolver", t, name)}
	switch {
	case t == core.DNSMX && w.failMX:
		return a, fmt.Errorf("%w: SERVFAIL", core.ErrLookupFailed)
	case t == core.DNSA:
		a.Values = []string{"192.0.2.10"}
	case t == core.DNSNS:
		a.Values = w.ns
	default:
		return a, fmt.Errorf("%w: none", core.ErrNotFound)
	}
	return a, nil
}

func (w *estateWorld) LookupSubdomains(_ context.Context, d string) (core.CTAnswer, error) {
	w.asked = append(w.asked, "ct "+d)
	return core.CTAnswer{Query: "GET https://ct.example.com/?q=" + d, Names: []string{"www." + d}, Truncated: true}, nil
}

func (w *estateWorld) LookupASN(_ context.Context, n uint32) (core.BGPAnnouncement, error) {
	w.asked = append(w.asked, fmt.Sprint("bgp AS", n))
	return core.BGPAnnouncement{Query: "GET https://bgp.example.com/AS", Holder: core.BGPHolder{ASN: n, Holder: "EXAMPLE-AS"},
		Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}, nil
}

func (w *estateWorld) LookupIP(context.Context, netip.Addr) (core.BGPOrigin, error) {
	return core.BGPOrigin{}, fmt.Errorf("%w: not used", core.ErrLookupFailed)
}

func (w *estateWorld) opts(file string) EstateOptions {
	return EstateOptions{File: file, Now: func() time.Time { return w.clock }}
}

// ctx carries the world's adapters into a library call (the unexported seam of RFC 0017).
func (w *estateWorld) ctx(t *testing.T) context.Context {
	return estateseam.With(t.Context(), estateseam.Ports{
		PTR: w, BGP: w, CT: w, DNS: w, Sleep: func(context.Context, time.Duration) error { return nil }})
}

func (w *estateWorld) tick() { w.clock = w.clock.Add(5 * 24 * time.Hour) }

// enableEstate lists external services in the example case's config.
func enableEstate(t *testing.T, dir string, services ...string) {
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

func keysOf(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func hasKeys(t *testing.T, what string, m map[string]json.RawMessage, want ...string) {
	t.Helper()
	if len(m) != len(want) {
		t.Errorf("%s has %d keys, want %v", what, len(m), want)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("%s lacks key %q", what, k)
		}
	}
}

func TestEstateIPReportsAnIncompleteLookupAndStoresNothingForIt(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	world := newEstateWorld()
	dir := copyCase(t)
	opts := EstateIPOptions{EstateOptions: world.opts(""), RDAPURL: srv.URL}

	res, err := EstateIP(world.ctx(t), dir, []string{"192.0.2.10"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() || len(res.Failures) != 1 || res.Failures[0].Lookup != "rdap" || !strings.Contains(res.Failures[0].Error, "503") {
		t.Fatalf("a registry that answered 503 must make the result incomplete: %+v", res)
	}
	if len(paths) != 1 || paths[0] != "/ip/192.0.2.10" {
		t.Errorf("registry paths %v", paths)
	}
	if !res.Wrote || res.Added.Nodes == 0 {
		t.Errorf("the reverse DNS answer is real and is kept: %+v", res)
	}
	m := keysOf(t, res)
	hasKeys(t, "EstateIPResult", m, "note", "file", "complete", "wrote", "addresses", "added", "unchanged", "failures", "conflicts")
	if string(m["complete"]) != "false" {
		t.Errorf("complete = %s", m["complete"])
	}
	for _, want := range []string{"CDN", "not who typed"} {
		if !strings.Contains(res.Note, want) {
			t.Errorf("note lacks %q", want)
		}
	}
}

func TestEstateIPRefusesTooManyAddressesAndMistakesBeforeAsking(t *testing.T) {
	world := newEstateWorld()
	dir := copyCase(t)
	for name, c := range map[string]struct {
		ips  []string
		opts EstateIPOptions
	}{
		"over the cap":    {[]string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, EstateIPOptions{EstateOptions: world.opts(""), MaxIPs: 2}},
		"over the ceil":   {[]string{"192.0.2.1"}, EstateIPOptions{EstateOptions: world.opts(""), MaxIPs: EstateMax + 1}},
		"not an address":  {[]string{"example.com"}, EstateIPOptions{EstateOptions: world.opts("")}},
		"no address":      {nil, EstateIPOptions{EstateOptions: world.opts("")}},
		"timeout too low": {[]string{"192.0.2.1"}, EstateIPOptions{EstateOptions: world.opts(""), Timeout: -time.Second}},
		"bad file name":   {[]string{"192.0.2.1"}, EstateIPOptions{EstateOptions: world.opts("../x.yaml")}},
		"bad rdap url":    {[]string{"192.0.2.1"}, EstateIPOptions{EstateOptions: world.opts(""), RDAPURL: "ftp://x"}},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := EstateIP(world.ctx(t), dir, c.ips, c.opts)
			if !IsUsage(err) || res != nil {
				t.Errorf("want a usage error and no result, got %v, %v", res, err)
			}
		})
	}
	if len(world.asked) != 0 {
		t.Errorf("a refused run asked %v", world.asked)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "estate", "estate.yaml")); err == nil && strings.Contains(string(b), "192.0.2.1") {
		t.Error("a refused run wrote the estate file")
	}
}

func TestEstateExternalServicesAreOffUntilTheCaseListsThem(t *testing.T) {
	calls := map[string]func(dir string, w *estateWorld) (*EstateExternalResult, error){
		"bgp": func(dir string, w *estateWorld) (*EstateExternalResult, error) {
			return EstateASN(w.ctx(t), dir, []string{"AS64500"}, EstateExternalOptions{EstateOptions: w.opts("")})
		},
		"dns": func(dir string, w *estateWorld) (*EstateExternalResult, error) {
			return EstateDNS(w.ctx(t), dir, []string{"example.com"}, EstateExternalOptions{EstateOptions: w.opts("")})
		},
		"crt.sh": func(dir string, w *estateWorld) (*EstateExternalResult, error) {
			return EstateCT(w.ctx(t), dir, []string{"example.com"}, EstateExternalOptions{EstateOptions: w.opts("")})
		},
	}
	for service, call := range calls {
		t.Run(service, func(t *testing.T) {
			w := newEstateWorld()
			dir := copyCase(t)
			res, err := call(dir, w)
			if !IsUsage(err) || res != nil || len(w.asked) != 0 {
				t.Fatalf("a service the case does not list must be refused with nothing sent: %v %v %v", res, err, w.asked)
			}
			if !strings.Contains(err.Error(), `"`+service+`" service is not enabled`) {
				t.Errorf("the refusal must name the service: %v", err)
			}
			var others []string
			for s := range calls {
				if s != service {
					others = append(others, s)
				}
			}
			enableEstate(t, dir, others...) // the switch is per service
			if _, err := call(dir, w); !IsUsage(err) || len(w.asked) != 0 {
				t.Errorf("another service being on must not enable this one: %v %v", err, w.asked)
			}
			editEstateSwitch(t, dir, others, append(others, service))
			if res, err := call(dir, w); err != nil || len(w.asked) == 0 || res.Service != service {
				t.Errorf("an enabled service must run: %+v %v", res, err)
			}
		})
	}
}

// editEstateSwitch replaces the estate.external list that enableEstate wrote.
func editEstateSwitch(t *testing.T, dir string, from, to []string) {
	t.Helper()
	p := filepath.Join(dir, "config", "hunt.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	old := "external: [" + strings.Join(from, ", ") + "]"
	if !strings.Contains(string(b), old) {
		t.Fatalf("config lacks %q", old)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), old, "external: ["+strings.Join(to, ", ")+"]", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEstateCTTruncationIsIncompleteAndTooManyTargetsAreRefused(t *testing.T) {
	w := newEstateWorld()
	dir := copyCase(t)
	enableEstate(t, dir, "crt.sh")
	res, err := EstateCT(w.ctx(t), dir, []string{"example.com"}, EstateExternalOptions{EstateOptions: w.opts("")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() || len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Error, "truncated") {
		t.Fatalf("a cut result must say so: %+v", res)
	}
	hasKeys(t, "EstateExternalResult", keysOf(t, res), "note", "notes", "service", "asked", "file", "complete", "wrote", "targets", "added", "unchanged", "failures", "conflicts")

	w.asked = nil
	_, err = EstateCT(w.ctx(t), dir, []string{"a.example.com", "b.example.com", "c.example.com"}, EstateExternalOptions{EstateOptions: w.opts(""), MaxTargets: 2})
	if !IsUsage(err) || len(w.asked) != 0 || !strings.Contains(err.Error(), "the cap is 2") {
		t.Errorf("a longer list is refused whole, before anything is asked: %v %v", err, w.asked)
	}
}

func TestEstateRefreshDiffPromoteRoundTrip(t *testing.T) {
	w := newEstateWorld()
	dir := copyCase(t)
	enableEstate(t, dir, "dns")
	base := w.opts("base.yaml")
	if _, err := EstateDNS(w.ctx(t), dir, []string{"example.com"}, EstateExternalOptions{EstateOptions: base}); err != nil {
		t.Fatal(err)
	}

	// A failed MX lookup makes the snapshot incomplete, and an incomplete one is never a baseline.
	w.tick()
	w.failMX = true
	snap, err := EstateRefresh(w.ctx(t), dir, EstateRefreshOptions{EstateOptions: base})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Complete() || len(snap.Failures) == 0 {
		t.Fatalf("a failed lookup must make the refresh incomplete: %+v", snap)
	}
	hasKeys(t, "EstateRefreshResult", keysOf(t, snap), "note", "snapshot", "file", "based_on", "complete", "nodes", "edges", "absences", "services", "failures")
	if _, err := EstateDiff(t.Context(), dir, EstateDiffOptions{EstateOptions: base}); err == nil {
		t.Error("a diff against an incomplete snapshot must be refused")
	}
	if _, err := EstatePromote(dir, snap.Snapshot, base); !IsUsage(err) {
		t.Errorf("promoting an incomplete snapshot must be a usage error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "estate", "archive")); err == nil {
		t.Error("a refused promotion archived the baseline")
	}

	// The world changes; a complete refresh shows it as drift.
	w.tick()
	w.failMX = false
	w.ns = []string{"ns1.example.com", "ns7.example.com"}
	snap, err = EstateRefresh(w.ctx(t), dir, EstateRefreshOptions{EstateOptions: base})
	if err != nil || !snap.Complete() {
		t.Fatalf("%+v %v", snap, err)
	}
	var log strings.Builder
	diffOpts := EstateDiffOptions{EstateOptions: base, Alert: true, Out: &log}
	diff, err := EstateDiff(t.Context(), dir, diffOpts)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Alerts == nil || diff.Alerts.New != 1 || len(diff.Findings) == 0 || diff.Findings[0].Severity != "high" {
		t.Fatalf("a new NS is a high finding that alerts once: %+v", diff)
	}
	hasKeys(t, "EstateDiffResult", keysOf(t, diff), "note", "from", "to", "questions_compared", "changes", "not_comparable", "nodes_not_compared", "counts", "findings", "alerts")
	if !strings.Contains(log.String(), "ALERT [high]") || strings.Contains(log.String(), "ns7") {
		t.Errorf("alert output: %q", log.String())
	}
	if again, _ := EstateDiff(t.Context(), dir, diffOpts); again == nil || again.Alerts.New != 0 || again.Alerts.Suppressed != 1 {
		t.Errorf("the same drift is held back by its stable tag: %+v", again)
	}

	p, err := EstatePromote(dir, snap.Snapshot, base)
	if err != nil || p.Promoted != snap.Snapshot || p.Archived == "" {
		t.Fatalf("%+v %v", p, err)
	}
	hasKeys(t, "EstatePromoteResult", keysOf(t, p), "promoted", "baseline", "archived")
	if after, err := EstateDiff(t.Context(), dir, EstateDiffOptions{EstateOptions: base}); err != nil || len(after.Changes) != 0 {
		t.Errorf("after promotion the drift is accepted: %+v %v", after, err)
	}
}

func TestEstateRefreshRefusesMoreTargetsThanTheCapAndAsksNothing(t *testing.T) {
	w := newEstateWorld()
	dir := copyCase(t)
	enableEstate(t, dir, "dns", "bgp")
	base := w.opts("base.yaml")
	if _, err := EstateDNS(w.ctx(t), dir, []string{"example.com"}, EstateExternalOptions{EstateOptions: base}); err != nil {
		t.Fatal(err)
	}
	if _, err := EstateASN(w.ctx(t), dir, []string{"AS64500"}, EstateExternalOptions{EstateOptions: base}); err != nil {
		t.Fatal(err)
	}
	w.asked = nil
	if _, err := EstateRefresh(w.ctx(t), dir, EstateRefreshOptions{EstateOptions: base, MaxTargets: 1}); !IsUsage(err) || len(w.asked) != 0 {
		t.Errorf("a longer list is refused whole: %v %v", err, w.asked)
	}
	if _, err := EstateRefresh(w.ctx(t), dir, EstateRefreshOptions{EstateOptions: base, MaxTargets: 2}); err != nil {
		t.Errorf("two targets fit a cap of two: %v", err)
	}
	if _, err := EstateRefresh(w.ctx(t), dir, EstateRefreshOptions{EstateOptions: w.opts("none.yaml")}); err == nil || IsUsage(err) {
		t.Errorf("a missing baseline is an error, not an empty one: %v", err)
	}
}

// A baseline edited between refresh and promote is refused as a usage error, and the
// edit survives. The digest the refresh stored comes from the bytes it read.
func TestEstatePromoteRefusesABaselineEditedAfterRefresh(t *testing.T) {
	w := newEstateWorld()
	dir := copyCase(t)
	enableEstate(t, dir, "dns")
	base := w.opts("base.yaml")
	if _, err := EstateDNS(w.ctx(t), dir, []string{"example.com"}, EstateExternalOptions{EstateOptions: base}); err != nil {
		t.Fatal(err)
	}
	w.tick()
	snap, err := EstateRefresh(w.ctx(t), dir, EstateRefreshOptions{EstateOptions: base})
	if err != nil || !snap.Complete() {
		t.Fatalf("%+v %v", snap, err)
	}
	file := filepath.Join(dir, "estate", "base.yaml")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	edited := append(data, []byte("# hand edit\n")...)
	if err := os.WriteFile(file, edited, 0o640); err != nil {
		t.Fatal(err)
	}
	_, err = EstatePromote(dir, snap.Snapshot, base)
	if !IsUsage(err) || !strings.Contains(err.Error(), "baseline changed since the snapshot; refresh again") {
		t.Fatalf("want a usage error naming the change, got %v", err)
	}
	if got, _ := os.ReadFile(file); string(got) != string(edited) {
		t.Error("the edited baseline was overwritten")
	}
	if _, err := os.Stat(filepath.Join(dir, "estate", "archive")); err == nil {
		t.Error("a refused promotion archived the baseline")
	}
}
