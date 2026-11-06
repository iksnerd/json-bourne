package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// driftWorld is a synthetic estate the stubs answer for: one domain with an address, NS
// and certificate names, and one AS. Tests change it between runs to make drift.
type driftWorld struct {
	label   string   // names the resolver in the method, as the real adapter does
	addr    string   // example.com A
	ns      []string // example.com NS
	ctNames []string
	failMX  bool
	asked   []string
	clock   time.Time
}

func newWorld() *driftWorld {
	return &driftWorld{label: "stub resolver one", addr: "192.0.2.10", ns: []string{"ns1.example.com", "ns2.example.com"}, ctNames: []string{"www.example.com"},
		clock: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)}
}

func (w *driftWorld) Lookup(_ context.Context, name string, t core.DNSType) (core.DNSAnswer, error) {
	w.asked = append(w.asked, "dns "+string(t)+" "+name)
	a := core.DNSAnswer{Query: fmt.Sprintf("%s %s via %s", t, name, w.label)}
	switch {
	case t == core.DNSMX && w.failMX:
		return a, fmt.Errorf("%w: SERVFAIL", core.ErrLookupFailed)
	case t == core.DNSA:
		a.Values = []string{w.addr}
	case t == core.DNSNS:
		a.Values = w.ns
	default:
		return a, fmt.Errorf("%w: none", core.ErrNotFound)
	}
	return a, nil
}

func (w *driftWorld) LookupSubdomains(_ context.Context, d string) (core.CTAnswer, error) {
	w.asked = append(w.asked, "ct "+d)
	return core.CTAnswer{Query: "GET https://ct.example.com/?q=%25." + d, Names: w.ctNames}, nil
}

func (w *driftWorld) LookupASN(_ context.Context, n uint32) (core.BGPAnnouncement, error) {
	w.asked = append(w.asked, fmt.Sprint("bgp AS", n))
	return core.BGPAnnouncement{Query: "GET https://bgp.example.com/AS", Holder: core.BGPHolder{ASN: n, Holder: "EXAMPLE-AS"},
		Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}, nil
}

func (w *driftWorld) LookupIP(context.Context, netip.Addr) (core.BGPOrigin, error) {
	return core.BGPOrigin{}, fmt.Errorf("%w: not used", core.ErrLookupFailed)
}

func (w *driftWorld) deps() deps {
	d := testDeps(nil)
	d.fwd, d.ct, d.bgp = w, w, w
	d.now = func() time.Time { return w.clock }
	d.sleep = func(context.Context, time.Duration) error { return nil }
	return d
}

func (w *driftWorld) tick() { w.clock = w.clock.Add(5 * 24 * time.Hour) }

// baseline records the world with the three external collectors into base.yaml.
func (w *driftWorld) baseline(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{{"dns", "example.com"}, {"ct", "example.com"}, {"asn", "AS64500"}} {
		a := append([]string{"estate", args[0], "--case", dir, "--file", "base.yaml"}, args[1:]...)
		if code, out, errs := run(t, w.deps(), a...); code != 0 {
			t.Fatalf("baseline %v: exit %d\n%s\n%s", args, code, out, errs)
		}
	}
}

type diffJSON struct {
	Compared int `json:"questions_compared"`
	Changes  []struct {
		Kind         string `json:"kind"`
		Type         string `json:"type"`
		Subject      string `json:"subject"`
		Relation     string `json:"relation"`
		Source       string `json:"source"`
		FromObserved string `json:"from_observed"`
		ToObserved   string `json:"to_observed"`
		Detail       string `json:"detail"`
	} `json:"changes"`
	NotComparable []struct {
		Source string `json:"source"`
		Method string `json:"method"`
		Side   string `json:"side"`
		Claims int    `json:"claims"`
	} `json:"not_comparable"`
	Findings []struct {
		Detector string `json:"detector"`
		Tag      string `json:"tag"`
		Severity string `json:"severity"`
		Summary  string `json:"summary"`
	} `json:"findings"`
	Counts map[string]struct {
		Added   int `json:"added"`
		Removed int `json:"removed"`
		Changed int `json:"changed"`
	} `json:"counts"`
}

func runDiff(t *testing.T, w *driftWorld, dir string, extra ...string) (int, diffJSON, string, string) {
	t.Helper()
	args := append([]string{"estate", "diff", "--case", dir, "--file", "base.yaml", "--output", "json"}, extra...)
	code, out, errs := run(t, w.deps(), args...)
	var d diffJSON
	if out != "" {
		if err := json.Unmarshal([]byte(out), &d); err != nil {
			t.Fatalf("diff output is not JSON: %v\n%s", err, out)
		}
	}
	return code, d, out, errs
}

func snapshotFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, _ := os.ReadDir(filepath.Join(dir, "estate", "snapshots"))
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func TestEstateDriftEndToEnd(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "dns", "bgp", "crt.sh")
	w := newWorld()
	w.baseline(t, dir)
	basePath := filepath.Join(dir, "estate", "base.yaml")
	baseBefore, _ := os.ReadFile(basePath)

	// Nothing has changed: the first refresh matches the baseline.
	w.tick()
	code, out, errs := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml")
	if code != 0 {
		t.Fatalf("refresh: exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"complete    true", "20261106T100000Z", "not modified", "promote"} {
		if !strings.Contains(out, want) {
			t.Errorf("refresh output lacks %q:\n%s", want, out)
		}
	}
	if after, _ := os.ReadFile(basePath); string(after) != string(baseBefore) {
		t.Fatal("refresh changed the baseline file; only promote may")
	}
	code, d, raw, errs := runDiff(t, w, dir)
	if code != 0 || len(d.Changes) != 0 || len(d.Findings) != 0 || d.Compared == 0 || len(d.NotComparable) != 0 {
		t.Fatalf("no drift expected: exit %d\n%s\n%s", code, raw, errs)
	}

	// The world changes: new address, one NS gone and one new, a new certificate name.
	w.tick()
	w.addr, w.ns, w.ctNames = "192.0.2.99", []string{"ns1.example.com", "ns3.example.com"}, []string{"www.example.com", "vpn.example.com"}
	if code, out, errs = run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml"); code != 0 {
		t.Fatalf("second refresh: exit %d\n%s\n%s", code, out, errs)
	}
	if got := snapshotFiles(t, dir); len(got) != 2 {
		t.Fatalf("each refresh writes a new file: %v", got)
	}
	code, d, raw, errs = runDiff(t, w, dir)
	if code != 0 {
		t.Fatalf("diff: exit %d\n%s\n%s", code, raw, errs)
	}
	sev := map[string]string{}
	for _, f := range d.Findings {
		sev[f.Tag[:strings.LastIndex(f.Tag, ":")]] = f.Severity
		if f.Detector != "estate_drift" || strings.Contains(f.Summary, "ns3") || strings.Contains(f.Summary, "vpn") || strings.Contains(f.Summary, "192.0.2.99") {
			t.Errorf("finding must not carry values: %+v", f)
		}
	}
	want := map[string]string{
		"estate_drift:ns:domain:example.com":      "high",
		"estate_drift:address:domain:example.com": "activity",
		"estate_drift:ct:domain:example.com":      "check",
	}
	if len(sev) != len(want) {
		t.Fatalf("findings %v\n%s", sev, raw)
	}
	for k, v := range want {
		if sev[k] != v {
			t.Errorf("%s: severity %q, want %q", k, sev[k], v)
		}
	}
	for _, c := range d.Changes {
		if c.FromObserved != "2026-11-01T10:00:00Z" && c.FromObserved != "2026-11-06T10:00:00Z" || c.ToObserved != "2026-11-11T10:00:00Z" {
			t.Errorf("every change names both observation times: %+v", c)
		}
	}
	if !strings.Contains(raw, "not who typed the commands") || !strings.Contains(raw, "CDN") {
		t.Errorf("the attribution caveat must travel with the output:\n%s", raw)
	}

	// Table form says what it compared.
	_, tbl, _ := run(t, w.deps(), "estate", "diff", "--case", dir, "--file", "base.yaml")
	for _, s := range []string{"from", "to", "same source and same method", "ADDED", "REMOVED", "FINDINGS", "[high]"} {
		if !strings.Contains(tbl, s) {
			t.Errorf("table lacks %q:\n%s", s, tbl)
		}
	}

	// Promotion adopts the snapshot: the baseline is archived, then replaced; the drift is accepted.
	snaps := snapshotFiles(t, dir)
	id := strings.TrimSuffix(snaps[len(snaps)-1], ".yaml")
	if code, out, errs = run(t, w.deps(), "estate", "promote", "--case", dir, "--file", "base.yaml", id); code != 0 {
		t.Fatalf("promote: exit %d\n%s\n%s", code, out, errs)
	}
	if arch, err := os.ReadFile(filepath.Join(dir, "estate", "archive", "base-"+id+".yaml")); err != nil || string(arch) == "" {
		t.Errorf("the old baseline must be archived: %v", err)
	}
	if code, d, raw, _ = runDiff(t, w, dir); code != 0 || len(d.Changes) != 0 {
		t.Errorf("after promotion there is no drift: %d\n%s", code, raw)
	}
	if code, out, _ := run(t, testDeps(nil), "case", "check", dir); code != 0 {
		t.Errorf("case check with snapshots and archive present: %d\n%s", code, out)
	}
}

// A different resolver is a different method. Its answers differ, and none of that is drift.
func TestEstateDriftMethodChangeIsNotComparableNotDrift(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "dns")
	w := newWorld()
	w.baseline2(t, dir)
	w.tick()
	w.label, w.addr, w.ns = "stub resolver two", "198.51.100.7", []string{"ns9.example.net"}
	if code, out, errs := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml"); code != 0 {
		t.Fatalf("refresh: %d\n%s\n%s", code, out, errs)
	}
	code, d, raw, errs := runDiff(t, w, dir)
	if code != 0 {
		t.Fatalf("diff: %d\n%s\n%s", code, raw, errs)
	}
	for _, c := range d.Changes {
		if c.Type == "edge" || c.Type == "absence" {
			t.Errorf("a resolver change reported as drift: %+v", c)
		}
	}
	if len(d.Findings) != 0 {
		t.Errorf("no findings from a method change: %+v", d.Findings)
	}
	var from, to int
	for _, n := range d.NotComparable {
		if n.Side == "from only" {
			from++
		}
		if n.Side == "to only" {
			to++
		}
	}
	if from == 0 || to == 0 || d.Compared != 0 {
		t.Errorf("the unmatched questions must be listed on both sides: %d %d compared %d\n%s", from, to, d.Compared, raw)
	}
}

func (w *driftWorld) baseline2(t *testing.T, dir string) {
	t.Helper()
	if code, out, errs := run(t, w.deps(), "estate", "dns", "--case", dir, "--file", "base.yaml", "example.com"); code != 0 {
		t.Fatalf("baseline: %d\n%s\n%s", code, out, errs)
	}
}

func TestEstateRefreshFailedLookupIsIncompleteAndNeverTheBaseline(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "dns")
	w := newWorld()
	w.baseline2(t, dir)
	basePath := filepath.Join(dir, "estate", "base.yaml")
	baseBefore, _ := os.ReadFile(basePath)

	w.tick()
	w.failMX = true
	code, out, errs := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml")
	if code != exitFailure || !strings.Contains(out, "INCOMPLETE") || !strings.Contains(out, "dns/MX") || !strings.Contains(errs, "incomplete") {
		t.Fatalf("a failed lookup must end the run INCOMPLETE with exit 1: %d\n%s\n%s", code, out, errs)
	}
	snaps := snapshotFiles(t, dir)
	if len(snaps) != 1 {
		t.Fatalf("the incomplete snapshot is kept as a record: %v", snaps)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "estate", "snapshots", snaps[0]))
	if !strings.Contains(string(raw), "complete: false") {
		t.Errorf("the snapshot must be marked incomplete:\n%s", raw)
	}
	// diff against the default (newest) snapshot refuses.
	if code, _, _, errs := runDiff(t, w, dir); code != exitFailure || !strings.Contains(errs, "incomplete") {
		t.Errorf("diff must refuse an incomplete snapshot: %d %s", code, errs)
	}
	// promote refuses, and the baseline is untouched.
	id := strings.TrimSuffix(snaps[0], ".yaml")
	if code, _, errs := run(t, w.deps(), "estate", "promote", "--case", dir, "--file", "base.yaml", id); code == 0 || !strings.Contains(errs, "incomplete") {
		t.Errorf("promote must refuse an incomplete snapshot: %d %s", code, errs)
	}
	if after, _ := os.ReadFile(basePath); string(after) != string(baseBefore) {
		t.Error("the baseline changed")
	}
	if _, err := os.Stat(filepath.Join(dir, "estate", "archive")); err == nil {
		t.Error("nothing may be archived when promotion is refused")
	}
}

func TestEstateRefreshSkipsServicesThatAreNotEnabledAndListsThem(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "dns", "bgp", "crt.sh")
	w := newWorld()
	w.baseline(t, dir)
	// Now only dns stays on.
	editFile(t, filepath.Join(dir, "config", "hunt.yaml"), "external: [dns, bgp, crt.sh]", "external: [dns]")
	w.asked = nil
	w.tick()
	code, out, errs := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	for _, a := range w.asked {
		if strings.HasPrefix(a, "bgp") || strings.HasPrefix(a, "ct") {
			t.Errorf("a service that is off was asked: %s", a)
		}
	}
	for _, want := range []string{"bgp", "crt.sh", "SKIPPED", "not enabled in estate.external"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// The skipped questions are listed by diff, not read as removals.
	code, d, raw, _ := runDiff(t, w, dir)
	if code != 0 || d.Counts["all"].Removed != 0 {
		t.Errorf("skipped services must not read as removals: %d\n%s", code, raw)
	}
	sawBGP := false
	for _, n := range d.NotComparable {
		sawBGP = sawBGP || (n.Source == "bgp" && n.Side == "from only")
	}
	if !sawBGP {
		t.Errorf("the skipped bgp question must be listed as not comparable:\n%s", raw)
	}
	// And the snapshot cannot become the baseline: it would lose those claims.
	snaps := snapshotFiles(t, dir)
	id := strings.TrimSuffix(snaps[len(snaps)-1], ".yaml")
	if code, _, errs := run(t, w.deps(), "estate", "promote", "--case", dir, "--file", "base.yaml", id); code == 0 || !strings.Contains(errs, "skipped") {
		t.Errorf("promoting a snapshot that skipped a service must be refused: %d %s", code, errs)
	}
}

func TestEstateDriftRefusals(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "dns")
	w := newWorld()
	// No baseline: an error, never an empty one.
	if code, _, errs := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "nope.yaml"); code == 0 || !strings.Contains(errs, "baseline") {
		t.Errorf("a missing baseline: %d %s", code, errs)
	}
	w.baseline2(t, dir)
	// No snapshot to compare with.
	if code, _, errs := run(t, w.deps(), "estate", "diff", "--case", dir, "--file", "base.yaml"); code != exitUsage || !strings.Contains(errs, "no snapshot") {
		t.Errorf("no snapshot: %d %s", code, errs)
	}
	// A corrupt snapshot is an error, not an empty baseline.
	w.tick()
	if code, _, _ := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml"); code != 0 {
		t.Fatal("refresh")
	}
	snaps := snapshotFiles(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "estate", "snapshots", snaps[0]), []byte("apiVersion: jb.estate-snapshot/v1\nbogus: true\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := run(t, w.deps(), "estate", "diff", "--case", dir, "--file", "base.yaml"); code == 0 || errs == "" {
		t.Errorf("a corrupt snapshot must be an error: %d %s", code, errs)
	}
	// A corrupt baseline likewise.
	if err := os.WriteFile(filepath.Join(dir, "estate", "base.yaml"), []byte("apiVersion: jb.estate/v1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml"); code == 0 || !strings.Contains(errs, "baseline") {
		t.Errorf("a corrupt baseline: %d %s", code, errs)
	}
}

func TestEstateDriftDoesNotSendWhenOnlyDiffing(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "dns")
	w := newWorld()
	w.baseline2(t, dir)
	w.tick()
	run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml")
	w.asked = nil
	run(t, w.deps(), "estate", "diff", "--case", dir, "--file", "base.yaml")
	run(t, w.deps(), "estate", "diff", "--case", dir, "--file", "base.yaml", "--alert")
	if len(w.asked) != 0 {
		t.Errorf("diff is local: it must ask nobody, asked %v", w.asked)
	}
}

func TestEstateDiffAlertDedupes(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "dns")
	w := newWorld()
	w.baseline2(t, dir)
	w.tick()
	w.ns = []string{"ns1.example.com", "ns7.example.com"}
	if code, out, errs := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml"); code != 0 {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	alert := func() string {
		code, out, errs := run(t, w.deps(), "estate", "diff", "--case", dir, "--file", "base.yaml", "--alert")
		if code != 0 {
			t.Fatalf("exit %d\n%s\n%s", code, out, errs)
		}
		return out + errs
	}
	first := alert()
	if !strings.Contains(first, "alerts   1 new, 0 held back") || !strings.Contains(first, "ALERT [high]") {
		t.Fatalf("first run alerts:\n%s", first)
	}
	if second := alert(); !strings.Contains(second, "alerts   0 new, 1 held back") {
		t.Errorf("the same drift is held back by its stable tag:\n%s", second)
	}
	log, err := os.ReadFile(filepath.Join(dir, "evidence", "estate-drift.log"))
	if err != nil || strings.Count(string(log), "ALERT") != 1 || strings.Contains(string(log), "ns7") {
		t.Errorf("one alert line in the log, no values: %v\n%s", err, log)
	}
}

func TestEstateRefreshRefusesMoreTargetsThanTheCapAndAsksNothing(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "dns", "bgp", "crt.sh")
	w := newWorld()
	w.baseline(t, dir) // two distinct targets: example.com and AS64500
	w.asked = nil
	code, out, errs := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml", "--max-targets", "1")
	if code != exitUsage || !strings.Contains(errs, "too many targets") || len(w.asked) != 0 || out != "" {
		t.Fatalf("a longer list is refused whole, before anything is asked: %d %v\n%s\n%s", code, w.asked, out, errs)
	}
	if got := snapshotFiles(t, dir); len(got) != 0 {
		t.Errorf("a refused run wrote a snapshot: %v", got)
	}
	if code, _, errs := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml", "--max-targets", "2"); code != 0 {
		t.Errorf("two targets fit a cap of two: %d %s", code, errs)
	}
}
