package signup

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// All data is synthetic: example.* domains and paths that belong to no product.
var (
	t0  = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	win = core.Window{From: t0, To: t0.Add(10 * time.Minute)}
)

const (
	createPath = "/account/create"
	formPath   = "/account/create/form"
)

type fakeReader struct {
	evs    []core.Event
	err    error
	onEnd  func()
	gotWin *core.Window
}

// Events ignores ctx on purpose: stopping must be the detector's doing.
func (f fakeReader) Events(_ context.Context, w core.Window) iter.Seq2[core.Event, error] {
	return func(yield func(core.Event, error) bool) {
		if f.gotWin != nil {
			*f.gotWin = w
		}
		for _, ev := range f.evs {
			if !yield(ev, nil) {
				return
			}
		}
		if f.onEnd != nil {
			f.onEnd()
		}
		if f.err != nil {
			yield(core.Event{}, f.err)
		}
	}
}

type req struct {
	path, method string
	status       any
	address      any
	n            int
}

func evs(reqs ...req) []core.Event {
	var out []core.Event
	for _, r := range reqs {
		n := r.n
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			f := map[string]any{"path": r.path, "method": r.method, "status": r.status}
			if r.address != nil {
				f["email"] = r.address
			}
			out = append(out, core.Event{Time: t0, Source: "synthetic", Kind: "http", Fields: f})
		}
	}
	return out
}

func created(n int) req    { return req{path: createPath, method: "POST", status: 302, n: n} }
func rejected(n int) req   { return req{path: createPath, method: "POST", status: 400, n: n} }
func formRender(n int) req { return req{path: createPath, method: "GET", status: 200, n: n} }
func otherForm(n int) req  { return req{path: formPath, method: "GET", status: 200, n: n} }
func createdBy(addr string) req {
	return req{path: createPath, method: "POST", status: 302, address: addr}
}

func baseCfg() Config {
	return Config{
		CreatePaths: []string{createPath}, PathField: "path", StatusField: "status",
		MethodField: "method", Methods: []string{"POST"},
	}
}

func mustNew(t *testing.T, c Config) *Detector {
	t.Helper()
	d, err := New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func detect(t *testing.T, c Config, cur, prev []core.Event) ([]core.Finding, error) {
	t.Helper()
	return mustNew(t, c).Detect(context.Background(), fakeReader{evs: cur}, fakeReader{evs: prev}, win)
}

func byTag(fs []core.Finding, tag string) *core.Finding {
	for i := range fs {
		if fs[i].Tag == tag {
			return &fs[i]
		}
	}
	return nil
}

func TestBurstRaisedOnCreationsAndMultiple(t *testing.T) {
	fs, err := detect(t, baseCfg(), evs(created(30)), evs(created(4)))
	if err != nil {
		t.Fatal(err)
	}
	f := byTag(fs, "signup")
	if f == nil || len(fs) != 1 {
		t.Fatalf("want one finding tagged signup, got %+v", fs)
	}
	if f.Severity != core.SevActivity || f.Detector != "signup" {
		t.Errorf("severity %v detector %q", f.Severity, f.Detector)
	}
	if f.Detail["creations_cur"] != 30 || f.Detail["creations_prev"] != 4 || f.Detail["baseline_empty"] != false {
		t.Errorf("detail %v", f.Detail)
	}
	if f.Baseline != win.Previous() {
		t.Errorf("baseline window %v", f.Baseline)
	}
}

// The rule that cost a week: 1,071 form renders against 87 accounts. A form render
// is a GET on the same path, or a different path; neither is a creation.
func TestFormRendersAreNeverCreations(t *testing.T) {
	cur := evs(created(2), formRender(500), otherForm(500))
	fs, err := detect(t, baseCfg(), cur, evs(created(1)))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("1,000 form renders and 2 creations must not raise: %+v", fs)
	}
}

func TestWithoutMethodFieldSamePathGETCounts(t *testing.T) {
	// Without method_field a GET on the create path cannot be told apart, so it
	// counts. The doc says so; this pins the behaviour so it is not silent.
	c := baseCfg()
	c.MethodField, c.Methods = "", nil
	fs, err := detect(t, c, evs(formRender(30)), evs(created(1)))
	if err != nil || len(fs) != 1 {
		t.Fatalf("fs %v err %v", fs, err)
	}
}

func TestOnlyConfiguredSuccessStatusesCount(t *testing.T) {
	// 400s on the creating endpoint are attempts, not accounts.
	fs, err := detect(t, baseCfg(), evs(created(2), rejected(200)), evs(created(1)))
	if err != nil || len(fs) != 0 {
		t.Fatalf("rejected attempts counted as accounts: %v %v", fs, err)
	}
	c := baseCfg()
	c.SuccessStatuses = []int{201}
	fs, err = detect(t, c, evs(req{path: createPath, method: "POST", status: 201, n: 9}, created(50)), evs(created(1)))
	if err != nil || len(fs) != 1 || fs[0].Detail["creations_cur"] != 9 || fs[0].Detail["attempts_cur"] != 59 {
		t.Fatalf("custom status list: %v %v", fs, err)
	}
}

func TestPathMatchIsExactNotSubstring(t *testing.T) {
	// "/account/create" must not match "/account/create/form" or "/account/created".
	cur := evs(req{path: createPath + "/form", method: "POST", status: 302, n: 40},
		req{path: createPath + "d", method: "POST", status: 302, n: 40},
		req{path: createPath + "?utm=1", method: "POST", status: 302, n: 3},
		req{path: createPath + "/", method: "POST", status: 302, n: 3})
	c := baseCfg()
	c.MinCreations = 7
	fs, err := detect(t, c, cur, evs(created(1)))
	if err != nil || len(fs) != 0 {
		t.Fatalf("substring match: %v %v", fs, err)
	}
	// Query string and trailing slash are tolerated: 3+3 = 6 creations.
	c.MinCreations = 6
	fs, err = detect(t, c, cur, evs(created(1)))
	if err != nil || len(fs) != 1 || fs[0].Detail["creations_cur"] != 6 {
		t.Fatalf("query/slash: %v %v", fs, err)
	}
}

func TestBelowMinCreationsIsQuiet(t *testing.T) {
	fs, err := detect(t, baseCfg(), evs(created(4)), evs(created(1)))
	if err != nil || len(fs) != 0 {
		t.Fatalf("default min is 5: %v %v", fs, err)
	}
	fs, err = detect(t, baseCfg(), evs(created(5)), evs(created(1)))
	if err != nil || len(fs) != 1 {
		t.Fatalf("exactly the minimum raises: %v %v", fs, err)
	}
}

func TestMultipleOfPreviousRequired(t *testing.T) {
	// 30 now, 20 before: above N but only 1.5x. A steadily busy signup is not a burst.
	fs, err := detect(t, baseCfg(), evs(created(30)), evs(created(20)))
	if err != nil || len(fs) != 0 {
		t.Fatalf("1.5x is not a burst at factor 3: %v %v", fs, err)
	}
	// exactly 3x raises (boundary is inclusive).
	fs, err = detect(t, baseCfg(), evs(created(30)), evs(created(10)))
	if err != nil || len(fs) != 1 {
		t.Fatalf("exactly 3x must raise: %v %v", fs, err)
	}
	c := baseCfg()
	c.Factor = 1.2
	fs, err = detect(t, c, evs(created(30)), evs(created(20)))
	if err != nil || len(fs) != 1 {
		t.Fatalf("factor 1.2 must raise at 1.5x: %v %v", fs, err)
	}
}

func TestPreviousWithAttemptsButNoCreationsIsRealBaseline(t *testing.T) {
	fs, err := detect(t, baseCfg(), evs(created(8)), evs(rejected(3)))
	if err != nil || len(fs) != 1 {
		t.Fatalf("%v %v", fs, err)
	}
	if fs[0].Severity != core.SevActivity || fs[0].Detail["baseline_empty"] != false {
		t.Errorf("a window with attempts is not an empty baseline: %v", fs[0])
	}
}

func TestEmptyBaselineReportedAndSeverityLowered(t *testing.T) {
	fs, err := detect(t, baseCfg(), evs(created(30)), nil)
	if err != nil || len(fs) != 1 {
		t.Fatalf("%v %v", fs, err)
	}
	f := fs[0]
	if f.Severity != core.SevCheck || f.Detail["baseline_empty"] != true {
		t.Errorf("want check + baseline_empty, got %v %v", f.Severity, f.Detail)
	}
	if !strings.Contains(f.Summary, "no preceding") {
		t.Errorf("summary should say there was nothing to compare: %q", f.Summary)
	}
}

func TestEmptyCurrentWindowIsErrNoRecords(t *testing.T) {
	for name, cur := range map[string][]core.Event{
		"no events":        nil,
		"only other paths": evs(req{path: "/health", method: "GET", status: 200, n: 10}),
		"unparsable":       evs(req{path: createPath, method: "POST", status: "n/a", n: 10}),
	} {
		fs, err := detect(t, baseCfg(), cur, evs(created(10)))
		if !errors.Is(err, core.ErrNoRecords) || fs != nil {
			t.Errorf("%s: want ErrNoRecords, got %v %v", name, fs, err)
		}
	}
}

func TestZeroCreationsWithAttemptsIsAnswerNotError(t *testing.T) {
	fs, err := detect(t, baseCfg(), evs(rejected(10)), evs(created(10)))
	if err != nil || len(fs) != 0 {
		t.Fatalf("attempts present, none created: %v %v", fs, err)
	}
}

func TestReaderErrorsPropagate(t *testing.T) {
	boom := errors.New("backend down")
	d := mustNew(t, baseCfg())
	_, err := d.Detect(context.Background(), fakeReader{evs: evs(created(30)), err: boom}, fakeReader{}, win)
	if !errors.Is(err, boom) || errors.Is(err, core.ErrNoRecords) {
		t.Errorf("current: %v", err)
	}
	_, err = d.Detect(context.Background(), fakeReader{evs: evs(created(30))}, fakeReader{err: boom}, win)
	if !errors.Is(err, boom) {
		t.Errorf("a failed baseline read must not be an empty baseline: %v", err)
	}
}

func TestCancellationIsAnErrorNotAShortWindow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cur := fakeReader{evs: evs(created(30)), onEnd: cancel}
	fs, err := mustNew(t, baseCfg()).Detect(ctx, cur, fakeReader{evs: evs(created(1))}, win)
	if !errors.Is(err, context.Canceled) || fs != nil {
		t.Fatalf("%v %v", fs, err)
	}
}

func TestBaselineIsReadFromPreviousWindow(t *testing.T) {
	var got core.Window
	_, err := mustNew(t, baseCfg()).Detect(context.Background(), fakeReader{evs: evs(created(30))}, fakeReader{gotWin: &got}, win)
	if err != nil {
		t.Fatal(err)
	}
	if got != win.Previous() {
		t.Errorf("prev read %v, want %v", got, win.Previous())
	}
}

func TestDisposableOnlyWithConfiguredList(t *testing.T) {
	var cur []core.Event
	for i := 0; i < 2; i++ {
		cur = append(cur, evs(createdBy(fmt.Sprintf("u%d@mail.disposable.example", i)))...)
	}
	cur = append(cur, evs(createdBy("real@corp.example"), createdBy("x@sub.other.example"))...)
	// No list: no disposable finding, whatever the addresses look like.
	c := baseCfg()
	fs, err := detect(t, c, cur, evs(created(1)))
	if err != nil || len(fs) != 0 {
		t.Fatalf("no list, no finding: %v %v", fs, err)
	}
	c.AddressField = "email"
	c.DisposableDomains = []string{"Disposable.example", "@other.example"}
	fs, err = detect(t, c, cur, evs(created(1)))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("want one finding per matched list entry, got %+v", fs)
	}
	f := byTag(fs, "signup:disposable:disposable.example")
	if f == nil || f.Severity != core.SevCheck || f.Detail["domain_cur"] != 2 || f.Detail["domain_prev"] != 0 {
		t.Fatalf("%+v", f)
	}
	if byTag(fs, "signup:disposable:other.example") == nil {
		t.Errorf("subdomain of a listed domain must match: %+v", fs)
	}
	for _, f := range fs {
		for k, v := range f.Detail {
			if s, ok := v.(string); ok && strings.Contains(s, "@") {
				t.Errorf("detail %s leaks an address: %q", k, s)
			}
		}
		if strings.Contains(f.Summary, "@") {
			t.Errorf("summary leaks an address: %q", f.Summary)
		}
	}
}

func TestDisposableMatchIsDomainNotSubstring(t *testing.T) {
	c := baseCfg()
	c.AddressField = "email"
	c.DisposableDomains = []string{"mail.example"}
	cur := evs(createdBy("a@notmail.example"), createdBy("b@mail.example.org"), createdBy("mail.example"))
	fs, err := detect(t, c, cur, evs(created(1)))
	if err != nil || len(fs) != 0 {
		t.Fatalf("substring of a domain matched: %v %v", fs, err)
	}
}

func TestDisposableNotCountedFromRejectedAttempts(t *testing.T) {
	c := baseCfg()
	c.AddressField = "email"
	c.DisposableDomains = []string{"mail.example"}
	cur := evs(req{path: createPath, method: "POST", status: 400, address: "a@mail.example", n: 5}, created(1))
	fs, err := detect(t, c, cur, evs(created(1)))
	if err != nil || len(fs) != 0 {
		t.Fatalf("%v %v", fs, err)
	}
}

func TestDisposableLoweredWhenBaselineEmpty(t *testing.T) {
	c := baseCfg()
	c.AddressField = "email"
	c.DisposableDomains = []string{"mail.example"}
	fs, err := detect(t, c, evs(createdBy("a@mail.example")), nil)
	if err != nil || len(fs) != 1 {
		t.Fatalf("%v %v", fs, err)
	}
	if fs[0].Severity != core.SevInfo || fs[0].Detail["baseline_empty"] != true {
		t.Errorf("%+v", fs[0])
	}
}

func TestNewValidation(t *testing.T) {
	bad := map[string]func(*Config){
		"no create path":    func(c *Config) { c.CreatePaths = nil },
		"blank create path": func(c *Config) { c.CreatePaths = []string{" "} },
		"relative path":     func(c *Config) { c.CreatePaths = []string{"account/create"} },
		"no path field":     func(c *Config) { c.PathField = "" },
		"no status field":   func(c *Config) { c.StatusField = "" },
		"methods no field":  func(c *Config) { c.MethodField = "" },
		"bad status":        func(c *Config) { c.SuccessStatuses = []int{99} },
		"negative min":      func(c *Config) { c.MinCreations = -1 },
		"factor at 1":       func(c *Config) { c.Factor = 1 },
		"factor negative":   func(c *Config) { c.Factor = -2 },
		"list no field":     func(c *Config) { c.DisposableDomains = []string{"a.example"} },
		"field no list":     func(c *Config) { c.AddressField = "email" },
		"domain is address": func(c *Config) { c.AddressField = "email"; c.DisposableDomains = []string{"x@a.example"} },
		"blank domain":      func(c *Config) { c.AddressField = "email"; c.DisposableDomains = []string{" "} },
		"bad name":          func(c *Config) { c.Name = "Has Space" },
	}
	for name, mut := range bad {
		c := baseCfg()
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if d := mustNew(t, baseCfg()); d.Name() != "signup" {
		t.Errorf("default name %q", d.Name())
	}
	c := baseCfg()
	c.Name = "reg-burst"
	if mustNew(t, c).Name() != "reg-burst" {
		t.Error("name not applied")
	}
}

func TestNewCopiesCallerSlices(t *testing.T) {
	c := baseCfg()
	d := mustNew(t, c)
	c.CreatePaths[0] = "/elsewhere"
	fs, err := d.Detect(context.Background(), fakeReader{evs: evs(created(30))}, fakeReader{evs: evs(created(1))}, win)
	if err != nil || len(fs) != 1 {
		t.Fatalf("detector must own its config: %v %v", fs, err)
	}
}
