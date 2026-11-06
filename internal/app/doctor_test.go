package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fakeCfgs map[string]DoctorConfig

func (f fakeCfgs) Load(ref string) (DoctorConfig, error) {
	c, ok := f[ref]
	if !ok {
		return DoctorConfig{}, errors.New("line 3: unknown key \"typo\"")
	}
	return c, nil
}

type fakeCases struct {
	c   DoctorCase
	err error
}

func (f fakeCases) Inspect(string, string) (DoctorCase, error) { return f.c, f.err }

type fakeEnv map[string]bool

func (f fakeEnv) IsSet(n string) bool { return f[n] }

type fakeStores map[string]DoctorStore

func (f fakeStores) Probe(_ context.Context, p string) DoctorStore { s := f[p]; s.Path = p; return s }

type fakeReach struct {
	targets map[string]string // service name -> target
	down    map[string]bool
	probed  []string
}

func (f *fakeReach) Target(s DoctorService) (string, string) {
	if t := f.targets[s.Name]; t != "" {
		return t, ""
	}
	return "", "the URL variable is unset"
}
func (f *fakeReach) Probe(_ context.Context, t string) error {
	f.probed = append(f.probed, t)
	if f.down[t] {
		return errors.New("connection refused")
	}
	return nil
}

var goodStore = DoctorStore{Exists: true, Schema: 3, BuildSchema: 3}

func baseDeps() DoctorDeps {
	return DoctorDeps{
		Build: DoctorBuild{Version: "dev", Go: "go1.25", DuckDBDriver: "v2.0", DuckDBEngine: "v1.4"},
		Configs: fakeCfgs{"hunt.yaml": {StorePath: "/ev/jb.duckdb", Services: []DoctorService{
			{Kind: "source", Type: "kibana", Name: "kibana:logs", Enabled: true, EnvVars: []string{"JB_KIBANA_API_KEY"}, Host: "kibana.example.com:443", Leaves: "the query"},
			{Kind: "feed", Type: "dnsbl", Name: "dnsbl:bl.example.test", Enabled: false, Resolver: true, Leaves: "each IP"},
			{Kind: "feed", Type: "greynoise", Name: "greynoise:community", Enabled: true, EnvVars: []string{"JB_GREYNOISE_API_KEY"}, Host: "api.greynoise.io:443", Leaves: "each IP"},
			{Kind: "alert", Type: "webhook", Name: "webhook", Enabled: true, EnvVars: []string{"JB_WEBHOOK_URL"}, Leaves: "a summary"},
		}}},
		Env:    fakeEnv{"JB_KIBANA_API_KEY": true, "JB_GREYNOISE_API_KEY": true, "JB_WEBHOOK_URL": true},
		Stores: fakeStores{"/ev/jb.duckdb": goodStore},
	}
}

func find(r DoctorReport, group, contains string) []Check {
	var out []Check
	for _, c := range r.Checks {
		if c.Group == group && strings.Contains(c.Name, contains) {
			out = append(out, c)
		}
	}
	return out
}

func one(t *testing.T, r DoctorReport, group, contains string) Check {
	t.Helper()
	cs := find(r, group, contains)
	if len(cs) != 1 {
		t.Fatalf("want exactly one %s check containing %q, got %+v\nall: %+v", group, contains, cs, r.Checks)
	}
	return cs[0]
}

func TestDoctorPassesOnlyWhenEveryRequiredCheckPasses(t *testing.T) {
	r := Doctor(context.Background(), baseDeps(), DoctorRequest{ConfigPath: "hunt.yaml"})
	if !r.OK() || r.Failed() != 0 {
		t.Fatalf("%+v", r.Checks)
	}
	if c := one(t, r, "env", "KIBANA"); c.Status != CheckOK || c.Detail != "set" {
		t.Errorf("%+v", c)
	}
	// What is not configured or not asked is skipped, never ok.
	if c := one(t, r, "case", "case"); c.Status != CheckSkipped {
		t.Errorf("no case must be skipped: %+v", c)
	}
	if c := one(t, r, "online", "reachability"); c.Status != CheckSkipped {
		t.Errorf("no --online must be skipped: %+v", c)
	}
	if len(r.Services) != 4 {
		t.Fatalf("services %+v", r.Services)
	}
	for _, s := range r.Services {
		if s.Leaves == "" || (s.State != "enabled" && s.State != "disabled") {
			t.Errorf("service %+v", s)
		}
	}
}

func TestDoctorUnsetVariableFailsAndNeverHasAValue(t *testing.T) {
	d := baseDeps()
	d.Env = fakeEnv{"JB_KIBANA_API_KEY": true}
	r := Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
	if r.OK() {
		t.Fatal("an unset variable named by an enabled service must fail the run")
	}
	for _, v := range []string{"JB_GREYNOISE_API_KEY", "JB_WEBHOOK_URL"} {
		if c := one(t, r, "env", v); c.Status != CheckFail || !strings.Contains(c.Detail, "unset") {
			t.Errorf("%s: %+v", v, c)
		}
	}
}

func TestDoctorDisabledServiceNeedsNothing(t *testing.T) {
	d := baseDeps()
	d.Configs = fakeCfgs{"hunt.yaml": {StorePath: "/ev/jb.duckdb", Services: []DoctorService{
		{Kind: "feed", Type: "x", Name: "off", Enabled: false, EnvVars: []string{"JB_UNSET"}, Leaves: "x"}}}}
	d.Env = fakeEnv{}
	r := Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
	if c := one(t, r, "env", "JB_UNSET"); c.Status != CheckSkipped || !r.OK() {
		t.Fatalf("%+v ok=%v", c, r.OK())
	}
}

func TestDoctorConfigThatDoesNotLoadFailsAndTheRestStillRuns(t *testing.T) {
	r := Doctor(context.Background(), baseDeps(), DoctorRequest{ConfigPath: "typo.yaml"})
	if r.OK() {
		t.Fatal("a config that does not load must fail")
	}
	if c := one(t, r, "config", "typo.yaml"); c.Status != CheckFail || !strings.Contains(c.Detail, "unknown key") {
		t.Errorf("%+v", c)
	}
	if len(find(r, "build", "")) == 0 {
		t.Error("build facts are reported even when the config is bad")
	}
}

func TestDoctorStoreStates(t *testing.T) {
	cases := []struct {
		name  string
		store DoctorStore
		want  CheckStatus // of the worst store line
		ok    bool
	}{
		{"fine", goodStore, CheckOK, true},
		{"absent", DoctorStore{}, CheckSkipped, true},
		{"not writable", DoctorStore{Exists: true, WriteErr: "permission denied"}, CheckFail, false},
		{"wrong owner", DoctorStore{Exists: true, OwnerMismatch: "owned by uid 0, you are uid 501"}, CheckFail, false},
		{"loose mode", DoctorStore{Exists: true, LooseMode: "0666", Schema: 3, BuildSchema: 3}, CheckWarn, true},
		{"schema behind", DoctorStore{Exists: true, OpenErr: "x", OpenKind: "behind", Schema: 1, BuildSchema: 3}, CheckWarn, true},
		{"schema ahead", DoctorStore{Exists: true, OpenErr: "x", OpenKind: "ahead", Schema: 9, BuildSchema: 3}, CheckFail, false},
		{"does not open", DoctorStore{Exists: true, OpenErr: "could not set lock", OpenKind: "other"}, CheckFail, false},
	}
	for _, tc := range cases {
		d := baseDeps()
		d.Stores = fakeStores{"/ev/jb.duckdb": tc.store}
		r := Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
		worst := CheckOK
		rank := map[CheckStatus]int{CheckOK: 0, CheckSkipped: 1, CheckWarn: 2, CheckFail: 3}
		for _, c := range find(r, "store", "") {
			if rank[c.Status] > rank[worst] {
				worst = c.Status
			}
		}
		if worst != tc.want || r.OK() != tc.ok {
			t.Errorf("%s: worst %s ok=%v, want %s ok=%v\n%+v", tc.name, worst, r.OK(), tc.want, tc.ok, find(r, "store", ""))
		}
	}
	// An absent file is skipped, not "ok".
	d := baseDeps()
	d.Stores = fakeStores{"/ev/jb.duckdb": {}}
	r := Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
	if c := one(t, r, "store", "(file)"); c.Status != CheckSkipped {
		t.Errorf("%+v", c)
	}
}

func TestDoctorCaseItemsAreCarriedAndAFailureFailsTheRun(t *testing.T) {
	d := baseDeps()
	d.Cases = fakeCases{c: DoctorCase{ID: "c1", ConfigRefs: []string{"hunt.yaml"}, Items: []CaseItem{
		{Name: "case.yaml", Status: CheckOK, Detail: "c1"},
		{Name: "evidence guard", Status: CheckFail, Detail: "evidence/ is not ignored by git"},
		{Name: "actors", Status: CheckSkipped, Detail: "none found"},
	}}}
	r := Doctor(context.Background(), d, DoctorRequest{CaseDir: "/case"})
	if r.OK() {
		t.Fatal("the evidence guard failing must fail the run")
	}
	if c := one(t, r, "case", "guard"); c.Status != CheckFail {
		t.Errorf("%+v", c)
	}
	if len(find(r, "config", "hunt.yaml")) != 1 {
		t.Error("the case's configs are loaded")
	}
	d.Cases = fakeCases{err: errors.New("case.yaml: missing id")}
	if r := Doctor(context.Background(), d, DoctorRequest{CaseDir: "/case"}); r.OK() {
		t.Fatal("a case that does not load must fail")
	}
}

func TestDoctorOnlineDoesOneProbePerHostAndOnlyWhenAsked(t *testing.T) {
	d := baseDeps()
	reach := &fakeReach{targets: map[string]string{
		"kibana:logs": "kibana.example.com:443", "greynoise:community": "kibana.example.com:443", // same host: one probe
		"webhook": "hooks.example.com:443"}, down: map[string]bool{}}
	r := Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
	if len(reach.probed) != 0 {
		t.Fatal("no --online, no probe")
	}
	d.Reach = reach
	r = Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
	if len(reach.probed) != 2 || !r.OK() {
		t.Fatalf("probed %v ok=%v\n%+v", reach.probed, r.OK(), find(r, "online", ""))
	}
	if c := one(t, r, "online", "kibana.example.com"); !strings.Contains(c.Detail, "kibana:logs") || !strings.Contains(c.Detail, "greynoise") || c.Status != CheckOK {
		t.Errorf("%+v", c)
	}
	// The disabled DNSBL is never probed, and a resolver service is skipped, not probed.
	for _, p := range reach.probed {
		if strings.Contains(p, "bl.example") {
			t.Errorf("probed %s", p)
		}
	}
	reach.down["hooks.example.com:443"] = true
	r = Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
	if r.OK() {
		t.Fatal("an unreachable service host fails an --online run")
	}
}

func TestDoctorOnlineSkipsWhatItCannotResolveAndDoesNotCallItReachable(t *testing.T) {
	d := baseDeps()
	d.Reach = &fakeReach{targets: map[string]string{}, down: map[string]bool{}}
	r := Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
	c := one(t, r, "online", "webhook")
	if c.Status != CheckSkipped || !strings.Contains(c.Detail, "unset") {
		t.Fatalf("%+v", c)
	}
}

func TestDoctorReportNeverContainsWhatThePortsDoNotCarry(t *testing.T) {
	// The env port returns a bool; the fakes above hold no value at all. This asserts
	// the report text for the unusual-but-possible leak: a service description that
	// carries a sentinel in a place the report must not print (the env var list is names).
	d := baseDeps()
	r := Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
	text := fmt.Sprintf("%+v", r)
	for _, bad := range []string{"len=", "length", "chars"} {
		if strings.Contains(text, bad) {
			t.Errorf("report mentions %q: a length hint about a secret", bad)
		}
	}
}

type fakePlugins struct {
	src  string
	list []DoctorPlugin
	err  error
}

func (f fakePlugins) Plugins() (string, []DoctorPlugin, error) { return f.src, f.list, f.err }

func TestDoctorReportsPluginTrustAndFailsOnABadOne(t *testing.T) {
	d := baseDeps()
	d.Plugins = fakePlugins{src: "/home/u/.jb/plugins.yaml", list: []DoctorPlugin{
		{Name: "acme.good", Path: "/opt/p/good", Pin: "ok"},
		{Name: "acme.loose", Path: "/opt/p/loose", Pin: "none", Err: "file: mode 0666 is writable by group or others"},
		{Name: "acme.changed", Path: "/opt/p/changed", Pin: "MISMATCH", Err: "pinned sha256 does not match"},
	}}
	r := Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
	if got := find(r, "plugins", "acme.good"); len(got) != 1 || got[0].Status != CheckOK || !strings.Contains(got[0].Detail, "pin: ok") {
		t.Errorf("good plugin = %+v", got)
	}
	for _, n := range []string{"acme.loose", "acme.changed"} {
		if got := find(r, "plugins", n); len(got) != 1 || got[0].Status != CheckFail {
			t.Errorf("%s = %+v, want a failed check", n, got)
		}
	}
	if r.OK() {
		t.Error("a plugin that fails its trust checks must fail doctor")
	}
}

func TestDoctorPluginAllowlistStates(t *testing.T) {
	d := baseDeps()
	r := Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
	if got := find(r, "plugins", "plugins"); len(got) != 1 || got[0].Status != CheckSkipped {
		t.Errorf("no port = %+v, want skipped", got)
	}
	d.Plugins = fakePlugins{}
	if got := find(Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"}), "plugins", "allowlist"); len(got) != 1 || got[0].Status != CheckSkipped {
		t.Errorf("empty allowlist = %+v, want skipped (not a pass)", got)
	}
	d.Plugins = fakePlugins{err: errors.New("plugin allowlist /x: mode 0666 is writable by group or others")}
	rr := Doctor(context.Background(), d, DoctorRequest{ConfigPath: "hunt.yaml"})
	if got := find(rr, "plugins", "allowlist"); len(got) != 1 || got[0].Status != CheckFail || rr.OK() {
		t.Errorf("unreadable allowlist = %+v ok=%v, want fail", got, rr.OK())
	}
}
