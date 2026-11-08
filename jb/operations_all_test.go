package jb

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/crtsh"
	"github.com/iksnerd/json-bourne/internal/adapters/rdap"
	"github.com/iksnerd/json-bourne/internal/ops"
)

// The table of RFC 0010 "Operations": name, command words and whether it only reads.
var rfcOperations = []struct {
	name     string
	command  string
	readOnly bool
}{
	{"activity", "activity", true},
	{"actor_status", "actor status", true},
	{"case_check", "case check", true},
	{"case_show", "case show", true},
	{"db_compact", "db compact", false},
	{"db_prune", "db prune", false},
	{"db_rename_source", "db rename-source", false},
	{"db_reputation", "db reputation", true},
	{"db_status", "db status", true},
	{"db_usage", "db usage", true},
	{"doctor", "doctor", true},
	{"estate_asn", "estate asn", false},
	{"estate_ct", "estate ct", false},
	{"estate_diff", "estate diff", true},
	{"estate_dns", "estate dns", false},
	{"estate_facts_import", "estate facts import", false},
	{"estate_ip", "estate", false},
	{"estate_promote", "estate promote", false},
	{"estate_refresh", "estate refresh", false},
	{"hunt", "hunt", true},
	{"intel", "intel", false},
	{"watch_status", "watch status", true},
}

func TestRegistryIsTheRFCTable(t *testing.T) {
	list := Operations()
	if len(list) != len(rfcOperations) {
		t.Fatalf("%d operations, the RFC lists %d", len(list), len(rfcOperations))
	}
	if ps := ops.ValidateAll(list); len(ps) != 0 {
		t.Fatalf("the registry breaks the RFC rules: %s", ops.Describe(ps))
	}
	byName := map[string]Operation{}
	cmds := map[string]string{}
	for _, op := range list {
		byName[op.Name] = op
		c := strings.Join(op.CLI.Command, " ")
		if prev, dup := cmds[c]; dup {
			t.Errorf("command %q belongs to %s and %s", c, prev, op.Name)
		}
		cmds[c] = op.Name
		if !strings.Contains(op.Description, ".") || len(op.Description) < 40 {
			t.Errorf("%s: description %q", op.Name, op.Description)
		}
	}
	for _, want := range rfcOperations {
		op, ok := byName[want.name]
		if !ok {
			t.Errorf("no operation %s", want.name)
			continue
		}
		if got := strings.Join(op.CLI.Command, " "); got != want.command {
			t.Errorf("%s: command %q, want %q", want.name, got, want.command)
		}
		if op.ReadOnly != want.readOnly {
			t.Errorf("%s: readOnly = %v, want %v", want.name, op.ReadOnly, want.readOnly)
		}
	}
}

func TestEveryMutatingOperationWithAnApplyFunctionTakesApplyDefaultingToFalse(t *testing.T) {
	for _, name := range []string{"db_prune", "db_compact", "db_rename_source"} {
		p, ok := opNamed(t, name).InputSchema.Properties["apply"]
		if !ok || p.Type != "boolean" {
			t.Errorf("%s has no boolean apply: %+v", name, p)
		}
		if p.Default != nil && p.Default != false {
			t.Errorf("%s: apply defaults to %v", name, p.Default)
		}
	}
}

func opNamed(t *testing.T, name string) Operation {
	t.Helper()
	for _, op := range Operations() {
		if op.Name == name {
			return op
		}
	}
	t.Fatalf("no operation %q", name)
	return Operation{}
}

func TestHuntAndActivityStoreIsFixedToFalseInTheTool(t *testing.T) {
	for _, name := range []string{"hunt", "activity"} {
		op := opNamed(t, name)
		p, ok := op.InputSchema.Properties["store"]
		if !ok || p.Type != "boolean" || p.Default != true {
			t.Fatalf("%s: store = %+v, want a boolean defaulting to true (RFC 0009's --no-store, positively)", name, p)
		}
		if !op.ReadOnly {
			t.Errorf("%s must be read-only over MCP", name)
		}
		tool := ops.Tool(op)
		if _, ok := tool.InputSchema.Properties["store"]; ok {
			t.Errorf("%s: the tool still offers store", name)
		}
		if v, ok := tool.Fixed["store"]; !ok || v != false {
			t.Errorf("%s: the tool does not fix store=false: %v", name, tool.Fixed)
		}
	}
}

func TestToolCallsRunWithTheFixedValuesAndRefuseTheirProperty(t *testing.T) {
	r, args, err := toolCall("hunt", map[string]any{"config": "x.yaml"})
	if err != nil || r.op.Name != "hunt" {
		t.Fatal(err)
	}
	if args["store"] != false || args["config"] != "x.yaml" {
		t.Fatalf("arguments = %v", args)
	}
	_, _, err = toolCall("hunt", map[string]any{"config": "x.yaml", "store": true})
	if !IsUsage(err) || !strings.Contains(err.Error(), "argument-unknown store") {
		t.Fatalf("a tool call may not set a fixed property: %v", err)
	}
	if _, _, err = toolCall("estate_diff", map[string]any{"case": "c", "alert": true}); !IsUsage(err) || !strings.Contains(err.Error(), "argument-unknown alert") {
		t.Fatalf("a cli.only property is refused in a tool call: %v", err)
	}
	if _, err := CallTool(context.Background(), "nope", nil, nil); !IsUsage(err) {
		t.Fatalf("unknown tool: %v", err)
	}
}

// ---- the handlers call the typed function and return its result ----

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCallDBOperationsMatchTheTypedFunctions(t *testing.T) {
	cfg, _ := seedDB(t, dbHunts)
	ctx := context.Background()

	got, err := Call(ctx, "db_status", map[string]any{"config": cfg}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := DBStatus(ctx, "", DBOptions{Config: cfg})
	if jsonOf(t, got) != jsonOf(t, want) {
		t.Errorf("db_status:\n%s\n%s", jsonOf(t, got), jsonOf(t, want))
	}

	got, err = Call(ctx, "db_usage", map[string]any{"config": cfg}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantU, _ := DBUsage(ctx, "", DBOptions{Config: cfg})
	if jsonOf(t, got) != jsonOf(t, wantU) {
		t.Errorf("db_usage differs")
	}

	// prune without apply is a dry run: nothing changes.
	before, _ := DBStatus(ctx, "", DBOptions{Config: cfg})
	res, err := Call(ctx, "db_prune", map[string]any{"config": cfg, "kind": "hunt", "older_than": "1d", "keep_latest": 0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pr := res.(*DBPruneResult)
	if pr.Applied {
		t.Error("db_prune applied without apply=true")
	}
	after, _ := DBStatus(ctx, "", DBOptions{Config: cfg})
	if after.Events != before.Events {
		t.Errorf("a dry run changed the store: %d -> %d events", before.Events, after.Events)
	}
	if len(pr.Runs) == 0 {
		t.Error("the dry run planned nothing, though the seeded hunts are old")
	}

	// prune by run id, keep_latest absent: the library's nil, not a conflicting default.
	if _, err := Call(ctx, "db_prune", map[string]any{"config": cfg, "run": []any{"hunt-20261001T000000Z"}}, nil); err != nil {
		t.Errorf("run ids with keep_latest absent: %v", err)
	}
	if _, err := Call(ctx, "db_prune", map[string]any{"config": cfg, "run": []any{"hunt-20261001T000000Z"}, "keep_latest": 1}, nil); !IsUsage(err) {
		t.Errorf("run ids with keep_latest present must be refused: %v", err)
	}

	// rename dry run, compact dry run.
	rr, err := Call(ctx, "db_rename_source", map[string]any{"config": cfg, "old": "ingress", "new": "edge"}, nil)
	if err != nil || rr.(*DBRenameSourceResult).Applied {
		t.Errorf("rename: %+v, %v", rr, err)
	}
	if _, err := Call(ctx, "db_compact", map[string]any{"config": cfg, "to": filepath.Join(filepath.Dir(cfg), "c.duckdb")}, nil); err != nil {
		t.Errorf("compact dry run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(cfg), "c.duckdb")); err == nil {
		t.Error("compact without apply wrote the copy")
	}
}

func TestCallUsageErrorsFromTheHandlers(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"hunt", map[string]any{}, "case or config"},
		{"hunt", map[string]any{"config": "x.yaml", "window": "soon"}, "window"},
		{"hunt", map[string]any{"config": "x.yaml", "window": "0s"}, "window must be positive"},
		{"hunt", map[string]any{"config": "x.yaml", "until": "2026-10-01T00:00:00"}, "until"},
		{"db_status", map[string]any{}, "required"},
		{"db_prune", map[string]any{"config": "x.yaml", "kind": "hunt", "older_than": "yesterday"}, "older_than"},
		{"db_prune", map[string]any{"config": "x.yaml", "kind": "watch", "older_than": "1d"}, "watch"},
		{"db_reputation", map[string]any{"config": "x.yaml", "since": "last week"}, "since"},
		{"estate_ip", map[string]any{"case": "c", "ips": []any{"192.0.2.1"}, "timeout": "fast"}, "timeout"},
		{"estate_dns", map[string]any{"case": "c", "targets": []any{"example.com"}, "min_interval": "-"}, "min_interval"},
		{"estate_diff", map[string]any{"case": "c", "alert": true, "ttl": "0s"}, "ttl"},
		{"estate_promote", map[string]any{"case": "c", "snapshot": "latest"}, "snapshot"},
		{"intel", map[string]any{"config": "x.yaml", "ips": []any{"not-an-ip"}}, "not an IP"},
		{"intel", map[string]any{}, "required"},
	} {
		_, err := Call(ctx, c.name, c.args, nil)
		if !IsUsage(err) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %v: err = %v, want a usage error containing %q", c.name, c.args, err, c.want)
		}
	}
}

func TestCallActorAndWatchStatusAndDoctorOnACase(t *testing.T) {
	dir := copyCase(t)
	seedStore(t, dir, webEvent(actorT0.Add(5*time.Minute), actorUA, "/login"))
	ctx := context.Background()

	got, err := Call(ctx, "actor_status", map[string]any{"case": dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := ActorStatus(ctx, dir, ActorStatusOptions{})
	if jsonOf(t, got) != jsonOf(t, want) {
		t.Errorf("actor_status differs")
	}
	if _, err := Call(ctx, "watch_status", map[string]any{"case": dir}, nil); err != nil {
		t.Errorf("watch_status: %v", err)
	}
	if _, err := Call(ctx, "watch_status", map[string]any{"case": dir, "name": "no spaces allowed"}, nil); !IsUsage(err) {
		t.Errorf("a bad watcher name is a usage error: %v", err)
	}
	d, err := Call(ctx, "doctor", map[string]any{"case": dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d.(*DoctorResult); !ok {
		t.Errorf("doctor result is %T", d)
	}
}

func TestOperationPropertiesCarryTheDefaultsOfTheLibrary(t *testing.T) {
	// The defaults the schema documents are the library's constants.
	want := map[string]map[string]any{
		"estate_ip":      {"file": EstateDefaultFile, "max_ips": int64(EstateDefaultMax)},
		"estate_refresh": {"file": EstateDefaultFile, "max_targets": int64(EstateDefaultMax)},
		"estate_asn":     {"file": EstateDefaultFile, "max_targets": int64(EstateExternalDefaultMax)},
		"estate_dns":     {"file": EstateDefaultFile, "max_targets": int64(EstateExternalDefaultMax)},
		"estate_diff":    {"file": EstateDefaultFile},
		"estate_promote": {"file": EstateDefaultFile},
		"db_prune":       {"keep_latest": int64(DefaultPruneKeepLatest)},
		"estate_ct":      {"file": EstateDefaultFile, "max_targets": int64(EstateExternalDefaultMax), "max_names": int64(crtsh.DefaultMaxNames)},
	}
	for _, name := range []string{"estate_ip", "estate_refresh"} {
		if got := opNamed(t, name).InputSchema.Properties["rdap_url"].Default; got != rdap.DefaultBaseURL {
			t.Errorf("%s.rdap_url default = %v, want %v", name, got, rdap.DefaultBaseURL)
		}
	}
	// A maximum in the schema is the library's maximum.
	for name, props := range map[string]map[string]int64{
		"estate_ip":      {"max_ips": EstateMax},
		"estate_refresh": {"max_targets": EstateMax},
		"estate_asn":     {"max_targets": EstateExternalMax},
		"estate_ct":      {"max_names": EstateMaxNames},
		"db_reputation":  {"limit": MaxReputationRows},
	} {
		for prop, want := range props {
			if got := opNamed(t, name).InputSchema.Properties[prop].Maximum; got == nil || *got != want {
				t.Errorf("%s.%s maximum = %v, want %d", name, prop, got, want)
			}
		}
	}
	for name, props := range want {
		op := opNamed(t, name)
		for prop, v := range props {
			if got := op.InputSchema.Properties[prop].Default; got != v {
				t.Errorf("%s.%s default = %v (%T), want %v", name, prop, got, got, v)
			}
		}
	}
	if !slices.Contains(opNamed(t, "estate_diff").CLI.Only, "alert") {
		t.Error("estate_diff alert writes to the alert sinks and must be cli.only")
	}
}
