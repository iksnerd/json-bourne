package contract

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/jb"
)

func noPrefix(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil && strings.HasPrefix(err.Error(), "jb: ") {
		t.Errorf("%s: a library error carries no \"jb: \" prefix, got %q", what, err)
	}
}

func TestUsageErrorValueContract(t *testing.T) {
	cause := io.ErrUnexpectedEOF
	ue := &jb.UsageError{Msg: "bad request", Cause: cause}
	if ue.Error() != "bad request" || !errors.Is(ue, cause) {
		t.Errorf("Error() = %q, Is(cause) = %v", ue.Error(), errors.Is(ue, cause))
	}
	wrapped := errors.Join(errors.New("context"), ue)
	if !jb.IsUsage(wrapped) || !jb.IsUsage(ue) {
		t.Error("IsUsage must see a UsageError, wrapped or not")
	}
	var got *jb.UsageError
	if !errors.As(wrapped, &got) || got.Msg != "bad request" || got.Cause != cause {
		t.Errorf("errors.As gave %+v", got)
	}
	if jb.IsUsage(nil) || jb.IsUsage(io.EOF) {
		t.Error("IsUsage is true for a non-usage error")
	}
	// UsageWrap (internal) keeps the cause reachable; that is the shape a caller sees.
}

func TestCallerMistakesAreUsageErrors(t *testing.T) {
	k := newKibana(t, searchDocs())
	dir := exampleCase(t, k)
	ctx := t.Context()
	neg := -time.Hour
	future := now.Add(time.Hour)

	_, nilCfg := jb.Hunt(ctx, nil, jb.HuntOptions{})
	_, negWindow := jb.HuntCase(ctx, dir, jb.CaseHuntOptions{Config: fpConfig, HuntOptions: jb.HuntOptions{Window: neg, Env: env}})
	_, futureUntil := jb.HuntCase(ctx, dir, jb.CaseHuntOptions{Config: fpConfig, HuntOptions: jb.HuntOptions{Window: time.Hour, Until: future, Env: env, Now: fixedNow}})
	_, fractional := jb.HuntCase(ctx, dir, jb.CaseHuntOptions{Config: fpConfig, HuntOptions: jb.HuntOptions{Window: time.Hour, Until: now.Add(-time.Hour).Add(time.Nanosecond), Env: env, Now: fixedNow}})
	_, tooLong := jb.HuntCase(ctx, dir, jb.CaseHuntOptions{Config: fpConfig, HuntOptions: jb.HuntOptions{Window: jb.MaxHistoricalWindow + time.Second, Until: now.Add(-time.Hour), Env: env, Now: fixedNow}})
	_, blankTerm := jb.HuntCase(ctx, dir, jb.CaseHuntOptions{Config: fpConfig, HuntOptions: jb.HuntOptions{Search: []string{" "}, Env: env, Now: fixedNow}})
	_, fiveTerms := jb.HuntCase(ctx, dir, jb.CaseHuntOptions{Config: fpConfig, HuntOptions: jb.HuntOptions{Search: []string{"a", "b", "c", "d", "e"}, Env: env, Now: fixedNow}})
	_, unknownCfg := jb.CaseShow(dir, jb.CaseShowOptions{Config: "config/nope.yaml"})
	_, outsideCfg := jb.HuntCase(ctx, dir, jb.CaseHuntOptions{Config: "../outside.yaml", HuntOptions: jb.HuntOptions{Env: env}})
	_, emptyDir := jb.CaseCheck("")
	_, badWatch := jb.Watch(ctx, dir, jb.WatchOptions{Once: true, Name: "Bad Name", Env: env})
	_, shortWindow := jb.Watch(ctx, dir, jb.WatchOptions{Once: true, Every: time.Hour, Window: time.Minute, Env: env})
	_, pruneNothing := jb.DBPrune(ctx, dir, jb.DBPruneOptions{})
	_, renameSame := jb.DBRenameSource(ctx, dir, jb.DBRenameSourceOptions{Old: "a", New: "a"})
	_, badOp := jb.Call(ctx, "no_such_operation", nil, env)
	_, badArg := jb.Call(ctx, "case_show", map[string]any{"case": dir, "surprise": 1}, env)
	_, _, dashErr := jb.DashboardHandler(jb.DashboardOptions{})

	for name, err := range map[string]error{
		"Hunt(nil config)": nilCfg, "negative window": negWindow, "Until in the future": futureUntil,
		"Until with a fraction": fractional, "Until with a window over the maximum": tooLong,
		"blank search term": blankTerm, "five search terms": fiveTerms, "unknown config": unknownCfg,
		"config outside the case": outsideCfg, "CaseCheck(\"\")": emptyDir, "bad watcher name": badWatch,
		"window shorter than the interval": shortWindow, "prune with no selection": pruneNothing,
		"rename to the same label": renameSame, "unknown operation": badOp, "unknown argument": badArg,
		"DashboardHandler with no case or config": dashErr,
	} {
		if !jb.IsUsage(err) {
			t.Errorf("%s: want a usage error, got %v", name, err)
		}
		noPrefix(t, name, err)
	}
}

// A missing case, an unreachable source and an unset credential are not usage errors.
func TestWhatIsNotAUsageError(t *testing.T) {
	_, err := jb.HuntCase(t.Context(), filepath.Join(t.TempDir(), "none"), jb.CaseHuntOptions{})
	if err == nil || jb.IsUsage(err) {
		t.Errorf("a missing case: want an error that is not a usage error, got %v", err)
	}
	noPrefix(t, "missing case", err)

	k := newKibana(t, nil)
	dir := exampleCase(t, k)
	unset := func(string) (string, bool) { return "", false }
	_, err = jb.HuntCase(t.Context(), dir, jb.CaseHuntOptions{Config: fpConfig, HuntOptions: jb.HuntOptions{Env: unset, Now: fixedNow}})
	if err == nil || jb.IsUsage(err) {
		t.Errorf("an unset credential: want an error that is not a usage error, got %v", err)
	}
	noPrefix(t, "unset credential", err)
}

func TestARefusedSearchSendsNothing(t *testing.T) {
	k := newKibana(t, searchDocs())
	dir := exampleCase(t, k)
	_, err := jb.HuntCase(t.Context(), dir, jb.CaseHuntOptions{Config: fpConfig, HuntOptions: jb.HuntOptions{Search: []string{" "}, Env: env, Now: fixedNow}})
	if !jb.IsUsage(err) {
		t.Fatal(err)
	}
	if n := k.requests(); n != 0 {
		t.Errorf("a refused search reached the network %d times", n)
	}
}

func TestSentinelErrors(t *testing.T) {
	// ErrNoSuchSource: nothing is stored under the label.
	dir, _ := pinned(t)
	res, err := jb.DBRenameSource(t.Context(), dir, jb.DBRenameSourceOptions{Old: "no-such-label", New: "other-label"})
	if !errors.Is(err, jb.ErrNoSuchSource) {
		t.Fatalf("want ErrNoSuchSource, got %v", err)
	}
	if res == nil || res.Applied {
		t.Errorf("the result is returned, not applied: %+v", res)
	}
	noPrefix(t, "ErrNoSuchSource", err)
	if jb.IsUsage(err) {
		t.Error("ErrNoSuchSource is not a usage error")
	}

	// ErrSourceOverlap: the same documents under two labels, then a rename onto the other.
	k := newKibana(t, searchDocs())
	dir = exampleCase(t, k)
	cfg := filepath.Join(dir, fpConfig)
	editFile(t, cfg, "- type: kibana", "- type: kibana\n    name: old-label")
	first := func() time.Time { return now.Add(-time.Minute) }
	o := huntOpts()
	o.Now = first
	if _, err := jb.HuntCase(t.Context(), dir, o); err != nil {
		t.Fatal(err)
	}
	editFile(t, cfg, "old-label", "new-label")
	if _, err := jb.HuntCase(t.Context(), dir, huntOpts()); err != nil {
		t.Fatal(err)
	}
	res, err = jb.DBRenameSource(t.Context(), dir, jb.DBRenameSourceOptions{Old: "old-label", New: "new-label", Apply: true})
	if !errors.Is(err, jb.ErrSourceOverlap) {
		t.Fatalf("want ErrSourceOverlap, got %v", err)
	}
	if res == nil || res.Applied || res.Overlap == 0 {
		t.Errorf("an overlap is refused with the counts: %+v", res)
	}
	noPrefix(t, "ErrSourceOverlap", err)
}

// A source that reads nothing is never an empty success: it is no_records, and the
// error it carries is ErrNoRecords.
func TestASourceThatReadsNothingIsNoRecords(t *testing.T) {
	k := newKibana(t, nil)
	dir := exampleCase(t, k)
	res, err := jb.HuntCase(t.Context(), dir, huntOpts())
	if res == nil {
		t.Fatalf("no result, err = %v", err)
	}
	if res.Complete() {
		t.Fatal("a hunt that read nothing is not complete")
	}
	if len(res.Sources) != 1 || res.Sources[0].Status != jb.StatusNoRecords || !errors.Is(res.Sources[0].Err, jb.ErrNoRecords) {
		t.Errorf("source = %+v, want status %s and ErrNoRecords", res.Sources, jb.StatusNoRecords)
	}
	if len(res.Failed()) == 0 {
		t.Error("Failed() must name the source")
	}
}
