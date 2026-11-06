package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

type stubFeed struct {
	name string
	fn   func(ind []string) ([]core.Reputation, error)
	got  [][]string
}

func (f *stubFeed) Name() string { return f.name }
func (f *stubFeed) Lookup(_ context.Context, ind []string) ([]core.Reputation, error) {
	f.got = append(f.got, ind)
	return f.fn(ind)
}

type memRep struct {
	rows []core.Reputation
	err  error
}

func (m *memRep) AppendReputation(_ context.Context, rs []core.Reputation) error {
	if m.err != nil {
		return m.err
	}
	m.rows = append(m.rows, rs...)
	return nil
}

type memInd struct {
	run string
	ind []string
	err error
}

func (m memInd) LatestRunIndicators(context.Context, []string, int) (string, []string, error) {
	return m.run, m.ind, m.err
}

var obsAt = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func answer(ind []string) ([]core.Reputation, error) {
	var out []core.Reputation
	for _, i := range ind {
		out = append(out, core.Reputation{Indicator: i, Verdict: "classification=benign", Observed: obsAt, Source: "stub"})
	}
	return out, nil
}

func TestIntelFromArgsStoresEverySnapshot(t *testing.T) {
	feed := &stubFeed{name: "stub", fn: answer}
	store := &memRep{}
	res, err := Intel(context.Background(), IntelDeps{Feeds: []core.Feed{feed}, Store: store}, IntelRequest{
		Indicators: []string{"192.0.2.1", "198.51.100.2", "192.0.2.1"}, MaxIndicators: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete() || len(res.Failures) != 0 || len(store.rows) != 2 || len(res.Rows) != 2 {
		t.Fatalf("%+v rows=%v", res, store.rows)
	}
	if len(feed.got) != 1 || len(feed.got[0]) != 2 {
		t.Fatalf("duplicates must be collapsed before asking: %v", feed.got)
	}
}

func TestIntelPartialFailureStoresAnswersAndIsIncomplete(t *testing.T) {
	feed := &stubFeed{name: "stub", fn: func(ind []string) ([]core.Reputation, error) {
		return []core.Reputation{{Indicator: ind[0], Verdict: core.VerdictNotFound, Observed: obsAt, Source: "stub"}},
			&core.LookupError{Indicator: ind[1], Err: core.ErrRateLimited}
	}}
	store := &memRep{}
	res, err := Intel(context.Background(), IntelDeps{Feeds: []core.Feed{feed}, Store: store}, IntelRequest{
		Indicators: []string{"192.0.2.1", "192.0.2.2"}, MaxIndicators: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() || len(res.Failures) != 1 || res.Failures[0].Indicator != "192.0.2.2" || !errors.Is(res.Failures[0].Err, core.ErrRateLimited) {
		t.Fatalf("%+v", res)
	}
	if len(store.rows) != 1 || store.rows[0].Verdict != core.VerdictNotFound {
		t.Fatalf("the answer that was obtained must be kept: %v", store.rows)
	}
	for _, r := range store.rows {
		if r.Indicator == "192.0.2.2" {
			t.Fatal("a failed lookup must never be stored")
		}
	}
}

func TestIntelWholeFeedErrorFailsEveryIndicator(t *testing.T) {
	feed := &stubFeed{name: "stub", fn: func([]string) ([]core.Reputation, error) { return nil, errors.New("connection refused") }}
	store := &memRep{}
	res, err := Intel(context.Background(), IntelDeps{Feeds: []core.Feed{feed}, Store: store}, IntelRequest{
		Indicators: []string{"192.0.2.1", "192.0.2.2"}, MaxIndicators: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() || len(res.Failures) != 2 || len(store.rows) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestIntelSilentFeedIsAFailureNotAnEmptyAnswer(t *testing.T) {
	// A feed that returns neither an answer nor an error for an indicator is broken.
	feed := &stubFeed{name: "stub", fn: func(ind []string) ([]core.Reputation, error) { return answer(ind[:1]) }}
	res, err := Intel(context.Background(), IntelDeps{Feeds: []core.Feed{feed}, Store: &memRep{}}, IntelRequest{
		Indicators: []string{"192.0.2.1", "192.0.2.2"}, MaxIndicators: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() || len(res.Failures) != 1 || res.Failures[0].Indicator != "192.0.2.2" {
		t.Fatalf("%+v", res)
	}
}

func TestIntelCapsIndicatorsAndReportsTheRest(t *testing.T) {
	feed := &stubFeed{name: "stub", fn: answer}
	res, err := Intel(context.Background(), IntelDeps{Feeds: []core.Feed{feed}, Store: &memRep{}}, IntelRequest{
		Indicators: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, MaxIndicators: 2})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() || len(res.Failures) != 1 || res.Failures[0].Indicator != "192.0.2.3" || !errors.Is(res.Failures[0].Err, core.ErrBudgetExceeded) {
		t.Fatalf("%+v", res)
	}
	if len(feed.got[0]) != 2 {
		t.Fatalf("asked %v", feed.got)
	}
}

func TestIntelTakesIndicatorsFromTheLatestRunWhenNoneGiven(t *testing.T) {
	feed := &stubFeed{name: "stub", fn: answer}
	res, err := Intel(context.Background(), IntelDeps{
		Feeds: []core.Feed{feed}, Store: &memRep{},
		Indicators: memInd{run: "hunt-9", ind: []string{"192.0.2.9", "not-an-ip", "2001:db8::1"}},
	}, IntelRequest{Fields: []string{"client_ip"}, MaxIndicators: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.Run != "hunt-9" || len(res.Rows) != 2 {
		t.Fatalf("%+v", res)
	}
	if res.Skipped != 1 {
		t.Fatalf("a non-IP value from the run is counted as skipped, not dropped silently: %+v", res)
	}
}

func TestIntelNothingToLookUpIsAnError(t *testing.T) {
	feed := &stubFeed{name: "stub", fn: answer}
	_, err := Intel(context.Background(), IntelDeps{Feeds: []core.Feed{feed}, Store: &memRep{},
		Indicators: memInd{run: "hunt-9", ind: []string{"not-an-ip", "example.com"}}}, IntelRequest{Fields: []string{"x"}, MaxIndicators: 10})
	if err == nil || len(feed.got) != 0 {
		t.Fatalf("err=%v asked=%v", err, feed.got)
	}
	_, err = Intel(context.Background(), IntelDeps{Feeds: []core.Feed{feed}, Store: &memRep{}}, IntelRequest{MaxIndicators: 10})
	if err == nil {
		t.Fatal("no args and no indicator reader must be an error")
	}
	_, err = Intel(context.Background(), IntelDeps{Store: &memRep{}}, IntelRequest{Indicators: []string{"192.0.2.1"}, MaxIndicators: 10})
	if err == nil {
		t.Fatal("no feed must be an error")
	}
}

func TestIntelRejectsBadArgIndicators(t *testing.T) {
	feed := &stubFeed{name: "stub", fn: answer}
	_, err := Intel(context.Background(), IntelDeps{Feeds: []core.Feed{feed}, Store: &memRep{}}, IntelRequest{
		Indicators: []string{"192.0.2.1", "example.com"}, MaxIndicators: 10})
	if err == nil || !strings.Contains(err.Error(), "example.com") || len(feed.got) != 0 {
		t.Fatalf("err=%v asked=%v", err, feed.got)
	}
}

func TestIntelStoreFailureIsAnError(t *testing.T) {
	feed := &stubFeed{name: "stub", fn: answer}
	_, err := Intel(context.Background(), IntelDeps{Feeds: []core.Feed{feed}, Store: &memRep{err: fmt.Errorf("disk full")}}, IntelRequest{
		Indicators: []string{"192.0.2.1"}, MaxIndicators: 10})
	if err == nil {
		t.Fatal("answers that could not be stored must not look like success")
	}
}

func named(name string) func(ind []string) ([]core.Reputation, error) {
	return func(ind []string) ([]core.Reputation, error) {
		var out []core.Reputation
		for _, i := range ind {
			out = append(out, core.Reputation{Indicator: i, Verdict: "v-" + name, Observed: obsAt, Source: name})
		}
		return out, nil
	}
}

// Each indicator x feed is its own answer. One feed failing makes the run incomplete and
// keeps the other feed's answers, and the stored source says which feed spoke.
func TestIntelManyFeedsKeepTheirOwnAnswersAndFailures(t *testing.T) {
	good := &stubFeed{name: "feed-a", fn: named("feed-a")}
	bad := &stubFeed{name: "feed-b", fn: func(ind []string) ([]core.Reputation, error) {
		return nil, &core.LookupError{Indicator: ind[0], Err: fmt.Errorf("%w: HTTP 500", core.ErrFeedFailed)}
	}}
	third := &stubFeed{name: "feed-c", fn: func(ind []string) ([]core.Reputation, error) {
		return []core.Reputation{{Indicator: ind[0], Verdict: core.VerdictNotFound, Observed: obsAt, Source: "feed-c"}},
			&core.LookupError{Indicator: ind[1], Err: core.ErrRateLimited}
	}}
	store := &memRep{}
	res, err := Intel(context.Background(), IntelDeps{Feeds: []core.Feed{good, bad, third}, Store: store},
		IntelRequest{Indicators: []string{"192.0.2.1", "192.0.2.2"}, MaxIndicators: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() {
		t.Fatal("a failing feed must make the run incomplete")
	}
	bySrc := map[string]int{}
	for _, r := range store.rows {
		bySrc[r.Source]++
	}
	if bySrc["feed-a"] != 2 || bySrc["feed-b"] != 0 || bySrc["feed-c"] != 1 || len(store.rows) != 3 {
		t.Fatalf("stored rows by source: %v", bySrc)
	}
	failBy := map[string][]string{}
	for _, f := range res.Failures {
		failBy[f.Feed] = append(failBy[f.Feed], f.Indicator)
	}
	if len(failBy["feed-a"]) != 0 || len(failBy["feed-b"]) != 2 || len(failBy["feed-c"]) != 1 || failBy["feed-c"][0] != "192.0.2.2" {
		t.Fatalf("failures by feed: %v", failBy)
	}
	for _, f := range []*stubFeed{good, bad, third} {
		if len(f.got) != 1 || len(f.got[0]) != 2 {
			t.Fatalf("%s must be asked once about every indicator: %v", f.name, f.got)
		}
	}
}

// A row whose source is not the feed that returned it would corrupt the source column.
func TestIntelRefusesARowThatNamesAnotherFeed(t *testing.T) {
	liar := &stubFeed{name: "feed-a", fn: func(ind []string) ([]core.Reputation, error) {
		return []core.Reputation{{Indicator: ind[0], Verdict: "x", Observed: obsAt, Source: "feed-b"}}, nil
	}}
	store := &memRep{}
	res, err := Intel(context.Background(), IntelDeps{Feeds: []core.Feed{liar}, Store: store},
		IntelRequest{Indicators: []string{"192.0.2.1"}, MaxIndicators: 10})
	if err != nil || len(store.rows) != 0 || res.Complete() || len(res.Failures) != 1 {
		t.Fatalf("rows=%v res=%+v err=%v", store.rows, res, err)
	}
	if !strings.Contains(res.Failures[0].Err.Error(), "feed-b") {
		t.Fatalf("the failure should say which source it claimed: %v", res.Failures[0].Err)
	}
}

func TestIntelRefusesTwoFeedsWithTheSameName(t *testing.T) {
	a := &stubFeed{name: "same", fn: named("same")}
	b := &stubFeed{name: "same", fn: named("same")}
	_, err := Intel(context.Background(), IntelDeps{Feeds: []core.Feed{a, b}, Store: &memRep{}},
		IntelRequest{Indicators: []string{"192.0.2.1"}, MaxIndicators: 10})
	if err == nil || !strings.Contains(err.Error(), "same") || len(a.got) != 0 {
		t.Fatalf("err=%v asked=%v", err, a.got)
	}
}
