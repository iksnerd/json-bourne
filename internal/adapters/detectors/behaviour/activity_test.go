package behaviour

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

func activityOf(t *testing.T, c Config, cur, prev []core.Event) (core.ActivityReport, error) {
	t.Helper()
	return mustNew(t, c).Activity(context.Background(), fakeReader{evs: cur}, fakeReader{evs: prev}, win)
}

func subj(t *testing.T, rep core.ActivityReport, name string) core.ActivitySubject {
	t.Helper()
	for _, s := range rep.Subjects {
		if s.Subject == name {
			return s
		}
	}
	t.Fatalf("no subject %q in %+v", name, rep.Subjects)
	return core.ActivitySubject{}
}

func TestActivityRareActionIsActiveWithItsLastTime(t *testing.T) {
	cur := events(win, noise(), ev{key: c1, path: "/oauth/device/code", method: "POST", n: 3})
	rep, err := activityOf(t, cfg(), cur, events(win.Previous(), noise()))
	if err != nil {
		t.Fatal(err)
	}
	s := subj(t, rep, "device-code")
	if !s.Active || s.Current != 3 || s.Previous != 0 || s.Kind != ClassRare {
		t.Fatalf("subject = %+v", s)
	}
	// events() stamps one millisecond apart in order, noise first.
	want := win.From.Add(52 * time.Millisecond)
	if !s.Last.Equal(want) {
		t.Fatalf("last = %v, want %v", s.Last, want)
	}
	if other := subj(t, rep, "signup"); other.Active || !other.Last.IsZero() {
		t.Fatalf("an action that did not occur is %+v", other)
	}
}

func TestActivityCommonActionIsOrdinaryTrafficUnlessItsFailureShareRose(t *testing.T) {
	ordinary, _ := activityOf(t, cfg(),
		events(win, append([]ev{noise()}, tokenTraffic(100, 1)...)...), events(win.Previous(), append([]ev{noise()}, tokenTraffic(100, 1)...)...))
	s := subj(t, ordinary, "token")
	if s.Active || s.Current == 0 || !s.Last.IsZero() {
		t.Fatalf("subject = %+v: legitimate token traffic is not the actor and has no last time", s)
	}
	spike, err := activityOf(t, cfg(),
		events(win, append([]ev{noise()}, tokenTraffic(20, 60)...)...), events(win.Previous(), append([]ev{noise()}, tokenTraffic(100, 1)...)...))
	if err != nil {
		t.Fatal(err)
	}
	if s := subj(t, spike, "token"); !s.Active || s.Last.IsZero() {
		t.Fatalf("subject = %+v, want active once the failure share rose", s)
	}
}

func TestActivityInfrastructureIsNeverTheActor(t *testing.T) {
	cur := events(win, noise(),
		ev{key: gateway, path: "/oauth/device/code", method: "POST", n: 30},
		ev{key: c1, path: "/oauth/device/code", method: "POST", ua: "Gateway-HTTP/1.0", n: 30})
	rep, err := activityOf(t, cfg(), cur, events(win.Previous(), noise()))
	if err != nil {
		t.Fatal(err)
	}
	if s := subj(t, rep, "device-code"); s.Active || s.Current != 0 || !s.Last.IsZero() {
		t.Fatalf("subject = %+v", s)
	}
	if !strings.Contains(strings.Join(rep.Notes, ";"), "60 event(s) set aside as ignored infrastructure") {
		t.Fatalf("notes = %v", rep.Notes)
	}
}

// The report names actions and counts. The key (here an address) is how the detector
// tells clients apart and is never attribution, so it must not be in the report.
func TestActivityReportCarriesNoKey(t *testing.T) {
	cur := events(win, noise(), ev{key: "203.0.113.77", path: "/oauth/device/code", method: "POST", n: 1})
	rep, err := activityOf(t, cfg(), cur, events(win.Previous(), noise()))
	if err != nil {
		t.Fatal(err)
	}
	if !subj(t, rep, "device-code").Active {
		t.Fatal("not active")
	}
	if dump := fmt.Sprintf("%+v", rep); strings.Contains(dump, "203.0.113.77") {
		t.Fatalf("the report carries a key: %s", dump)
	}
}

func TestActivityAgreesWithDetect(t *testing.T) {
	cur := events(win, noise(), ev{key: c1, path: "/oauth/device/code", method: "POST", n: 2}, ev{key: c1, path: "/signup", method: "POST", n: 1})
	pre := events(win.Previous(), noise(), ev{key: c1, path: "/oauth/device/code", method: "POST", n: 1})
	fs, err := detect(t, cfg(), cur, pre)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := activityOf(t, cfg(), cur, pre)
	if err != nil {
		t.Fatal(err)
	}
	raised := byTag(fs)
	for _, s := range rep.Subjects {
		_, in := raised["behaviour:"+s.Subject]
		if in != s.Active {
			t.Errorf("%s: detect raised=%v, activity active=%v", s.Subject, in, s.Active)
		}
	}
}

func TestActivityCountsEventsWithNoPath(t *testing.T) {
	cur := events(win, noise(), ev{key: c1, path: "", method: "POST", n: 30})
	rep, err := activityOf(t, cfg(), cur, events(win.Previous(), noise()))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Seen != 80 || rep.Unparsable != 30 {
		t.Fatalf("seen/unparsable = %d/%d, want 80/30", rep.Seen, rep.Unparsable)
	}
}

func TestActivityEmptyAndFailingReads(t *testing.T) {
	if _, err := activityOf(t, cfg(), nil, events(win.Previous(), noise())); !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want ErrNoRecords", err)
	}
	boom := errors.New("store went away")
	d := mustNew(t, cfg())
	if _, err := d.Activity(context.Background(), fakeReader{evs: events(win, noise())}, fakeReader{err: boom}, win); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the baseline read error, not an empty baseline", err)
	}
}
