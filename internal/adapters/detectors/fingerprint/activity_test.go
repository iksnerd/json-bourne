package fingerprint

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

func activity(t *testing.T, c Config, cur, pre []core.Event) (core.ActivityReport, error) {
	t.Helper()
	return mustNew(t, c).Activity(context.Background(), reader{evs: cur}, reader{evs: pre}, win)
}

func subject(t *testing.T, rep core.ActivityReport, id string) core.ActivitySubject {
	t.Helper()
	for _, s := range rep.Subjects {
		if s.Subject == id {
			return s
		}
	}
	t.Fatalf("no subject %q in %+v", id, rep.Subjects)
	return core.ActivitySubject{}
}

func TestActivityGenuineEventMakesTheActorActive(t *testing.T) {
	cur := append(ordinary(win), evs(win,
		e{at: 5 * time.Minute, ua: actorUA, path: "/login", status: 200},
		e{at: 9 * time.Minute, ua: actorUA, path: "/profile", status: 200},
	)...)
	pre := append(ordinary(prev), evs(prev, e{at: 30 * time.Minute, ua: actorUA, path: "/login", status: 200})...)
	rep, err := activity(t, cfg(), cur, pre)
	if err != nil {
		t.Fatal(err)
	}
	s := subject(t, rep, "actor-a")
	if !s.Active || s.Current != 2 || s.Previous != 1 {
		t.Fatalf("subject = %+v", s)
	}
	if !s.Last.Equal(win.From.Add(9*time.Minute)) || !s.LastEarlier.Equal(prev.From.Add(30*time.Minute)) {
		t.Fatalf("last = %v, earlier = %v", s.Last, s.LastEarlier)
	}
	if rep.Seen != 3 || rep.Unparsable != 0 {
		t.Fatalf("seen/unparsable = %d/%d, want the 3 events read", rep.Seen, rep.Unparsable)
	}
}

// Scanner traffic that shares the actor's user agent is not the actor, and it must not
// move the last genuine time either: a trailing sweep once put "last seen" a day late.
func TestActivityNoiseIsNeverGenuineAndNeverMovesLast(t *testing.T) {
	cur := append(ordinary(win), evs(win,
		e{at: 5 * time.Minute, ua: actorUA, path: "/login", status: 200},
		e{at: 50 * time.Minute, ua: actorUA, path: "/wp-login.php", status: 200},
		e{at: 51 * time.Minute, ua: actorUA, path: "/?junk", status: 404},
	)...)
	rep, err := activity(t, cfg(), cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	s := subject(t, rep, "actor-a")
	if s.Current != 1 || s.Noise != 2 || !s.Last.Equal(win.From.Add(5*time.Minute)) {
		t.Fatalf("subject = %+v, want 1 genuine, 2 noise, last at +5m", s)
	}

	onlyNoise := append(ordinary(win), evs(win,
		e{at: 50 * time.Minute, ua: actorUA, path: "/wp-login.php", status: 200},
		e{at: 51 * time.Minute, ua: actorUA, path: "/", status: 404},
	)...)
	rep, err = activity(t, cfg(), onlyNoise, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	s = subject(t, rep, "actor-a")
	if s.Active || !s.Last.IsZero() || s.Noise != 2 {
		t.Fatalf("subject = %+v: noise alone made the actor active or set a last time", s)
	}
}

func TestActivityInfrastructureIsNeverTheActor(t *testing.T) {
	c := cfg()
	c.IgnoreIPs = []string{gatewayIP}
	cur := append(ordinary(win), evs(win,
		e{at: 5 * time.Minute, ua: actorUA, path: tokenPath, status: 200, ip: gatewayIP},
	)...)
	rep, err := activity(t, c, cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	s := subject(t, rep, "actor-a")
	if s.Active || s.Current != 0 || s.Ignored != 1 || !s.Last.IsZero() {
		t.Fatalf("subject = %+v: a request relayed by our gateway counted as the actor", s)
	}
}

// An address is an observation: an edge relaying the actor and a stranger is not a client.
// The UA decides, and no address may appear anywhere in the report.
func TestActivityNeverAttributesByAddress(t *testing.T) {
	cur := append(ordinary(win), evs(win,
		e{at: 5 * time.Minute, ua: nearMiss, path: "/login", status: 200, ip: edgeIP},
		e{at: 6 * time.Minute, ua: actorUA, path: "/login", status: 200, ip: edgeIP},
	)...)
	rep, err := activity(t, cfg(), cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	if s := subject(t, rep, "actor-a"); s.Current != 1 {
		t.Fatalf("subject = %+v, want only the exact-UA event", s)
	}
	if dump := fmt.Sprintf("%+v", rep); strings.Contains(dump, edgeIP) || strings.Contains(dump, clientIP) {
		t.Fatalf("the report carries an address: %s", dump)
	}
	// The same edge, with no event of the actor: quiet. The address alone proves nothing.
	only := append(ordinary(win), evs(win, e{at: 5 * time.Minute, ua: nearMiss, path: "/login", status: 200, ip: edgeIP})...)
	rep, _ = activity(t, cfg(), only, ordinary(prev))
	if subject(t, rep, "actor-a").Active {
		t.Fatal("a near-miss user agent behind the same edge made the actor active")
	}
}

func TestActivityCountsWhatWasNotJudged(t *testing.T) {
	cur := append(ordinary(win), evs(win,
		e{at: 5 * time.Minute, ua: actorUA, path: "/login", status: 200, drop: "path"},
		e{at: 6 * time.Minute, ua: actorUA, path: "/login", status: "garbage"},
	)...)
	rep, err := activity(t, cfg(), cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Seen != 3 || rep.Unparsable != 2 {
		t.Fatalf("seen/unparsable = %d/%d, want 3/2", rep.Seen, rep.Unparsable)
	}
}

func TestActivityEmptyWindowFollowsTheDetectorsRule(t *testing.T) {
	if _, err := activity(t, cfg(), nil, ordinary(prev)); !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want ErrNoRecords: an empty window is not a quiet one", err)
	}
	c := cfg()
	c.EmptyIsQuiet = true
	rep, err := activity(t, c, nil, ordinary(prev))
	if err != nil || subject(t, rep, "actor-a").Active {
		t.Fatalf("rep = %+v err = %v", rep, err)
	}
}

func TestActivityReadErrorsAreNotEmptyReads(t *testing.T) {
	boom := errors.New("store went away")
	d := mustNew(t, cfg())
	if _, err := d.Activity(context.Background(), reader{evs: ordinary(win), err: boom}, reader{}, win); !errors.Is(err, boom) {
		t.Fatalf("current: err = %v", err)
	}
	if _, err := d.Activity(context.Background(), reader{evs: ordinary(win)}, reader{err: boom}, win); !errors.Is(err, boom) {
		t.Fatalf("preceding: err = %v", err)
	}
}

// Detect and Activity read through one path: whatever one calls genuine, the other does.
func TestActivityAgreesWithDetect(t *testing.T) {
	c := cfg()
	c.IgnoreIPs = []string{gatewayIP}
	cur := append(ordinary(win), evs(win,
		e{at: 1 * time.Minute, ua: actorUA, path: "/login", status: 200},
		e{at: 2 * time.Minute, ua: actorUA, path: "/wp-x", status: 200},
		e{at: 3 * time.Minute, ua: actorUA, path: "/login", status: 200, ip: gatewayIP},
		e{at: 4 * time.Minute, ua: nearMiss, path: "/login", status: 200},
	)...)
	fs, err := detect(t, c, cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := activity(t, c, cur, ordinary(prev))
	if err != nil {
		t.Fatal(err)
	}
	f, s := byTag(fs, "fingerprint:actor-a"), subject(t, rep, "actor-a")
	if f.Detail["cur_genuine"] != s.Current || f.Detail["cur_filtered"] != s.Noise || f.Detail["cur_ignored"] != s.Ignored {
		t.Fatalf("detect %v and activity %+v disagree", f.Detail, s)
	}
}

// byField is a store of events searchable by one field, newest first.
type byField struct {
	evs []core.Event // oldest first
	err error
}

func (b byField) EventsByField(_ context.Context, field, value string) iter.Seq2[core.Event, error] {
	return func(yield func(core.Event, error) bool) {
		for i := len(b.evs) - 1; i >= 0; i-- {
			if got, _ := b.evs[i].Fields[field].(string); got == value && !yield(b.evs[i], nil) {
				return
			}
		}
		if b.err != nil {
			yield(core.Event{}, b.err)
		}
	}
}

func TestHistoryFindsTheLastGenuineMatchPastTrailingNoiseAndInfrastructure(t *testing.T) {
	c := cfg()
	c.IgnoreIPs = []string{gatewayIP}
	store := byField{evs: append(append(
		evs(win, e{at: 5 * time.Minute, ua: actorUA, path: "/login", status: 200}),
		evs(win,
			e{at: 20 * time.Minute, ua: actorUA, path: "/login", status: 200}, // the real last one
			e{at: 30 * time.Minute, ua: actorUA, path: "/wp-login.php", status: 200},
			e{at: 40 * time.Minute, ua: actorUA, path: "/", status: 404},
			e{at: 50 * time.Minute, ua: actorUA, path: "/login", status: 200, ip: gatewayIP},
			e{at: 55 * time.Minute, ua: nearMiss, path: "/login", status: 200},
		)...), evs(win, e{at: 56 * time.Minute, ua: actorUA, path: "/x", status: 200, drop: "path"})...)}
	hs, err := mustNew(t, c).History(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != 1 {
		t.Fatalf("history = %+v", hs)
	}
	h := hs[0]
	if !h.LastGenuine.Equal(win.From.Add(20*time.Minute)) || h.Indicator != actorUA || h.Actor != "actor-a" {
		t.Fatalf("history = %+v, want the +20m event", h)
	}
	if h.Noise != 2 || h.Ignored != 1 || h.Unparsable != 1 || h.Scanned != 5 || h.Capped {
		t.Fatalf("history = %+v, want 2 noise, 1 ignored, 1 unparsable, 5 scanned", h)
	}
}

func TestHistoryNeverMatchedIsNotAnError(t *testing.T) {
	hs, err := mustNew(t, cfg()).History(context.Background(), byField{})
	if err != nil || len(hs) != 1 || !hs[0].LastGenuine.IsZero() || hs[0].Scanned != 0 {
		t.Fatalf("hs = %+v err = %v", hs, err)
	}
}

func TestHistoryNoiseOnlyHasNoGenuineDate(t *testing.T) {
	store := byField{evs: evs(win, e{at: time.Minute, ua: actorUA, path: "/wp-login.php", status: 200})}
	hs, err := mustNew(t, cfg()).History(context.Background(), store)
	if err != nil || !hs[0].LastGenuine.IsZero() || hs[0].Noise != 1 {
		t.Fatalf("hs = %+v err = %v", hs, err)
	}
}

func TestHistoryReadErrorIsAnError(t *testing.T) {
	boom := errors.New("store went away")
	if _, err := mustNew(t, cfg()).History(context.Background(), byField{err: boom}); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, err := mustNew(t, cfg()).History(context.Background(), nil); err == nil {
		t.Fatal("nil finder accepted")
	}
}

func TestHistoryListsEveryUserAgentOfEveryActor(t *testing.T) {
	c := cfg()
	c.Actors[0].UserAgents = []string{actorUA, "Other/2.0"}
	c.Actors = append(c.Actors, Actor{ID: "actor-b", UserAgents: []string{"B/1.0"}})
	hs, err := mustNew(t, c).History(context.Background(), byField{})
	if err != nil || len(hs) != 3 {
		t.Fatalf("hs = %+v err = %v", hs, err)
	}
}
