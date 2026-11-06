package dnsbl

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// stub is a Resolver that answers by name and records every question.
type stub struct {
	mu    sync.Mutex
	asked []string
	nets  []string
	h     func(name string) ([]netip.Addr, error)
}

func (s *stub) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	s.mu.Lock()
	s.asked = append(s.asked, host)
	s.nets = append(s.nets, network)
	s.mu.Unlock()
	return s.h(host)
}

func nx(name string) *net.DNSError {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func ips(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

const zone = "bl.example.test"

func newFeed(h func(string) ([]netip.Addr, error), mod func(*Feed)) (*Feed, *stub) {
	st := &stub{h: h}
	f := &Feed{Zone: zone, Resolver: st, MaxLookups: 10, Timeout: time.Second,
		Codes: map[netip.Addr]string{netip.MustParseAddr("127.0.0.2"): "sbl", netip.MustParseAddr("127.0.0.4"): "xbl"},
		Now:   func() time.Time { return time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC) },
		Sleep: func(context.Context, time.Duration) error { return nil }}
	if mod != nil {
		mod(f)
	}
	return f, st
}

func TestListedNotListedAndLookupErrorAreThreeDifferentAnswers(t *testing.T) {
	f, st := newFeed(func(name string) ([]netip.Addr, error) {
		switch name {
		case "1.2.0.192." + zone + ".":
			return ips("127.0.0.2"), nil
		case "2.2.0.192." + zone + ".":
			return nil, nx(name)
		}
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}, nil)
	rs, err := f.Lookup(context.Background(), []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"})
	if len(rs) != 2 {
		t.Fatalf("want 2 answers, got %+v", rs)
	}
	if rs[0].Verdict != "listed=true;zone="+zone+";codes=127.0.0.2:sbl" {
		t.Fatalf("verdict %q", rs[0].Verdict)
	}
	if rs[1].Verdict != core.VerdictNotFound || rs[1].Indicator != "192.0.2.2" {
		t.Fatalf("NXDOMAIN is a real not-listed answer: %+v", rs[1])
	}
	if rs[0].Source != "dnsbl:"+zone || f.Name() != "dnsbl:"+zone || !rs[0].Observed.Equal(time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("source/time: %+v", rs[0])
	}
	les := core.LookupErrors(err)
	if len(les) != 1 || les[0].Indicator != "192.0.2.3" || !errors.Is(les[0], core.ErrFeedFailed) {
		t.Fatalf("SERVFAIL must be a lookup error: %v", err)
	}
	for _, n := range st.nets {
		if n != "ip4" {
			t.Fatalf("a DNSBL is asked for A records only, got network %q", n)
		}
	}
}

func TestReturnCodesAreMappedUnmappedCodesAreKeptRaw(t *testing.T) {
	f, _ := newFeed(func(string) ([]netip.Addr, error) {
		return ips("127.0.0.4", "127.0.0.2", "127.0.0.2", "127.0.0.77"), nil
	}, nil)
	rs, err := f.Lookup(context.Background(), []string{"192.0.2.1"})
	if err != nil || len(rs) != 1 {
		t.Fatal(rs, err)
	}
	if want := "listed=true;zone=" + zone + ";codes=127.0.0.2:sbl,127.0.0.4:xbl,127.0.0.77:unmapped"; rs[0].Verdict != want {
		t.Fatalf("got %q want %q", rs[0].Verdict, want)
	}
}

func TestResolverBlockCodesAreErrorsNeverNotListedNeverListed(t *testing.T) {
	for _, code := range []string{"127.255.255.252", "127.255.255.253", "127.255.255.254", "127.255.255.255"} {
		f, st := newFeed(func(string) ([]netip.Addr, error) { return ips(code), nil }, nil)
		rs, err := f.Lookup(context.Background(), []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"})
		les := core.LookupErrors(err)
		if len(rs) != 0 || len(les) != 3 {
			t.Fatalf("%s: a refusal is not an answer: rs=%v err=%v", code, rs, err)
		}
		if !strings.Contains(les[0].Error(), code) || !strings.Contains(les[0].Error(), "refus") {
			t.Fatalf("%s: the reason must name the refusal: %v", code, les[0])
		}
		if len(st.asked) != 1 {
			t.Fatalf("%s: after a refusal the zone must not be asked again, got %d questions", code, len(st.asked))
		}
	}
}

func TestExtraErrorCodesFromConfigAreErrors(t *testing.T) {
	f, _ := newFeed(func(string) ([]netip.Addr, error) { return ips("127.0.9.9"), nil },
		func(f *Feed) { f.ErrorCodes = []netip.Addr{netip.MustParseAddr("127.0.9.9")} })
	rs, err := f.Lookup(context.Background(), []string{"192.0.2.1"})
	if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
		t.Fatalf("rs=%v err=%v", rs, err)
	}
}

func TestAnAnswerOutsideLoopbackIsAResolverTamperingNotAListing(t *testing.T) {
	for _, tc := range [][]string{{"192.0.2.99"}, {"203.0.113.5", "127.0.0.2"}, {"10.0.0.1"}} {
		f, _ := newFeed(func(string) ([]netip.Addr, error) { return ips(tc...), nil }, nil)
		rs, err := f.Lookup(context.Background(), []string{"192.0.2.1"})
		if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
			t.Fatalf("%v: rs=%v err=%v", tc, rs, err)
		}
	}
}

func TestNoAnswerAndNoErrorIsNotAnAnswer(t *testing.T) {
	f, _ := newFeed(func(string) ([]netip.Addr, error) { return nil, nil }, nil)
	rs, err := f.Lookup(context.Background(), []string{"192.0.2.1"})
	if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
		t.Fatalf("rs=%v err=%v", rs, err)
	}
}

func TestQueryNamesAreReverseOctetAndIPv6IsRefusedUnlessEnabled(t *testing.T) {
	f, st := newFeed(func(n string) ([]netip.Addr, error) { return nil, nx(n) }, nil)
	rs, err := f.Lookup(context.Background(), []string{"192.0.2.1", "2001:db8::1", "::ffff:198.51.100.7"})
	les := core.LookupErrors(err)
	if len(rs) != 2 || len(les) != 1 || les[0].Indicator != "2001:db8::1" {
		t.Fatalf("rs=%v err=%v", rs, err)
	}
	if !strings.Contains(les[0].Error(), "IPv6") {
		t.Fatalf("the reason must say IPv6: %v", les[0])
	}
	if got := strings.Join(st.asked, " "); got != "1.2.0.192."+zone+". 7.100.51.198."+zone+"." {
		t.Fatalf("questions %q: IPv6 must not be asked when disabled, and a mapped address is its IPv4", got)
	}

	f, st = newFeed(func(n string) ([]netip.Addr, error) { return nil, nx(n) }, func(f *Feed) { f.IPv6 = true })
	if _, err := f.Lookup(context.Background(), []string{"2001:db8::1"}); err != nil {
		t.Fatal(err)
	}
	want := "1." + strings.Repeat("0.", 23) + "8.b.d.0.1.0.0.2." + zone + "."
	if len(st.asked) != 1 || st.asked[0] != want {
		t.Fatalf("nibble name:\n got %q\nwant %q", st.asked, want)
	}
}

func TestBudgetIntervalContextAndBadIndicators(t *testing.T) {
	var slept []time.Duration
	f, st := newFeed(func(n string) ([]netip.Addr, error) { return nil, nx(n) }, func(f *Feed) {
		f.MaxLookups = 2
		f.MinInterval = 500 * time.Millisecond
		f.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	})
	rs, err := f.Lookup(context.Background(), []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "example.com", "", "1.2.3.4.zone"})
	les := core.LookupErrors(err)
	if len(rs) != 2 || len(st.asked) != 2 || len(les) != 4 || !errors.Is(les[0], core.ErrBudgetExceeded) {
		t.Fatalf("rs=%d asked=%d err=%v", len(rs), len(st.asked), err)
	}
	if len(slept) != 1 || slept[0] != 500*time.Millisecond {
		t.Fatalf("pause between questions only: %v", slept)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f2, st2 := newFeed(func(n string) ([]netip.Addr, error) { return nil, nx(n) }, nil)
	rs, err = f2.Lookup(ctx, []string{"192.0.2.1", "192.0.2.2"})
	if len(rs) != 0 || len(core.LookupErrors(err)) != 2 || len(st2.asked) != 0 {
		t.Fatalf("rs=%v err=%v asked=%v", rs, err, st2.asked)
	}
}

func TestLabelsFromConfigAreSanitisedInTheVerdict(t *testing.T) {
	f, _ := newFeed(func(string) ([]netip.Addr, error) { return ips("127.0.0.2"), nil }, func(f *Feed) {
		f.Codes = map[netip.Addr]string{netip.MustParseAddr("127.0.0.2"): "a;b\nc=d,e"}
	})
	rs, _ := f.Lookup(context.Background(), []string{"192.0.2.1"})
	if len(rs) != 1 || rs[0].Verdict != "listed=true;zone="+zone+";codes=127.0.0.2:abcde" {
		t.Fatalf("verdict %+v", rs)
	}
}

func TestZoneValidation(t *testing.T) {
	for _, z := range []string{"bl.example.test", "a-b.example.test", "x.y"} {
		if err := ValidZone(z); err != nil {
			t.Errorf("%q: %v", z, err)
		}
	}
	for _, z := range []string{"", "localhost", ".example.test", "example.test.", "ex ample.test", "a..b", "-a.test", strings.Repeat("a", 64) + ".test", strings.Repeat("a.", 130) + "test", "1.2.3.4", "http://x.test", "x.test/path"} {
		if err := ValidZone(z); err == nil {
			t.Errorf("%q must be refused", z)
		}
	}
	f := &Feed{Zone: "bad zone", Resolver: &stub{h: func(string) ([]netip.Addr, error) { t.Fatal("asked"); return nil, nil }}, MaxLookups: 1}
	rs, err := f.Lookup(context.Background(), []string{"192.0.2.1"})
	if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
		t.Fatalf("an invalid zone must fail every lookup: %v %v", rs, err)
	}
}
