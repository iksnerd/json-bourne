package dnsptr

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

// fakeDNS is a UDP DNS server that answers every query by rule. It records who dialled
// it and what was asked, so a test can show that only the resolver is ever contacted.
type fakeDNS struct {
	pc      net.PacketConn
	mu      sync.Mutex
	asked   []string
	rcode   int      // 0 ok, 3 NXDOMAIN, 2 SERVFAIL
	answers []string // PTR targets, e.g. "edge.example.com."
	silent  bool     // never answer: a timeout
}

func newFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	f := &fakeDNS{pc: pc}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			f.mu.Lock()
			f.asked = append(f.asked, qname(q))
			silent, rcode, answers := f.silent, f.rcode, f.answers
			f.mu.Unlock()
			if silent {
				continue
			}
			_, _ = pc.WriteTo(reply(q, rcode, answers), from)
		}
	}()
	return f
}

func (f *fakeDNS) update(fn func()) { f.mu.Lock(); fn(); f.mu.Unlock() }

func (f *fakeDNS) questions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

func qname(q []byte) string {
	var parts []string
	for i := 12; i < len(q) && q[i] != 0; {
		l := int(q[i])
		parts = append(parts, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	return strings.Join(parts, ".")
}

func encodeName(n string) []byte {
	var b []byte
	for _, p := range strings.Split(strings.TrimSuffix(n, "."), ".") {
		b = append(b, byte(len(p)))
		b = append(b, p...)
	}
	return append(b, 0)
}

func reply(q []byte, rcode int, answers []string) []byte {
	end := 12
	for q[end] != 0 {
		end += int(q[end]) + 1
	}
	end += 1 + 4 // root label, QTYPE, QCLASS
	out := append([]byte(nil), q[:end]...)
	out[2], out[3] = 0x81, 0x80|byte(rcode) // response, RD, RA, rcode
	out[6], out[7] = 0, byte(len(answers))
	out[8], out[9], out[10], out[11] = 0, 0, 0, 0
	for _, a := range answers {
		rd := encodeName(a)
		out = append(out, 0xC0, 0x0C, 0, 12, 0, 1, 0, 0, 0, 60, byte(len(rd)>>8), byte(len(rd)))
		out = append(out, rd...)
	}
	return out
}

type dialLog struct {
	mu sync.Mutex
	a  []string
}

func (d *dialLog) add(s string) { d.mu.Lock(); d.a = append(d.a, s); d.mu.Unlock() }

func dialedList(d *dialLog) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.a...)
}

// resolver returns a net.Resolver whose every connection goes to the fake server, and
// the list of addresses it was asked to dial.
func (f *fakeDNS) resolver() (*net.Resolver, *dialLog) {
	dialed := &dialLog{}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed.add(address)
		var d net.Dialer
		return d.DialContext(ctx, "udp", f.pc.LocalAddr().String())
	}}, dialed
}

func TestLookupPTRAnswer(t *testing.T) {
	f := newFakeDNS(t)
	f.update(func() { f.answers = []string{"Edge.Example.COM.", "second.example.com."} })
	r, dialed := f.resolver()
	a := New(r, "fake resolver")
	got, err := a.LookupPTR(context.Background(), netip.MustParseAddr("192.0.2.10"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Names) != 2 || got.Names[0] != "edge.example.com" {
		t.Errorf("names %v: lower case, no trailing dot", got.Names)
	}
	if want := "PTR 10.2.0.192.in-addr.arpa via fake resolver"; got.Query != want {
		t.Errorf("query %q, want %q", got.Query, want)
	}
	if q := f.questions(); len(q) == 0 || q[0] != "10.2.0.192.in-addr.arpa" {
		t.Errorf("the resolver was asked %v", q)
	}
	for _, d := range dialedList(dialed) {
		if strings.HasPrefix(d, "192.0.2.10") {
			t.Fatalf("dialled the target: %v", dialedList(dialed))
		}
	}
}

func TestLookupPTRNXDomainIsNotFoundWithQuery(t *testing.T) {
	f := newFakeDNS(t)
	f.update(func() { f.rcode = 3 })
	r, _ := f.resolver()
	got, err := New(r, "fake").LookupPTR(context.Background(), netip.MustParseAddr("192.0.2.10"))
	if !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("NXDOMAIN must be ErrNotFound, got %v", err)
	}
	if got.Query == "" {
		t.Error("the query must be set even for a not-found answer")
	}
}

func TestLookupPTRFailuresAreNotAnswers(t *testing.T) {
	t.Run("servfail", func(t *testing.T) {
		f := newFakeDNS(t)
		f.update(func() { f.rcode = 2 })
		r, _ := f.resolver()
		_, err := New(r, "fake").LookupPTR(context.Background(), netip.MustParseAddr("192.0.2.10"))
		if !errors.Is(err, core.ErrLookupFailed) || errors.Is(err, core.ErrNotFound) {
			t.Fatalf("SERVFAIL must be a failure, got %v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f := newFakeDNS(t)
		f.update(func() { f.silent = true })
		r, _ := f.resolver()
		a := New(r, "fake")
		a.Timeout = 300 * time.Millisecond
		start := time.Now()
		_, err := a.LookupPTR(context.Background(), netip.MustParseAddr("192.0.2.10"))
		if !errors.Is(err, core.ErrLookupFailed) || errors.Is(err, core.ErrNotFound) {
			t.Fatalf("a timeout must be a failure, got %v", err)
		}
		if time.Since(start) > 5*time.Second {
			t.Errorf("timeout not bounded: %v", time.Since(start))
		}
	})
	t.Run("resolver unreachable", func(t *testing.T) {
		r := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		}}
		_, err := New(r, "dead").LookupPTR(context.Background(), netip.MustParseAddr("192.0.2.10"))
		if !errors.Is(err, core.ErrLookupFailed) || errors.Is(err, core.ErrNotFound) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestLookupPTRHostileValues(t *testing.T) {
	f := newFakeDNS(t)
	f.update(func() {
		f.answers = []string{"ok.example.com.", "a.b.c.d.e.f.g.h.i.j.k.example.com.", "x1.example.com.", "x2.example.com.", "x3.example.com.", "x4.example.com."}
	})
	r, _ := f.resolver()
	a := New(r, "fake")
	a.MaxNames = 3
	got, err := a.LookupPTR(context.Background(), netip.MustParseAddr("192.0.2.10"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Names) != 3 {
		t.Errorf("at most MaxNames values are kept: %v", got.Names)
	}
	for _, n := range got.Names {
		if strings.ContainsAny(n, " \n") {
			t.Errorf("unvalidated name %q", n)
		}
	}
}

func TestLookupPTRRefusesAnInvalidName(t *testing.T) {
	f := newFakeDNS(t)
	f.update(func() { f.answers = []string{"bad name with spaces."} })
	r, _ := f.resolver()
	_, err := New(r, "fake").LookupPTR(context.Background(), netip.MustParseAddr("192.0.2.10"))
	if !errors.Is(err, core.ErrLookupFailed) || errors.Is(err, core.ErrNotFound) {
		t.Fatalf("an unusable PTR value is a failure, not data and not a not-found: %v", err)
	}
}

func TestReverseName(t *testing.T) {
	if got := reverseName(netip.MustParseAddr("192.0.2.10")); got != "10.2.0.192.in-addr.arpa" {
		t.Error(got)
	}
	if got := reverseName(netip.MustParseAddr("2001:db8::1")); got != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" {
		t.Error(got)
	}
}
