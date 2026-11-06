package dnsfwd

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

type rr struct {
	typ   uint16
	rdata []byte
}

// fakeDNS answers every query with the records set for its type. It records what was
// asked and who was dialled, so a test can show that only the resolver is contacted.
type fakeDNS struct {
	pc     net.PacketConn
	mu     sync.Mutex
	asked  []string
	rcode  int
	recs   map[uint16][]rr
	silent bool
}

func newFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	f := &fakeDNS{pc: pc, recs: map[uint16][]rr{}}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			name, qt := parseQ(q)
			f.mu.Lock()
			f.asked = append(f.asked, name)
			silent, rcode, recs := f.silent, f.rcode, f.recs[qt]
			var owner []byte
			if (qt == 1 || qt == 28) && len(f.recs[5]) > 0 {
				// Go takes the canonical name from the owner of an address record.
				own := f.recs[5][0].rdata
				owner = own
			}
			f.mu.Unlock()
			if silent {
				continue
			}
			_, _ = pc.WriteTo(reply(q, rcode, recs, owner), from)
		}
	}()
	return f
}

func (f *fakeDNS) set(fn func(f *fakeDNS)) { f.mu.Lock(); fn(f); f.mu.Unlock() }

func parseQ(q []byte) (string, uint16) {
	var parts []string
	i := 12
	for ; i < len(q) && q[i] != 0; i += 1 + int(q[i]) {
		parts = append(parts, string(q[i+1:i+1+int(q[i])]))
	}
	return strings.Join(parts, "."), uint16(q[i+1])<<8 | uint16(q[i+2])
}

func encName(n string) []byte {
	var b []byte
	for _, p := range strings.Split(strings.TrimSuffix(n, "."), ".") {
		b = append(b, byte(len(p)))
		b = append(b, p...)
	}
	return append(b, 0)
}

// reply builds a response. owner, when set, is the encoded name the records belong to
// (the end of a CNAME chain); otherwise they belong to the name asked about.
func reply(q []byte, rcode int, recs []rr, owner []byte) []byte {
	end := 12
	for q[end] != 0 {
		end += int(q[end]) + 1
	}
	end += 5
	out := append([]byte(nil), q[:end]...)
	out[2], out[3] = 0x81, 0x80|byte(rcode)
	out[6], out[7] = 0, byte(len(recs))
	out[8], out[9], out[10], out[11] = 0, 0, 0, 0
	for _, r := range recs {
		if owner != nil {
			out = append(out, owner...)
		} else {
			out = append(out, 0xC0, 0x0C)
		}
		out = append(out, byte(r.typ>>8), byte(r.typ), 0, 1, 0, 0, 0, 60, byte(len(r.rdata)>>8), byte(len(r.rdata)))
		out = append(out, r.rdata...)
	}
	return out
}

func txt(s string) rr { return rr{16, append([]byte{byte(len(s))}, s...)} }

type dialed struct {
	mu sync.Mutex
	a  []string
}

func (f *fakeDNS) resolver() (*net.Resolver, *dialed) {
	d := &dialed{}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d.mu.Lock()
		d.a = append(d.a, address)
		d.mu.Unlock()
		var nd net.Dialer
		return nd.DialContext(ctx, "udp", f.pc.LocalAddr().String())
	}}, d
}

func newR(f *fakeDNS) (*Resolver, *dialed) {
	r, d := f.resolver()
	x := New(r, "fake resolver")
	x.Timeout = time.Second
	return x, d
}

func TestLookupAnswersEachType(t *testing.T) {
	f := newFakeDNS(t)
	f.set(func(f *fakeDNS) {
		f.recs[28] = []rr{{28, netip.MustParseAddr("2001:db8::10").AsSlice()}}
		f.recs[1] = []rr{{1, netip.MustParseAddr("192.0.2.10").AsSlice()}}
		f.recs[15] = []rr{{15, append([]byte{0, 10}, encName("mail.example.com")...)}}
		f.recs[2] = []rr{{2, encName("ns1.example.com")}, {2, encName("ns2.example.com")}}
		f.recs[16] = []rr{txt("google-site-verification=SECRETISH"), txt("v=spf1 ip4:192.0.2.0/24 -all")}
	})
	r, _ := newR(f)
	want := map[core.DNSType][]string{
		core.DNSA: {"192.0.2.10"}, core.DNSAAAA: {"2001:db8::10"}, core.DNSCNAME: {"edge.example.net"},
		core.DNSMX: {"mail.example.com"}, core.DNSNS: {"ns1.example.com", "ns2.example.com"},
		core.DNSSPF: {"v=spf1 ip4:192.0.2.0/24 -all"},
	}
	for typ, w := range want {
		if typ == core.DNSCNAME {
			f.set(func(f *fakeDNS) { f.recs[5] = []rr{{5, encName("Edge.Example.NET.")}} })
		} else {
			f.set(func(f *fakeDNS) { delete(f.recs, 5) })
		}
		got, err := r.Lookup(context.Background(), "svc.example.com", typ)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if strings.Join(got.Values, "|") != strings.Join(w, "|") {
			t.Errorf("%s: got %v want %v", typ, got.Values, w)
		}
		if !strings.Contains(got.Query, "svc.example.com via fake resolver") {
			t.Errorf("%s: query %q", typ, got.Query)
		}
	}
}

func TestSPFLookupNeverReturnsOtherTXT(t *testing.T) {
	f := newFakeDNS(t)
	f.set(func(f *fakeDNS) { f.recs[16] = []rr{txt("google-site-verification=SECRETISH"), txt("v=spf1 -all")} })
	r, _ := newR(f)
	got, err := r.Lookup(context.Background(), "svc.example.com", core.DNSSPF)
	if err != nil || strings.Contains(strings.Join(got.Values, " "), "SECRETISH") {
		t.Fatalf("%v %v", got, err)
	}
	f.set(func(f *fakeDNS) { f.recs[16] = []rr{txt("google-site-verification=SECRETISH")} })
	if _, err := r.Lookup(context.Background(), "svc.example.com", core.DNSSPF); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("TXT without SPF is a not-found for SPF: %v", err)
	}
}

func TestNXDOMAINAndNoCNAMEAreAnswers(t *testing.T) {
	f := newFakeDNS(t)
	f.set(func(f *fakeDNS) { f.rcode = 3 })
	r, _ := newR(f)
	for _, typ := range core.DNSTypes {
		ans, err := r.Lookup(context.Background(), "gone.example.com", typ)
		if !errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrLookupFailed) {
			t.Errorf("%s: NXDOMAIN must be ErrNotFound only: %v", typ, err)
		}
		if ans.Query == "" {
			t.Errorf("%s: query must be set on a not-found answer", typ)
		}
	}
	// A name with an address and no CNAME: Go reports the name itself.
	f.set(func(f *fakeDNS) { f.rcode = 0; f.recs[1] = []rr{{1, netip.MustParseAddr("192.0.2.10").AsSlice()}} })
	if _, err := r.Lookup(context.Background(), "svc.example.com", core.DNSCNAME); !errors.Is(err, core.ErrNotFound) {
		t.Errorf("a CNAME to itself is no CNAME: %v", err)
	}
}

func TestResolverFailuresAreNotAnswers(t *testing.T) {
	f := newFakeDNS(t)
	r, _ := newR(f)
	f.set(func(f *fakeDNS) { f.rcode = 2 }) // SERVFAIL
	for _, typ := range core.DNSTypes {
		if _, err := r.Lookup(context.Background(), "svc.example.com", typ); !errors.Is(err, core.ErrLookupFailed) || errors.Is(err, core.ErrNotFound) {
			t.Errorf("%s SERVFAIL: %v", typ, err)
		}
	}
	f.set(func(f *fakeDNS) { f.rcode = 0; f.silent = true })
	r.Timeout = 200 * time.Millisecond
	start := time.Now()
	if _, err := r.Lookup(context.Background(), "svc.example.com", core.DNSA); !errors.Is(err, core.ErrLookupFailed) || errors.Is(err, core.ErrNotFound) {
		t.Errorf("timeout: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("not bounded: %v", time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Lookup(ctx, "svc.example.com", core.DNSA); !errors.Is(err, core.ErrLookupFailed) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestValuesAreCappedAndSaid(t *testing.T) {
	f := newFakeDNS(t)
	f.set(func(f *fakeDNS) {
		for _, n := range []string{"a", "b", "c", "d"} {
			f.recs[2] = append(f.recs[2], rr{2, encName(n + ".example.com")})
		}
	})
	r, _ := newR(f)
	r.MaxValues = 3
	got, err := r.Lookup(context.Background(), "svc.example.com", core.DNSNS)
	if err != nil || len(got.Values) != 3 || !got.Truncated {
		t.Fatalf("%+v %v: more than the cap must say so", got, err)
	}
}

// Only the resolver is dialled: never the name or an address it resolves to.
func TestOnlyTheResolverIsDialled(t *testing.T) {
	f := newFakeDNS(t)
	f.set(func(f *fakeDNS) { f.recs[1] = []rr{{1, netip.MustParseAddr("192.0.2.10").AsSlice()}} })
	r, d := newR(f)
	if _, err := r.Lookup(context.Background(), "svc.example.com", core.DNSA); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.a) == 0 {
		t.Fatal("the resolver was never dialled")
	}
	for _, a := range d.a {
		if strings.Contains(a, "192.0.2.10") || strings.Contains(a, "svc.example.com") {
			t.Errorf("dialled %s", a)
		}
	}
}
