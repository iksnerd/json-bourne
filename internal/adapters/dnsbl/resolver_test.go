package dnsbl

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// fakeDNS is a UDP DNS server whose answer depends on the name asked. It records the
// questions, so a test can show that only the resolver is contacted and what it was asked.
type fakeDNS struct {
	pc    net.PacketConn
	mu    sync.Mutex
	asked []string
	rule  func(name string) (rcode int, a []string, silent bool)
}

func newFakeDNS(t *testing.T, rule func(string) (int, []string, bool)) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	f := &fakeDNS{pc: pc, rule: rule}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			name := qname(q)
			f.mu.Lock()
			f.asked = append(f.asked, name)
			f.mu.Unlock()
			rc, a, silent := rule(name)
			if silent {
				continue
			}
			_, _ = pc.WriteTo(reply(q, rc, a), from)
		}
	}()
	return f
}

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

func reply(q []byte, rcode int, answers []string) []byte {
	end := 12
	for q[end] != 0 {
		end += int(q[end]) + 1
	}
	end += 1 + 4
	out := append([]byte(nil), q[:end]...)
	out[2], out[3] = 0x81, 0x80|byte(rcode)
	out[6], out[7] = 0, byte(len(answers))
	out[8], out[9], out[10], out[11] = 0, 0, 0, 0
	for _, a := range answers {
		ip := net.ParseIP(a).To4()
		out = append(out, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		out = append(out, ip...)
	}
	return out
}

type dials struct {
	mu sync.Mutex
	a  []string
}

func (d *dials) list() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.a...)
}

func (f *fakeDNS) resolver() (*net.Resolver, *dials) {
	d := &dials{}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d.mu.Lock()
		d.a = append(d.a, address)
		d.mu.Unlock()
		var dd net.Dialer
		return dd.DialContext(ctx, network, f.pc.LocalAddr().String())
	}}, d
}

// Through a real net.Resolver the three outcomes keep their meaning: NXDOMAIN is "not
// listed", SERVFAIL / REFUSED / silence are lookup errors, and the indicator is never dialled.
func TestRealResolverRcodesKeepTheirMeaning(t *testing.T) {
	srv := newFakeDNS(t, func(name string) (int, []string, bool) {
		switch {
		case strings.HasPrefix(name, "1.2.0.192."):
			return 0, []string{"127.0.0.2"}, false // listed
		case strings.HasPrefix(name, "2.2.0.192."):
			return 3, nil, false // NXDOMAIN
		case strings.HasPrefix(name, "3.2.0.192."):
			return 2, nil, false // SERVFAIL
		case strings.HasPrefix(name, "4.2.0.192."):
			return 5, nil, false // REFUSED
		case strings.HasPrefix(name, "5.2.0.192."):
			return 0, nil, true // silence: a timeout
		case strings.HasPrefix(name, "6.2.0.192."):
			return 0, []string{"127.255.255.254"}, false // open-resolver refusal
		}
		return 3, nil, false
	})
	res, dialed := srv.resolver()
	f := &Feed{Zone: zone, Resolver: res, MaxLookups: 10, Timeout: 400 * time.Millisecond,
		Codes: nil, Sleep: func(context.Context, time.Duration) error { return nil }}
	rs, err := f.Lookup(context.Background(), []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7"})
	got := map[string]string{}
	for _, r := range rs {
		got[r.Indicator] = r.Verdict
	}
	if got["192.0.2.1"] != "listed=true;zone="+zone+";codes=127.0.0.2:unmapped" || got["192.0.2.2"] != core.VerdictNotFound {
		t.Fatalf("answers: %v", got)
	}
	failed := map[string]bool{}
	for _, le := range core.LookupErrors(err) {
		failed[le.Indicator] = true
	}
	for _, ip := range []string{"192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6"} {
		if _, isAnswer := got[ip]; isAnswer || !failed[ip] {
			t.Errorf("%s must be a lookup error, not an answer (answer=%q)", ip, got[ip])
		}
	}
	if _, ok := got["192.0.2.7"]; ok {
		t.Errorf("192.0.2.7 comes after the refusal and must not have been asked: %v", got)
	}
	for _, d := range dialed.list() {
		if strings.HasPrefix(d, "192.0.2.") {
			t.Fatalf("the indicator was dialled: %s", d)
		}
	}
	for _, q := range srv.questions() {
		if q != strings.TrimSuffix(q, ".local") || !strings.HasSuffix(q, "."+zone) {
			t.Fatalf("a question outside the zone: %q", q)
		}
	}
}
