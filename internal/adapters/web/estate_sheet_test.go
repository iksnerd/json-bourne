package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	evilKey = `k"><script>alert(11)</script>`
	evilVal = `v"><img src=x onerror=alert(12)>`
	evilNot = `n"><script>alert(13)</script>`
	evilBas = `b"><script>alert(14)</script>`
)

// sheetGraph has one node with facts out of order and two values under one key, a hostile
// key and value, and three assessments: one about the node, one about another node that
// cites the first in its basis, and one whose basis only shares a prefix with its id.
func sheetGraph() core.EstateGraph {
	f := func(k, v, src string) core.EstateFact {
		return core.EstateFact{Key: k, Value: v, Source: src, Method: "m-" + src, Observed: t0}
	}
	return core.EstateGraph{ID: "e1", Caveat: "c",
		Nodes: []core.EstateNode{
			{ID: "ip:192.0.2.10", Kind: "ip", Label: "a", Source: "rdns", Method: "m", Observed: t0, Facts: []core.EstateFact{
				f("tech", "nginx", "s1"), f("port.open", "8443", "s2"), f(evilKey, evilVal, "s3"), f("port.open", "443", "s4"), f("banner", "x", "s5")}},
			{ID: "host:b.example.com", Kind: "host", Label: "b", Source: "rdns", Method: "m", Observed: t0},
		},
		Assessments: []core.EstateAssessment{
			{ID: "a1", Subject: "ip:192.0.2.10", Label: "about-self", By: "analyst", Decided: "2026-11-06T12:00:00Z", Basis: []string{"ip:192.0.2.10#port.open"}, Note: evilNot},
			{ID: "a2", Subject: "host:b.example.com", Label: "cites-ip", By: "other", Decided: "2026-11-06T13:00:00Z", Basis: []string{evilBas, "ip:192.0.2.10#tech"}, Note: "see the ip"},
			{ID: "a3", Subject: "host:b.example.com", Label: "unrelated", By: "other", Decided: "2026-11-06T14:00:00Z", Basis: []string{"ip:192.0.2.100"}, Note: "prefix only"},
		},
	}
}

func sheetHandler() http.Handler {
	return New(depsWith(hostileFake(), sheetGraph()), Options{Loopback: true})
}

// bothRenders is the node record as a page and as the htmx fragment of the sheet.
func bothRenders(t *testing.T, h http.Handler, target string) []string {
	t.Helper()
	_, _, page := get(t, h, target)
	_, _, frag := getHX(t, h, target)
	return []string{page, frag}
}

func TestNodeSheetGroupsFactsByKeyInStableOrder(t *testing.T) {
	for _, body := range bothRenders(t, sheetHandler(), estNode) {
		iB, iP, iT := strings.Index(body, ">banner<"), strings.Index(body, ">port.open<"), strings.Index(body, ">tech<")
		if !(iB >= 0 && iB < iP && iP < iT) {
			t.Fatalf("keys not grouped in key order (%d %d %d):\n%s", iB, iP, iT, body)
		}
		if strings.Count(body, ">port.open<") != 1 {
			t.Errorf("a key with several values is listed once:\n%s", body)
		}
		i443, i8443 := strings.Index(body, ">443<"), strings.Index(body, ">8443<")
		if !(iP < i443 && i443 < i8443 && i8443 < iT) {
			t.Errorf("values of port.open out of order or outside the group (%d %d %d %d)", iP, i443, i8443, iT)
		}
		for _, w := range []string{">s4<", ">m-s4<", ">s2<", ">m-s2<", ">" + t0 + "<"} {
			if !strings.Contains(body, w) {
				t.Errorf("fact lacks %q", w)
			}
		}
	}
}

func TestNodeSheetEscapesFactKeyAndValue(t *testing.T) {
	for _, body := range bothRenders(t, sheetHandler(), estNode) {
		for _, bad := range []string{"<script>alert(11)", "<img src=x", evilKey, evilVal} {
			if strings.Contains(body, bad) {
				t.Errorf("hostile fact text reached the page unescaped: %q", bad)
			}
		}
		if !strings.Contains(body, "&lt;script&gt;alert(11)") {
			t.Errorf("hostile key should appear escaped:\n%s", body)
		}
	}
}
