package web

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

const evilRel2 = `r"><script>alert(31)</script>`

// edgeSheetGraph has edges of three relations around one node, listed out of order.
func edgeSheetGraph() core.EstateGraph {
	n := func(id string) core.EstateNode {
		return core.EstateNode{ID: id, Kind: "host", Label: id, Source: "s", Method: "m", Observed: t0}
	}
	e := func(from, to, rel, src, conf string) core.EstateEdge {
		return core.EstateEdge{From: from, To: to, Relation: rel, Source: src, Method: "m-" + src, Observed: "2026-11-0" + strconv.Itoa(len(src)) + "T10:00:00Z", Confidence: conf}
	}
	const me = "ip:192.0.2.10"
	return core.EstateGraph{ID: "e1", Caveat: "c",
		Nodes: []core.EstateNode{n(me), n("host:z.example.com"), n("host:a.example.com"), n("host:m.example.com")},
		Edges: []core.EstateEdge{
			e(me, "host:z.example.com", "resolves_to", "dns", "stated"),
			e("host:m.example.com", me, "ptr", "rdns", "inferred"),
			e(me, "host:a.example.com", "resolves_to", "dns", "stated"),
			e(me, "host:m.example.com", evilRel2, "feed", "stated"),
			e("host:a.example.com", me, "ptr", "rdns", "stated"),
		}}
}

func edgeSheetHandler() http.Handler {
	d := newDeps(hostileFake())
	d.Estate = fakeEstate{g: []core.EstateGraph{edgeSheetGraph()}}
	return New(d, Options{Loopback: true})
}

func TestNodeSheetListsEdgesGroupedByRelationInStableOrder(t *testing.T) {
	for _, body := range bothRenders(t, edgeSheetHandler(), "/estate/node?g=e1&id=ip:192.0.2.10") {
		if strings.Contains(body, "Connections out") || strings.Contains(body, "Connections in") {
			t.Error("edges are one section grouped by relation now")
		}
		i := strings.Index(body, "<h2>Connections")
		j := strings.Index(body, "<h2>Absences")
		if i < 0 || j < i {
			t.Fatalf("no connections section:\n%s", body)
		}
		sec := body[i:j]
		iPtr, iRes := strings.Index(sec, ">ptr<"), strings.Index(sec, ">resolves_to<")
		iEvil := strings.Index(sec, "&lt;script&gt;alert(31)")
		// Byte order: ptr, then r"><script>... (the quote sorts before 'e'), then resolves_to.
		if !(iPtr >= 0 && iPtr < iEvil && iEvil < iRes) {
			t.Fatalf("relations out of order (ptr %d, evil %d, resolves_to %d):\n%s", iPtr, iEvil, iRes, sec)
		}
		// Within resolves_to: a before z.
		seg := sec[iRes:]
		if a, z := strings.Index(seg, "host:a.example.com"), strings.Index(seg, "host:z.example.com"); !(a >= 0 && a < z) {
			t.Errorf("other nodes out of order within a relation (%d %d)", a, z)
		}
		// src "dns" has 3 letters, "rdns" 4, "feed" 4.
		for _, w := range []string{">out<", ">in<", ">dns<", ">m-dns<", ">rdns<", ">inferred<", ">stated<", ">2026-11-03T10:00:00Z<", ">2026-11-04T10:00:00Z<"} {
			if !strings.Contains(sec, w) {
				t.Errorf("connections lack %q", w)
			}
		}
		for _, bad := range []string{"<script>alert(31)", evilRel2} {
			if strings.Contains(body, bad) {
				t.Errorf("hostile relation unescaped: %q", bad)
			}
		}
	}
}

func TestNodeSheetWithNoEdgesSaysSo(t *testing.T) {
	_, _, body := get(t, edgeSheetHandler(), "/estate/node?g=e1&id=host:m.example.com")
	if !strings.Contains(body, "<h2>Connections") {
		t.Fatal("no connections section")
	}
	_, _, lone := get(t, New(depsWith(hostileFake(), sheetGraph()), Options{Loopback: true}), "/estate/node?g=e1&id=host:b.example.com")
	if !strings.Contains(lone, "no edge touches this node") {
		t.Errorf("empty connections not reported:\n%s", lone)
	}
}
