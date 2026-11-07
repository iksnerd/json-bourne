package web

import (
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

const evilMap = `m"><script>alert(21)</script>`

func originDeps() Deps {
	a := subjGraph("e1", "operated")
	b := subjGraph(evilMap, "adversary")
	c := subjGraph("e3", "")
	// e4 does not hold the node at all.
	d := subjGraph("e4", "operated")
	d.Nodes = []core.EstateNode{{ID: "host:other.example.com", Kind: "host", Label: "o", Source: "s", Method: "m", Observed: t0}}
	d.Edges = nil
	dd := newDeps(hostileFake())
	dd.Estate = fakeEstate{g: []core.EstateGraph{a, b, c, d}}
	return dd
}

func TestNodeSheetShowsEveryFileAndLayerTheNodeComesFrom(t *testing.T) {
	h := New(originDeps(), Options{Loopback: true})
	for _, body := range bothRenders(t, h, "/estate/node?g=e1&id=ip:192.0.2.10") {
		i := strings.Index(body, "Where this node comes from")
		if i < 0 {
			t.Fatalf("no provenance section:\n%s", body)
		}
		j := strings.Index(body[i:], "<h2>Facts")
		if j < 0 {
			t.Fatalf("provenance section must come before the facts")
		}
		sec := body[i : i+j]
		for _, w := range []string{">e1<", ">Operated<", ">Adversary and third-party<", ">e3<", ">Unclassified<", "this sheet"} {
			if !strings.Contains(sec, w) {
				t.Errorf("provenance lacks %q:\n%s", w, sec)
			}
		}
		if strings.Contains(sec, ">e4<") {
			t.Error("a file without the node must not be listed")
		}
		if strings.Contains(sec, "<script>alert(21)") || strings.Contains(sec, evilMap) {
			t.Error("hostile map id unescaped")
		}
		if !strings.Contains(sec, "&lt;script&gt;alert(21)") {
			t.Errorf("hostile map id should show escaped:\n%s", sec)
		}
	}
}

func TestNodeSheetOfASingleFileListsOnlyThatFile(t *testing.T) {
	h := New(originDeps(), Options{Loopback: true})
	_, _, body := get(t, h, "/estate/node?g=e4&id=host:other.example.com")
	if !strings.Contains(body, "Where this node comes from") || !strings.Contains(body, ">Operated<") || strings.Contains(body, ">Adversary and third-party<") {
		t.Errorf("single file provenance wrong:\n%s", body)
	}
}
