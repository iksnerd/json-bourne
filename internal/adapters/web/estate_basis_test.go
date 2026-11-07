package web

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// What these tests cover: that a basis entry of the form node#key becomes an in-page link
// to the fact group it names, that one which names nothing is printed as unresolved, and
// that the group shows the assessments that cite it. What they do not cover: that the
// browser scrolls to the anchor. That runs in a browser.

func basisGraph() core.EstateGraph {
	g := sheetGraph()
	g.Assessments = append(g.Assessments, core.EstateAssessment{ID: "a4", Subject: "ip:192.0.2.10", Label: "dangling", By: "analyst",
		Decided: "2026-11-06T15:00:00Z", Basis: []string{"ip:192.0.2.10#no.such.key", "host:gone.example.com#x", "host:b.example.com"}, Note: "n"})
	return g
}

func basisHandler() http.Handler {
	return New(depsWith(hostileFake(), basisGraph()), Options{Loopback: true})
}

func TestBasisCitingAFactLinksToItsGroupOnTheSameSheet(t *testing.T) {
	for _, body := range bothRenders(t, basisHandler(), estNode) {
		m := regexp.MustCompile(`<a href="#(fact-\d+)">ip:192\.0\.2\.10#port\.open</a>`).FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("the basis ip:192.0.2.10#port.open is not an in-page link:\n%s", body)
		}
		if !regexp.MustCompile(`id="` + m[1] + `"[^>]*>port\.open<`).MatchString(body) {
			t.Errorf("anchor %s is not the port.open group heading:\n%s", m[1], body)
		}
		t2 := regexp.MustCompile(`<a href="#(fact-\d+)">ip:192\.0\.2\.10#tech</a>`).FindStringSubmatch(body)
		if t2 == nil || t2[1] == m[1] {
			t.Errorf("tech basis should link to its own, different group: %v", t2)
		}
	}
}

func TestBasisThatCitesNothingIsShownAsUnresolvedNeverDropped(t *testing.T) {
	for _, body := range bothRenders(t, basisHandler(), estNode) {
		for _, w := range []string{"ip:192.0.2.10#no.such.key", "host:gone.example.com#x"} {
			i := strings.Index(body, w)
			if i < 0 {
				t.Fatalf("unresolved basis %q was dropped", w)
			}
			if strings.Contains(body[max(0, i-30):i], "<a ") {
				t.Errorf("unresolved basis %q must not be a link", w)
			}
			if !strings.Contains(body[i:min(len(body), i+len(w)+80)], "unresolved") {
				t.Errorf("basis %q should say unresolved", w)
			}
		}
		// A bare node id that exists in the map is a link to that node's sheet.
		if !regexp.MustCompile(`<a href="/estate/node\?g=e1&amp;id=host%3Ab\.example\.com">host:b\.example\.com</a>`).MatchString(body) {
			t.Errorf("a basis naming an existing node should link to it:\n%s", body)
		}
	}
}

func TestBasisHostileTextIsUnresolvedAndEscaped(t *testing.T) {
	_, _, body := get(t, basisHandler(), "/estate/node?g=e1&id=host:b.example.com")
	if strings.Contains(body, "<script>alert(14)") || strings.Contains(body, evilBas) {
		t.Error("hostile basis reached the page unescaped")
	}
	i := strings.Index(body, "&lt;script&gt;alert(14)")
	if i < 0 || !strings.Contains(body[i:min(len(body), i+200)], "unresolved") {
		t.Errorf("hostile basis should show escaped and unresolved:\n%s", body)
	}
}

func TestFactGroupShowsTheAssessmentsThatCiteIt(t *testing.T) {
	for _, body := range bothRenders(t, basisHandler(), estNode) {
		iP, iT := strings.Index(body, ">port.open<"), strings.Index(body, ">tech<")
		seg := body[iP:iT]
		if !strings.Contains(seg, "about-self") || !strings.Contains(seg, "analyst") || !strings.Contains(seg, "opinion") {
			t.Errorf("the port.open group should show the assessment about-self next to its facts:\n%s", seg)
		}
		if strings.Contains(seg, "cites-ip") {
			t.Error("cites-ip cites tech, not port.open")
		}
		if !strings.Contains(body[iT:], "cites-ip") {
			t.Error("the tech group should show cites-ip")
		}
	}
}
