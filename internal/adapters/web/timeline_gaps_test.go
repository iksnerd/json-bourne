package web

import (
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// The only-gaps view (RFC 0019, Changes): render-only; it filters data the page
// already loaded.

// tlViewControl is the one line the only-gaps option adds to the default view.
var tlViewControl = regexp.MustCompile(`<p class="note" id="tl-view">.*?</p>`)

func readGolden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTimelineDefaultViewIsUnchangedExceptTheViewControl(t *testing.T) {
	_, get := tlServer(tlStore(), tlHistory())
	for target, golden := range map[string]string{
		"/timeline": "timeline_default.golden",
		"/timeline?w=7d&watcher=a&sev=high&sev=critical": "timeline_default_filtered.golden",
	} {
		_, body := get(target)
		if !tlViewControl.MatchString(body) {
			t.Fatalf("%s: no view control", target)
		}
		if got := tlViewControl.ReplaceAllString(body, ""); got != readGolden(t, golden) {
			t.Errorf("%s differs from the pre-change output beyond the view control", target)
		}
	}
}

func TestTimelineGapsViewShowsMarkersAndFindingsAndNoCycleRow(t *testing.T) {
	_, get := tlServer(tlStore(), tlHistory())
	code, body := get("/timeline?gaps=1")
	if code != 200 {
		t.Fatalf("code %d", code)
	}
	i := strings.Index(body, "<h2>Record</h2>")
	if i < 0 {
		t.Fatal("no record table")
	}
	rec := body[i:]
	// Plain cycles are hidden; the gap-reporting, INCOMPLETE and FAILED cycles stay.
	for _, hidden := range []string{"CYCLE QUIET", "CYCLE FINDINGS"} {
		if strings.Contains(rec, hidden) {
			t.Errorf("plain cycle row %q is shown", hidden)
		}
	}
	for _, kept := range []string{"CYCLE INCOMPLETE (not a quiet result); gap reported: events 2026-11-05T07:00:00Z to 2026-11-05T08:00:00Z were never examined", "CYCLE FAILED (not a quiet result)"} {
		if !strings.Contains(rec, kept) {
			t.Errorf("cycle row %q is hidden", kept)
		}
	}
	if n := strings.Count(rec, "<td>cycle</td>"); n != 2 {
		t.Errorf("%d cycle rows, want 2", n)
	}
	if n := strings.Count(rec, "<td>no cycle recorded</td>"); n != 2 {
		t.Errorf("%d markers, want 2", n)
	}
	if n := strings.Count(rec, "<td>finding</td>"); n != 2 {
		t.Errorf("%d findings, want 2", n)
	}
	for _, want := range []string{"watch.a.log from 2026-11-05T09:00:00Z to 2026-11-05T10:10:00Z", "since 2026-11-05T11:00:00Z"} {
		if !strings.Contains(rec, want) {
			t.Errorf("record lacks %q", want)
		}
	}
	if !strings.Contains(body, "older than 48h0m0s") || !strings.Contains(body, "<h2>Retention</h2>") {
		t.Error("retention horizon missing")
	}
}

func TestTimelineGapsViewCountsHiddenCyclesPerLane(t *testing.T) {
	_, get := tlServer(tlStore(), tlHistory())
	_, body := get("/timeline?gaps=1")
	for _, want := range []string{"a: 2 plain cycle row(s) hidden in this view.", "(unnamed): 1 plain cycle row(s) hidden in this view."} {
		if !strings.Contains(body, want) {
			t.Errorf("no summary %q", want)
		}
	}
	if !strings.Contains(body, "a: 2 plain cycle row(s) hidden in this view. Findings of its runs older than 48h0m0s") {
		t.Error("lane summary lacks the retention horizon")
	}
	_, one := get("/timeline?gaps=1&w=1h")
	if !strings.Contains(one, "a: 0 plain cycle row(s) hidden") {
		t.Error("1h count wrong")
	}
	_, def := get("/timeline")
	if strings.Contains(def, "hidden in this view") {
		t.Error("default view says rows are hidden")
	}
}

func TestTimelineGapsViewKeepsCutAndUnknownIntervalNotices(t *testing.T) {
	f := tlStore()
	f.page.More = true
	h := tlHistory()
	a := h.h["a"]
	a.Cut = true
	h.h["a"] = a
	u := h.h[""]
	for i := 0; i < timelineCycleRows+5; i++ {
		u.Cycles = append(u.Cycles, tlCycle(time.Duration(i+1)*time.Second, "QUIET"))
	}
	h.h[""] = u
	_, get := tlServer(f, h)
	_, all := get("/timeline")
	_, gaps := get("/timeline?gaps=1")
	for _, want := range []string{"INCOMPLETE: watch.a.log read from", "INCOMPLETE: the newest 500 cycles of (unnamed)", "INCOMPLETE: the newest 500 findings",
		"interval unknown (no readable watch-status record)", "<caption>INCOMPLETE: the list is cut"} {
		if !strings.Contains(all, want) {
			t.Fatalf("default view lacks %q, test proves nothing", want)
		}
		if !strings.Contains(gaps, want) {
			t.Errorf("gaps view lacks %q", want)
		}
	}
	if !strings.Contains(gaps, "(unnamed): 500 plain cycle row(s) hidden") {
		t.Error("hidden count is not the shown count of the cut lane")
	}
}

func TestTimelineGapsViewEscapesHostileStrings(t *testing.T) {
	f := tlStore()
	f.page.Rows[0].Detector, f.page.Rows[0].Tag, f.page.Rows[0].Summary = hostileUA, hostilePath, hostileSum
	f.page.Rows[0].Run = hostilePath
	h := tlHistory()
	h.names = append(h.names, hostilePath)
	h.h[hostilePath] = core.WatchHistory{Cycles: []core.WatchCycleLine{tlCycle(time.Hour, "QUIET")}}
	_, get := tlServer(f, h)
	for _, target := range []string{"/timeline?gaps=1", "/timeline?gaps=1&w=7d&sev=high&watcher=a&watcher=%2Fx%22onmouseover%3D"} {
		_, body := get(target)
		body = ownScript.ReplaceAllString(body, "")
		for _, bad := range rawAttack {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains raw %q", target, bad)
			}
		}
	}
	_, body := get("/timeline?gaps=1")
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("the payload did not reach the page")
	}
}

func TestTimelineGapsViewIsDeterministic(t *testing.T) {
	_, get := tlServer(tlStore(), tlHistory())
	_, a := get("/timeline?gaps=1")
	_, b := get("/timeline?gaps=1")
	if a != b {
		t.Fatal("two loads differ")
	}
	f := tlStore()
	f.page.Rows = []core.TimelineFinding{f.page.Rows[1], f.page.Rows[0]}
	h := tlHistory()
	hc := h.h["a"]
	hc.Cycles = []core.WatchCycleLine{hc.Cycles[3], hc.Cycles[1], hc.Cycles[0], hc.Cycles[2]}
	hc.Gaps = []core.WatchNoCycle{hc.Gaps[1], hc.Gaps[0]}
	h.h["a"] = hc
	_, c := tlServer(f, h)
	_, shuffled := c("/timeline?gaps=1")
	if a != shuffled {
		t.Error("shuffled input changed the gaps view")
	}
}

func TestTimelineViewLinksKeepTheOtherParameters(t *testing.T) {
	_, get := tlServer(tlStore(), tlHistory())
	_, body := get("/timeline?w=6h&watcher=a&watcher=_&sev=critical&sev=high&sev=bogus")
	if want := `href="/timeline?gaps=1&amp;sev=high&amp;sev=critical&amp;w=6h&amp;watcher=_&amp;watcher=a"`; !strings.Contains(body, want) {
		t.Errorf("only-gaps link wrong:\n%s", tlViewControl.FindString(body))
	}
	_, gaps := get("/timeline?gaps=1&w=6h&watcher=a&watcher=_&sev=critical&sev=high")
	if want := `href="/timeline?sev=high&amp;sev=critical&amp;w=6h&amp;watcher=_&amp;watcher=a"`; !strings.Contains(gaps, want) {
		t.Errorf("show-all link wrong:\n%s", tlViewControl.FindString(gaps))
	}
	if strings.Contains(tlViewControl.FindString(gaps), "gaps=1") {
		t.Error("show-all link keeps gaps")
	}
	if !strings.Contains(gaps, `<input type="hidden" name="gaps" value="1">`) {
		t.Error("form drops gaps")
	}
	if strings.Contains(body, `name="gaps"`) {
		t.Error("default form carries gaps")
	}
}

func TestTimelineGapsParameterAcceptsOnlyOne(t *testing.T) {
	_, get := tlServer(tlStore(), tlHistory())
	_, def := get("/timeline")
	for _, v := range []string{"0", "true", "2", "", "1%20", "yes"} {
		_, body := get("/timeline?gaps=" + v)
		if body != def {
			t.Errorf("gaps=%q changed the page", v)
		}
	}
	_, one := get("/timeline?gaps=1")
	_, two := get("/timeline?gaps=1&gaps=1")
	if one != two {
		t.Error("repeated gaps=1 differs")
	}
	d, _ := tlServer(tlStore(), tlHistory())
	req := httptest.NewRequest("GET", "/timeline?gaps=1", nil)
	req.Host = "127.0.0.1:8090"
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	New(d, Options{Loopback: true}).ServeHTTP(rec, req)
	if b := rec.Body.String(); strings.Contains(b, "<html") || !strings.Contains(b, "hidden in this view") || !tlViewControl.MatchString(b) {
		t.Errorf("fragment:\n%s", b)
	}
}
