package web

import (
	"regexp"
	"strings"
	"testing"
)

// What these tests cover: that the search box and its script are on the page, that the
// script is a file served from this origin, and that it holds the key handling and no
// way to write markup. What they do not cover: that typing marks the right nodes, that
// "/", Escape and the arrow keys move focus as described, and that a swap by the filters
// keeps the search. Those run in a browser, and this repo has none in its tests.

func TestEstatePageHasTheSearchBoxAndItsScriptFromSelf(t *testing.T) {
	h := legendHandler(legendGraph("e1", ""))
	_, _, page := get(t, h, "/estate")
	for _, w := range []string{`id="estate-search"`, `type="search"`, `aria-controls="estate-graphs"`, `id="estate-search-status"`, `aria-live="polite"`, `<script src="/static/estate-search.js" defer></script>`} {
		if !strings.Contains(page, w) {
			t.Errorf("page lacks %q", w)
		}
	}
	// Without script the box could do nothing, so it starts hidden and the script shows it.
	if !regexp.MustCompile(`<input[^>]*id="estate-search"[^>]*\bhidden\b`).MatchString(page) && !regexp.MustCompile(`<input[^>]*\bhidden\b[^>]*id="estate-search"`).MatchString(page) {
		t.Errorf("the search box must start hidden:\n%s", page)
	}
	// It sits outside the filter form, or typing would submit the kind filter.
	if i, j := strings.Index(page, "</form>"), strings.Index(page, `id="estate-search"`); i < 0 || j < i {
		t.Errorf("the search box must come after the filter form (%d %d)", i, j)
	}
	// The filters swap #estate-graphs only; the box is not part of that fragment.
	_, _, frag := getHX(t, h, "/estate?kind=ip")
	if strings.Contains(frag, "estate-search") {
		t.Error("the filter fragment must not carry the search box")
	}
	// No inline script anywhere: every script tag has a src.
	for _, m := range regexp.MustCompile(`<script[^>]*>`).FindAllString(page, -1) {
		if !strings.Contains(m, ` src="/static/`) {
			t.Errorf("inline script tag %q", m)
		}
	}
	d := newDeps(hostileFake())
	d.Estate = nil
	_, _, none := get(t, New(d, Options{Loopback: true}), "/estate")
	if strings.Contains(none, "estate-search") {
		t.Error("no search box when the estate is not available")
	}
}

func TestSearchScriptIsServedFromSelfAndWritesNoMarkup(t *testing.T) {
	h := legendHandler(legendGraph("e1", ""))
	code, hd, js := get(t, h, "/static/estate-search.js")
	if code != 200 || !strings.HasPrefix(hd.Get("Content-Type"), "text/javascript") || hd.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("estate-search.js: %d %q", code, hd.Get("Content-Type"))
	}
	for _, w := range []string{"estate-search", `"/"`, `"Escape"`, `"ArrowDown"`, `"ArrowUp"`, "htmx:afterSwap", "textContent"} {
		if !strings.Contains(js, w) {
			t.Errorf("estate-search.js lacks %q", w)
		}
	}
	for _, bad := range []string{".innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function", "document.write", `setAttribute("style"`, "fetch(", "XMLHttpRequest"} {
		if strings.Contains(js, bad) {
			t.Errorf("estate-search.js must not use %q", bad)
		}
	}
}
