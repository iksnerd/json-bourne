package web

import (
	"strings"
	"testing"
)

// What these tests cover: the export buttons and their script are on the page, the script
// is a file served from this origin, it makes no request of its own (so there is no route
// behind the export) and it writes no markup or style attribute. What they do not cover:
// that the downloaded SVG looks right, that the JSON holds the nodes drawn, and that the
// browser lets a blob download through the CSP. Those need a browser.

func TestEstatePageHasTheExportButtonsAndTheirScript(t *testing.T) {
	h := legendHandler(legendGraph("e1", ""))
	_, _, page := get(t, h, "/estate")
	for _, w := range []string{`id="estate-export-svg"`, `id="estate-export-json"`, `id="estate-export-status"`, `type="button"`, `<script src="/static/estate-export.js" defer></script>`} {
		if !strings.Contains(page, w) {
			t.Errorf("page lacks %q", w)
		}
	}
	// Without script a button can do nothing, so both start hidden.
	for _, id := range []string{"estate-export-svg", "estate-export-json"} {
		i := strings.Index(page, `id="`+id+`"`)
		j := strings.Index(page[i:], ">")
		if i < 0 || !strings.Contains(page[i:i+j], "hidden") {
			t.Errorf("%s must start hidden", id)
		}
	}
	if strings.Contains(page, "download=") {
		t.Error("the page itself offers no download link: the script builds the file in the browser")
	}
	_, _, frag := getHX(t, h, "/estate?kind=ip")
	if strings.Contains(frag, "estate-export") {
		t.Error("the filter fragment must not carry the export buttons")
	}
}

func TestExportScriptBuildsTheFileInTheBrowserWithoutARequest(t *testing.T) {
	h := legendHandler(legendGraph("e1", ""))
	code, hd, js := get(t, h, "/static/estate-export.js")
	if code != 200 || !strings.HasPrefix(hd.Get("Content-Type"), "text/javascript") {
		t.Fatalf("estate-export.js: %d %q", code, hd.Get("Content-Type"))
	}
	for _, w := range []string{"estate-export-svg", "estate-export-json", "Blob", "download", "svg.estate-d3", "application/json", "image/svg+xml"} {
		if !strings.Contains(js, w) {
			t.Errorf("estate-export.js lacks %q", w)
		}
	}
	for _, bad := range []string{"fetch(", "XMLHttpRequest", "sendBeacon", "WebSocket", ".innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function", "document.write", `setAttribute("style"`} {
		if strings.Contains(js, bad) {
			t.Errorf("estate-export.js must not use %q", bad)
		}
	}
}
