package web

import (
	"regexp"
	"strings"
	"testing"
)

// What these tests cover: that the copy button, its status line and the record it copies
// are on the node page and in the sheet fragment, that the button starts hidden, that the
// script is a file served from this origin, and that it reads the page and writes no
// markup and sends no request. What they do not cover: that the text it builds reads well,
// that the clipboard API or the textarea fallback copies, and that the button shows after
// an htmx swap. Those run in a browser, and this repo has none in its tests.

func TestNodeSheetHasTheCopyButtonHiddenUntilScriptRuns(t *testing.T) {
	for _, body := range bothRenders(t, sheetHandler(), estNode) {
		for _, w := range []string{`id="sheet-copy"`, `id="sheet-copy-status"`, `id="sheet-record"`, `aria-live="polite"`, `type="button"`} {
			if !strings.Contains(body, w) {
				t.Errorf("sheet lacks %q", w)
			}
		}
		if !regexp.MustCompile(`<button[^>]*id="sheet-copy"[^>]*\bhidden\b`).MatchString(body) && !regexp.MustCompile(`<button[^>]*\bhidden\b[^>]*id="sheet-copy"`).MatchString(body) {
			t.Error("the copy button must start hidden")
		}
		// The button is not part of the text it copies.
		i := strings.Index(body, `id="sheet-record"`)
		if j := strings.Index(body, `id="sheet-copy"`); j > i {
			t.Error("the button must sit outside the record it copies")
		}
	}
}

func TestCopyScriptIsLoadedOnThePagesThatHaveTheSheetAndNotInTheFragment(t *testing.T) {
	h := sheetHandler()
	tag := `<script src="/static/sheet-copy.js" defer></script>`
	_, _, node := get(t, h, estNode)
	_, _, frag := getHX(t, h, estNode)
	_, _, est := get(t, h, "/estate")
	if !strings.Contains(node, tag) || !strings.Contains(est, tag) {
		t.Error("the node page and the estate page must load sheet-copy.js")
	}
	if strings.Contains(frag, "<script") {
		t.Error("the sheet fragment must carry no script")
	}
}

func TestCopyScriptIsServedFromSelfAndTouchesNoNetwork(t *testing.T) {
	code, hd, js := get(t, sheetHandler(), "/static/sheet-copy.js")
	if code != 200 || !strings.HasPrefix(hd.Get("Content-Type"), "text/javascript") || hd.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("sheet-copy.js: %d %q", code, hd.Get("Content-Type"))
	}
	for _, w := range []string{"sheet-copy", "sheet-record", "navigator.clipboard", "writeText", "textarea", "execCommand", "textContent", "htmx:afterSwap"} {
		if !strings.Contains(js, w) {
			t.Errorf("sheet-copy.js lacks %q", w)
		}
	}
	for _, bad := range []string{".innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function", "document.write", `setAttribute("style"`, "fetch(", "XMLHttpRequest", "sendBeacon", "WebSocket"} {
		if strings.Contains(js, bad) {
			t.Errorf("sheet-copy.js must not use %q", bad)
		}
	}
}
