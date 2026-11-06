package web

import (
	"fmt"
	"strconv"
	"strings"
)

// htmxConfig is the page's htmx configuration, set in a <meta name="htmx-config"> so no
// inline script is needed. Each key closes a way for text in a page to become code or
// to be kept: no eval (hx-on and js: triggers are refused), no script tags in a swapped
// fragment, no injected style element (the CSP allows no inline style), no history (a
// snapshot of a page of untrusted log text would be copied into the browser's
// storage), and requests to this origin only.
const htmxConfig = `{"allowEval":false,"allowScriptTags":false,"includeIndicatorStyles":false,"historyEnabled":false,"refreshOnHistoryMiss":false,"selfRequestsOnly":true}`

// escQuery percent-encodes s for use as one query-string value. Everything but the
// unreserved characters is encoded, so a stored value can never end the value or add a
// parameter. (net/url is not used here: the web adapter builds no URL it could call.)
func escQuery(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '-', ch == '.', ch == '_', ch == '~':
			b.WriteByte(ch)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[ch>>4])
			b.WriteByte(hex[ch&15])
		}
	}
	return b.String()
}

// The links the dashboard draws. They are always relative paths built here, never a
// stored value, so a link can only reach another page of this dashboard.
func runHref(id string) string { return "/run?id=" + escQuery(id) }
func nodeHref(g, id string) string {
	return "/estate/node?g=" + escQuery(g) + "&id=" + escQuery(id)
}
func edgeHref(g string, i int) string {
	return "/estate/edge?g=" + escQuery(g) + "&i=" + strconv.Itoa(i)
}
func graphHref(g string, kinds []string) string {
	return "/estate/graph.json?g=" + escQuery(g) + kindQuery(kinds)
}
func overlayHref(g, id string) string {
	return "/estate/overlay?g=" + escQuery(g) + "&id=" + escQuery(id)
}

// kindQuery is the kind filter as query-string text. The kinds were checked against the
// known list before they got here, and are encoded anyway.
func kindQuery(kinds []string) string {
	var b strings.Builder
	for _, k := range kinds {
		b.WriteString("&kind=" + escQuery(k))
	}
	return b.String()
}

// str prints any of the counters and ids a view model carries.
func str(v any) string { return fmt.Sprint(v) }

// badgeVariant keeps a badge to the variants that exist.
func badgeVariant(v string) string {
	switch v {
	case "destructive", "warning", "success":
		return v
	}
	return "outline"
}

// sevVariant maps a finding row's severity class to a badge variant.
func sevVariant(class string) string {
	switch class {
	case "bad":
		return "destructive"
	case "warn":
		return "warning"
	}
	return "outline"
}

func boolAttr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
