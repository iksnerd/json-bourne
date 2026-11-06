package archtest

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The RFCs in docs/rfcs are the written design of every public contract of jb (a file
// format, the plugin wire protocol, the Go API, config keys, CLI flags, the security
// policy). They only help if they are kept in one shape, so this test checks the shape:
// a number that matches the file name, a status from the list, an acceptance date when
// the status needs one, the sections a reviewer looks for, and links that resolve.

var (
	rfcStatuses     = map[string]bool{"draft": true, "accepted": true, "implemented": true, "superseded": true, "withdrawn": true}
	rfcNeedsDate    = map[string]bool{"accepted": true, "implemented": true, "superseded": true}
	rfcSections     = []string{"Summary", "Motivation", "Conventions", "Non-goals", "Drawbacks", "Compatibility", "Security considerations", "Open questions"}
	rfcTitleRE      = regexp.MustCompile(`^# RFC (\d{4}): \S.*$`)
	rfcStatusRE     = regexp.MustCompile(`(?m)^Status: (\S+)\s*$`)
	rfcAcceptedRE   = regexp.MustCompile(`(?m)^Accepted: (\d{4}-\d{2}-\d{2}) by the maintainer\s*$`)
	rfcFileRE       = regexp.MustCompile(`^(\d{4})-[a-z0-9]+(-[a-z0-9]+)*\.md$`)
	mdRelativeLinks = regexp.MustCompile(`\]\(([^)#:]+?)(#[^)]*)?\)`)
)

// checkRFC returns what is wrong with one RFC. name is the file name, dir the folder the
// relative links are checked against.
func checkRFC(name, dir, body string) []string {
	var bad []string
	m := rfcFileRE.FindStringSubmatch(name)
	if m == nil {
		return []string{name + ": the file name must be NNNN-short-title.md"}
	}
	first := strings.SplitN(body, "\n", 2)[0]
	t := rfcTitleRE.FindStringSubmatch(first)
	switch {
	case t == nil:
		bad = append(bad, name+": the first line must be `# RFC NNNN: title`")
	case t[1] != m[1]:
		bad = append(bad, fmt.Sprintf("%s: the title says RFC %s and the file name says %s", name, t[1], m[1]))
	}
	st := rfcStatusRE.FindStringSubmatch(body)
	switch {
	case st == nil:
		bad = append(bad, name+": no `Status:` line")
	case !rfcStatuses[st[1]]:
		bad = append(bad, fmt.Sprintf("%s: status %q is not one of draft, accepted, implemented, superseded, withdrawn", name, st[1]))
	case rfcNeedsDate[st[1]] && !rfcAcceptedRE.MatchString(body):
		bad = append(bad, fmt.Sprintf("%s: status %s needs a line `Accepted: YYYY-MM-DD by the maintainer`", name, st[1]))
	case st[1] == "draft" && rfcAcceptedRE.MatchString(body):
		bad = append(bad, name+": a draft must not carry an acceptance date")
	}
	for _, s := range rfcSections {
		if !regexp.MustCompile(`(?m)^## ` + regexp.QuoteMeta(s) + `\s*$`).MatchString(body) {
			bad = append(bad, fmt.Sprintf("%s: no `## %s` section", name, s))
		}
	}
	for _, l := range mdRelativeLinks.FindAllStringSubmatch(body, -1) {
		if strings.HasPrefix(l[1], "http") || strings.HasPrefix(l[1], "mailto") {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(l[1]))); err != nil {
			bad = append(bad, fmt.Sprintf("%s: the link to %s does not resolve", name, l[1]))
		}
	}
	return bad
}

func goodRFC(n, status string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# RFC %s: A title\nStatus: %s\nScope: one line\n", n, status)
	if status != "draft" && status != "withdrawn" {
		b.WriteString("Accepted: 2026-11-06 by the maintainer\n")
	}
	for _, s := range rfcSections {
		fmt.Fprintf(&b, "\n## %s\n\ntext\n", s)
	}
	return b.String()
}

func TestRFCCheckerFlagsWhatItShould(t *testing.T) {
	dir := t.TempDir()
	if bad := checkRFC("0007-a-title.md", dir, goodRFC("0007", "draft")); len(bad) != 0 {
		t.Fatalf("a well-formed RFC was flagged: %v", bad)
	}
	if bad := checkRFC("0007-a-title.md", dir, goodRFC("0007", "implemented")); len(bad) != 0 {
		t.Fatalf("a well-formed implemented RFC was flagged: %v", bad)
	}
	for name, c := range map[string]struct{ file, body, want string }{
		"bad file name":      {"rfc7.md", goodRFC("0007", "draft"), "file name must be"},
		"number mismatch":    {"0008-a-title.md", goodRFC("0007", "draft"), "title says RFC 0007"},
		"no title":           {"0007-a-title.md", strings.Replace(goodRFC("0007", "draft"), "# RFC 0007: A title", "A title", 1), "first line must be"},
		"unknown status":     {"0007-a-title.md", strings.Replace(goodRFC("0007", "draft"), "Status: draft", "Status: maybe", 1), "not one of"},
		"no status":          {"0007-a-title.md", strings.Replace(goodRFC("0007", "draft"), "Status: draft\n", "", 1), "no `Status:` line"},
		"accepted, no date":  {"0007-a-title.md", strings.Replace(goodRFC("0007", "accepted"), "Accepted: 2026-11-06 by the maintainer\n", "", 1), "needs a line `Accepted"},
		"draft with a date":  {"0007-a-title.md", strings.Replace(goodRFC("0007", "draft"), "Scope: one line\n", "Scope: one line\nAccepted: 2026-11-06 by the maintainer\n", 1), "must not carry an acceptance date"},
		"missing section":    {"0007-a-title.md", strings.Replace(goodRFC("0007", "draft"), "## Drawbacks", "## Costs", 1), "no `## Drawbacks` section"},
		"dead relative link": {"0007-a-title.md", goodRFC("0007", "draft") + "\nSee [it](nope/missing.md).\n", "does not resolve"},
	} {
		bad := checkRFC(c.file, dir, c.body)
		found := false
		for _, b := range bad {
			found = found || strings.Contains(b, c.want)
		}
		if !found {
			t.Errorf("%s: want a problem containing %q, got %v", name, c.want, bad)
		}
	}
}

func TestRFCsAreWellFormed(t *testing.T) {
	dir := filepath.Join("..", "..", "docs", "rfcs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".md") || n == "README.md" || n == "0000-template.md" {
			continue
		}
		names = append(names, n)
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range checkRFC(n, dir, string(b)) {
			t.Error(bad)
		}
		if num := n[:4]; seen[num] != "" {
			t.Errorf("RFC %s is in two files: %s and %s", num, seen[num], n)
		} else {
			seen[num] = n
		}
	}
	sort.Strings(names)
	// The template is not an RFC, but it is the form every RFC is checked against: it must
	// itself pass, as a draft numbered 0000.
	if b, err := os.ReadFile(filepath.Join(dir, "0000-template.md")); err != nil {
		t.Errorf("docs/rfcs/0000-template.md is missing: %v", err)
	} else {
		body := strings.ReplaceAll(string(b), "# RFC 0000: <title>", "# RFC 0000: template")
		for _, bad := range checkRFC("0000-template.md", dir, body) {
			t.Errorf("the template does not pass its own check: %s", bad)
		}
	}
}
