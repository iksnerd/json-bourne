package archtest

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The docs make claims the code can check: which packages exist, what the glossary points
// at, how many operations and commands there are. A doc that says 22 when the registry
// holds 23 misleads the next reader and nothing fails, so this test fails instead. The
// checks are pure functions of text, tested against bad inline fixtures; the repo files
// are only read.
//
// archtest must not import jb or cmd/jb (it is a test of the architecture, and those
// packages pull in every adapter), so the counts come from two sources that are pinned
// elsewhere: docs/operations.json (golden-pinned against jb.Operations() in cmd/jb) for
// the operations, and the go/ast of cmd/jb for the commands that register their flags from
// an operation (calls of addOperationFlags with a literal operation name).

const repoRoot = "../.."

var (
	opsClaimRE = []*regexp.Regexp{
		regexp.MustCompile(`derive the (\w+) operations`),
		regexp.MustCompile(`each of the (\w+) operations`),
	}
	cmdsClaimRE = []*regexp.Regexp{
		regexp.MustCompile(`flags of (\w+) commands`),
		regexp.MustCompile(`(\w+) commands \([^)]*\) register their flags`),
	}
	numberWords = map[string]int{"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
		"eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19,
		"twenty": 20, "twenty-one": 21, "twenty-two": 22, "twenty-three": 23, "twenty-four": 24, "twenty-five": 25}
	backtickRE  = regexp.MustCompile("`([^`]+)`")
	mdLinkRE    = regexp.MustCompile(`\[[^\]]*\]\(([^)\s]+)\)`)
	tableSepRE  = regexp.MustCompile(`^\|[\s:|-]+\|?\s*$`)
	escapedPipe = "\x00"
)

func readRepo(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// tableRows returns the rows (cells trimmed) of the first markdown table whose header row
// starts with the given first cell. The header and the separator row are not returned.
func tableRows(body, firstHeader string) [][]string {
	var rows [][]string
	in := false
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		isRow := strings.HasPrefix(line, "|")
		if !in {
			if isRow && len(splitRow(line)) > 0 && splitRow(line)[0] == firstHeader {
				in = true
			}
			continue
		}
		if !isRow {
			break
		}
		if tableSepRE.MatchString(line) {
			continue
		}
		rows = append(rows, splitRow(line))
	}
	return rows
}

func splitRow(line string) []string {
	line = strings.ReplaceAll(line, `\|`, escapedPipe)
	line = strings.TrimSuffix(strings.TrimPrefix(line, "|"), "|")
	cells := strings.Split(line, "|")
	for i, c := range cells {
		cells[i] = strings.TrimSpace(strings.ReplaceAll(c, escapedPipe, "|"))
	}
	return cells
}

// checkPackageTable returns what is wrong with the package table of docs/ARCHITECTURE.md.
// dirs are the directories directly under internal/ (names only); exists says whether a
// repo-relative path exists.
func checkPackageTable(rows [][]string, dirs []string, exists func(string) bool) []string {
	var bad []string
	listed := map[string]bool{}
	for _, r := range rows {
		if len(r) != 3 {
			name := ""
			if len(r) > 0 {
				name = r[0]
			}
			bad = append(bad, fmt.Sprintf("package table: the row for %s has %d cells, want 3 (Package, Role, May import)", name, len(r)))
		}
		if len(r) == 0 {
			continue
		}
		m := backtickRE.FindStringSubmatch(r[0])
		if m == nil {
			bad = append(bad, fmt.Sprintf("package table: the first cell %q has no backticked package name", r[0]))
			continue
		}
		p := strings.TrimSuffix(strings.TrimSuffix(m[1], "/*"), "/")
		listed[p] = true
		if strings.HasPrefix(p, "internal/") && !exists(p) {
			bad = append(bad, fmt.Sprintf("package table: `%s` is listed but %s does not exist", m[1], p))
		}
	}
	for _, d := range dirs {
		if !listed["internal/"+d] {
			bad = append(bad, fmt.Sprintf("package table: internal/%s is a package directory but has no row (first cell)", d))
		}
	}
	return bad
}

// glossaryEntry is one row of docs/GLOSSARY.md that points at code.
type glossaryEntry struct {
	term, link string
	idents     []string
}

func parseGlossary(body string) ([]glossaryEntry, []string) {
	var out []glossaryEntry
	var bad []string
	for _, r := range tableRows(body, "Term") {
		if len(r) != 3 {
			bad = append(bad, fmt.Sprintf("glossary: the row for %q has %d cells, want 3 (Term, Meaning, Where)", r[0], len(r)))
			continue
		}
		l := mdLinkRE.FindStringSubmatchIndex(r[2])
		if l == nil {
			bad = append(bad, fmt.Sprintf("glossary: the Where cell of %q has no link: %q", r[0], r[2]))
			continue
		}
		e := glossaryEntry{term: r[0], link: r[2][l[2]:l[3]]}
		for _, m := range backtickRE.FindAllStringSubmatch(r[2][l[1]:], -1) {
			e.idents = append(e.idents, strings.TrimSuffix(m[1], "()"))
		}
		out = append(out, e)
	}
	return out, bad
}

// checkGlossary returns what is wrong with the entries. resolve maps a link to the repo
// file or directory it names and whether it exists; read returns the Go or text content
// to search for a path (for a directory, all of its files).
func checkGlossary(entries []glossaryEntry, resolve func(link string) (string, bool), read func(path string) string) []string {
	var bad []string
	for _, e := range entries {
		if strings.Contains(e.link, "://") || strings.HasPrefix(e.link, "mailto:") {
			continue
		}
		path, ok := resolve(e.link)
		if !ok {
			bad = append(bad, fmt.Sprintf("glossary: %q links to %s, which does not exist", e.term, e.link))
			continue
		}
		if len(e.idents) == 0 {
			continue
		}
		src := read(path)
		for _, id := range e.idents {
			if !regexp.MustCompile(`\b` + regexp.QuoteMeta(id) + `\b`).MatchString(src) {
				bad = append(bad, fmt.Sprintf("glossary: %q names `%s`, which is not a word in %s", e.term, id, e.link))
			}
		}
	}
	return bad
}

func numberOf(s string) (int, bool) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, true
	}
	n, ok := numberWords[strings.ToLower(s)]
	return n, ok
}

// checkCount finds every claim matching one of the patterns in body and compares it with
// want. A doc that no longer makes the claim at all is also a failure: the pattern must be
// updated with the prose, or the check silently stops checking.
func checkCount(doc, what string, res []*regexp.Regexp, body string, want int) []string {
	var bad []string
	found := 0
	for _, re := range res {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			found++
			n, ok := numberOf(m[1])
			switch {
			case !ok:
				bad = append(bad, fmt.Sprintf("%s: cannot read %q as a number of %s", doc, m[1], what))
			case n != want:
				bad = append(bad, fmt.Sprintf("%s: says %d %s, the code has %d", doc, n, what, want))
			}
		}
	}
	if found == 0 {
		bad = append(bad, fmt.Sprintf("%s: no longer states the number of %s in a form this test reads; update the patterns in docs_test.go", doc, what))
	}
	return bad
}

// operationFlagCommands returns the distinct operation names that cmd/jb passes, as a
// string literal, to addOperationFlags: one command per operation.
func operationFlagCommands(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("glob %s: %v (%d files)", dir, err, len(files))
	}
	seen := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || len(c.Args) != 2 {
				return true
			}
			if id, ok := c.Fun.(*ast.Ident); !ok || id.Name != "addOperationFlags" {
				return true
			}
			if lit, ok := c.Args[1].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				s, _ := strconv.Unquote(lit.Value)
				seen[s] = true
			}
			return true
		})
	}
	var out []string
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func TestDocCheckersFlagWhatTheyShould(t *testing.T) {
	has := func(name string, bad []string, want string) {
		t.Helper()
		for _, b := range bad {
			if strings.Contains(b, want) {
				return
			}
		}
		t.Errorf("%s: want a problem containing %q, got %v", name, want, bad)
	}

	ops := "the 22 operations"
	if bad := checkCount("d.md", "operations", opsClaimRE, "derive "+ops+" from", 22); len(bad) != 0 {
		t.Fatalf("a right count was flagged: %v", bad)
	}
	has("wrong number", checkCount("d.md", "operations", opsClaimRE, "derive the 23 operations", 22), "says 23 operations, the code has 22")
	has("wrong word", checkCount("d.md", "commands", cmdsClaimRE, "Twelve commands (a, b) register their flags", 13), "says 12 commands, the code has 13")
	if bad := checkCount("d.md", "commands", cmdsClaimRE, "Thirteen commands (a, b) register their flags", 13); len(bad) != 0 {
		t.Fatalf("a right count in words was flagged: %v", bad)
	}
	has("claim reworded away", checkCount("d.md", "operations", opsClaimRE, "there are many operations", 22), "no longer states the number")
	has("unreadable number", checkCount("d.md", "operations", opsClaimRE, "derive the several operations", 22), "cannot read")
}

// The package-table, glossary and count checkers also run the shared corpus of the
// docs-code-links skill (testdata/docs-code-links-corpus): the same inputs and expected
// problems that any other implementation of these checks must pass. A want is a substring
// that names the offender, so this file's messages may be worded differently.
type corpusFile struct {
	Cases []struct {
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
		Want  []string        `json:"want"`
	} `json:"cases"`
}

func runCorpus(t *testing.T, file string, run func(in json.RawMessage) []string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "docs-code-links-corpus", file))
	if err != nil {
		t.Fatal(err)
	}
	var cf corpusFile
	if err := json.Unmarshal(b, &cf); err != nil {
		t.Fatal(err)
	}
	if len(cf.Cases) == 0 {
		t.Fatalf("%s holds no cases", file)
	}
	for _, c := range cf.Cases {
		got := run(c.Input)
		if len(c.Want) == 0 && len(got) != 0 {
			t.Errorf("%s: want clean, got %v", c.Name, got)
		}
		for _, w := range c.Want {
			found := false
			for _, g := range got {
				found = found || strings.Contains(g, w)
			}
			if !found {
				t.Errorf("%s: want a problem containing %q, got %v", c.Name, w, got)
			}
		}
		if len(c.Want) > 0 && len(got) != len(c.Want) {
			t.Errorf("%s: want %d problems, got %d: %v", c.Name, len(c.Want), len(got), got)
		}
	}
}

func TestDocCheckersPassTheSharedCorpus(t *testing.T) {
	contains := func(list []string, s string) bool {
		for _, x := range list {
			if x == s {
				return true
			}
		}
		return false
	}
	runCorpus(t, "package_table.json", func(raw json.RawMessage) []string {
		var in struct {
			Dirs   []string
			Exists []string
			Rows   [][]string
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			t.Fatal(err)
		}
		return checkPackageTable(in.Rows, in.Dirs, func(p string) bool { return contains(in.Exists, p) })
	})
	runCorpus(t, "glossary.json", func(raw json.RawMessage) []string {
		var in struct {
			Files map[string]string
			Rows  [][]string
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			t.Fatal(err)
		}
		var body strings.Builder
		body.WriteString("| Term | Meaning | Where |\n|---|---|---|\n")
		for _, r := range in.Rows {
			body.WriteString("| " + strings.Join(r, " | ") + " |\n")
		}
		entries, bad := parseGlossary(body.String())
		resolve := func(l string) (string, bool) { _, ok := in.Files[l]; return l, ok }
		return append(bad, checkGlossary(entries, resolve, func(p string) string { return in.Files[p] })...)
	})
	runCorpus(t, "count.json", func(raw json.RawMessage) []string {
		var in struct {
			Patterns []string
			Body     string
			Want     int
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			t.Fatal(err)
		}
		var res []*regexp.Regexp
		for _, p := range in.Patterns {
			res = append(res, regexp.MustCompile(p))
		}
		return checkCount("doc", "operations", res, in.Body, in.Want)
	})
}

func TestArchitectureDocMatchesCode(t *testing.T) {
	arch := readRepo(t, "docs/ARCHITECTURE.md")
	lib := readRepo(t, "docs/LIBRARY.md")

	t.Run("package table lists every internal package and only real ones", func(t *testing.T) {
		entries, err := os.ReadDir(filepath.Join(repoRoot, "internal"))
		if err != nil {
			t.Fatal(err)
		}
		var dirs []string
		for _, e := range entries {
			if e.IsDir() {
				dirs = append(dirs, e.Name())
			}
		}
		rows := tableRows(arch, "Package")
		if len(rows) == 0 {
			t.Fatal("docs/ARCHITECTURE.md: no table with a Package column")
		}
		exists := func(p string) bool {
			_, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(p)))
			return err == nil
		}
		for _, b := range checkPackageTable(rows, dirs, exists) {
			// Rule 2 (three cells) is reported by its own subtest below.
			if !strings.Contains(b, "cells, want 3") {
				t.Error(b)
			}
		}
	})

	t.Run("every package table row has three cells", func(t *testing.T) {
		for _, r := range tableRows(arch, "Package") {
			if len(r) != 3 {
				t.Errorf("package table: the row for %s has %d cells, want 3 (Package, Role, May import)", r[0], len(r))
			}
		}
	})

	t.Run("glossary links resolve and name real identifiers", func(t *testing.T) {
		b, err := os.ReadFile(filepath.Join(repoRoot, "docs", "GLOSSARY.md"))
		if os.IsNotExist(err) {
			t.Skip("docs/GLOSSARY.md does not exist yet")
		}
		if err != nil {
			t.Fatal(err)
		}
		entries, bad := parseGlossary(string(b))
		if len(entries) == 0 && len(bad) == 0 {
			t.Fatal("docs/GLOSSARY.md: no table with a Term column")
		}
		resolve := func(link string) (string, bool) {
			link = strings.SplitN(link, "#", 2)[0]
			// A link is repo-relative; one written relative to docs/ (../x) also resolves.
			for _, base := range []string{repoRoot, filepath.Join(repoRoot, "docs")} {
				p := filepath.Join(base, filepath.FromSlash(link))
				if _, err := os.Stat(p); err == nil {
					return p, true
				}
			}
			return "", false
		}
		read := func(p string) string {
			var sb strings.Builder
			_ = filepath.WalkDir(p, func(f string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					if b, err := os.ReadFile(f); err == nil {
						sb.Write(b)
					}
				}
				return nil
			})
			return sb.String()
		}
		bad = append(bad, checkGlossary(entries, resolve, read)...)
		for _, m := range bad {
			t.Error(m)
		}
	})

	t.Run("operation and command counts match the code", func(t *testing.T) {
		var defs []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(readRepo(t, "docs/operations.json")), &defs); err != nil {
			t.Fatal(err)
		}
		cmds := operationFlagCommands(t, filepath.Join(repoRoot, "cmd", "jb"))
		for _, c := range cmds {
			found := false
			for _, d := range defs {
				found = found || d.Name == c
			}
			if !found {
				t.Errorf("cmd/jb registers flags from operation %q, which is not in docs/operations.json", c)
			}
		}
		for doc, body := range map[string]string{"docs/ARCHITECTURE.md": arch, "docs/LIBRARY.md": lib} {
			for _, m := range checkCount(doc, "operations", opsClaimRE, body, len(defs)) {
				t.Error(m)
			}
			for _, m := range checkCount(doc, "commands that register flags from an operation", cmdsClaimRE, body, len(cmds)) {
				t.Error(m)
			}
		}
	})
}
