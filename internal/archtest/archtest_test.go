// Package archtest fails the build when a package imports what the architecture
// forbids. Each rule says why, so a failure explains itself.
package archtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const mod = "github.com/iksnerd/json-bourne"

type rule struct {
	pkg        string   // package under test, relative to the module
	forbid     []string // import path prefixes it must not use
	forbidEq   []string // import paths it must not use, exactly (for "net" without net/netip)
	stdlibOnly bool
	why        string
}

var rules = []rule{
	{pkg: "internal/core", stdlibOnly: true, why: "the domain depends on nothing"},
	{pkg: "internal/adapters/kibana", forbid: []string{mod + "/internal/adapters/greynoise", mod + "/internal/adapters/webhook", mod + "/internal/adapters/duckdb", mod + "/internal/app", "github.com/spf13/cobra", "github.com/duckdb"}, why: "adapters depend on core only and never on each other"},
	{pkg: "internal/logmap/keycloak", forbid: []string{mod + "/internal/adapters", mod + "/internal/app", mod + "/internal/config", mod + "/internal/casefile", "github.com/spf13", "github.com/duckdb", "gopkg.in/", "net/http", "net/url", "os", "io/ioutil", "log", "unsafe", "plugin", "runtime", "sync", "math/rand", "crypto/rand"}, forbidEq: []string{"net", "io/fs", "reflect"}, why: "a log mapper is a pure function of the document bytes (core and the standard library only; no file, network, process, clock source, randomness or shared state), so a separate-process mapper can be proven identical on the same corpus"},
	{pkg: "internal/logmap/requestdump", forbid: []string{mod + "/internal/adapters", mod + "/internal/app", mod + "/internal/config", mod + "/internal/casefile", "github.com/spf13", "github.com/duckdb", "gopkg.in/", "net/http", "net/url", "os", "io/ioutil", "log", "unsafe", "plugin", "runtime", "sync", "math/rand", "crypto/rand"}, forbidEq: []string{"net", "io/fs", "reflect"}, why: "a log mapper is a pure function of the document bytes (core and the standard library only; no file, network, process, clock source, randomness or shared state), so a separate-process mapper can be proven identical on the same corpus"},
	{pkg: "internal/adapters/duckdb", forbid: []string{mod + "/internal/adapters/greynoise", mod + "/internal/adapters/webhook", mod + "/internal/adapters/kibana", mod + "/internal/app", "github.com/spf13/cobra", "net/http"}, why: "adapters depend on core only; storage has no network"},
	{pkg: "internal/adapters/alertlog", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/adapters/kibana", mod + "/internal/adapters/duckdb", "github.com/spf13/cobra", "net", "os/exec"}, why: "the local alert adapter depends on core only and sends nothing over a network; a network sink is a separate adapter or plugin"},
	{pkg: "internal/adapters/watchstate", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/adapters/kibana", mod + "/internal/adapters/duckdb", "github.com/spf13/cobra", "net", "os/exec"}, why: "the watch state file adapter depends on core only and has no network"},
	{pkg: "internal/adapters/watchstatus", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/adapters", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "net", "os/exec"}, why: "the watch status file adapter depends on core only, has no network and no process, and holds names, counts and times, so a credential has no path into the record"},
	{pkg: "internal/adapters/runlock", forbid: []string{mod + "/internal", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "net", "os/exec", "log"}, why: "the run lock is a file lock and a PID: the standard library only, no network, no process, no log, and it knows nothing of the domain, so it cannot leak what a case holds"},
	{pkg: "internal/adapters/detectors/authspike", stdlibOnly: false, forbid: []string{mod + "/internal/adapters/greynoise", mod + "/internal/adapters/kibana", mod + "/internal/adapters/duckdb", mod + "/internal/app", "github.com/spf13/cobra", "github.com/duckdb", "net/http", "os/exec"}, why: "a detector is pure: it reads through core.EventReader and touches nothing else"},
	{pkg: "internal/adapters/detectors/signup", forbid: []string{mod + "/internal/adapters", mod + "/internal/casefile", mod + "/internal/config", mod + "/internal/app", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "net/http", "os"}, why: "a detector is pure: it reads through core.EventReader and touches nothing else (no files, no processes, no network)"},
	{pkg: "internal/adapters/detectors/newkey", forbid: []string{mod + "/internal/adapters", mod + "/internal/casefile", mod + "/internal/config", mod + "/internal/app", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "net/http", "os"}, why: "a detector is pure: it reads through core.EventReader and touches nothing else (no files, no processes, no network)"},
	{pkg: "internal/adapters/detectors/signature", forbid: []string{mod + "/internal/adapters", mod + "/internal/casefile", mod + "/internal/config", mod + "/internal/app", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "net/http", "os"}, why: "a detector is pure: it reads through core.EventReader and touches nothing else (no files, no processes, no network)"},
	{pkg: "internal/adapters/detectors/behaviour", forbid: []string{mod + "/internal/adapters", mod + "/internal/casefile", mod + "/internal/config", mod + "/internal/app", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "net/http", "os"}, why: "a detector is pure: it reads through core.EventReader and touches nothing else (no files, no processes, no network)"},
	{pkg: "internal/adapters/detectors/fingerprint", forbid: []string{mod + "/internal/adapters", mod + "/internal/casefile", mod + "/internal/config", mod + "/internal/app", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "net/http", "os"}, why: "a detector is pure: it reads through core.EventReader and touches nothing else (no files, no processes, no network); the actor file is read by internal/config and handed over as plain values"},
	{pkg: "internal/adapters/greynoise", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/casefile", mod + "/internal/adapters/kibana", mod + "/internal/adapters/duckdb", mod + "/internal/adapters/alertlog", mod + "/internal/adapters/watchstate", mod + "/internal/adapters/webhook", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "os/exec", "os"}, why: "the reputation feed adapter depends on core and the standard library only; net/http is allowed here and nowhere else outside kibana"},
	{pkg: "internal/adapters/sansisc", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/casefile", mod + "/internal/adapters", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "os/exec", "os"}, why: "the SANS ISC reputation feed depends on core and the standard library only, reads no file or environment and starts no process; net/http is allowed here and in the other remote adapters only"},
	{pkg: "internal/adapters/dnsbl", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/casefile", mod + "/internal/adapters", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "os/exec", "os", "net/http"}, why: "the DNSBL reputation feed depends on core and the standard library only and asks a DNS resolver through an injected port; it has no HTTP, reads no file or environment and starts no process"},
	{pkg: "internal/adapters/webhook", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/casefile", mod + "/internal/adapters", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "os/exec", "os", "path/filepath", "log"}, why: "the webhook alert adapter depends on core and the standard library only; it reads no file and no environment (the config layer hands it the URL), starts no process and writes no log, so the URL has nowhere to leak; net/http is allowed here and nowhere else outside kibana and greynoise"},
	{pkg: "internal/adapters/rdap", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/casefile", mod + "/internal/adapters/kibana", mod + "/internal/adapters/duckdb", mod + "/internal/adapters/greynoise", mod + "/internal/adapters/alertlog", mod + "/internal/adapters/webhook", mod + "/internal/adapters/watchstate", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "os/exec", "os", mod + "/internal/adapters/dnsptr"}, why: "the RDAP adapter depends on core and the standard library only; net/http is allowed here and in the other remote adapters only"},
	{pkg: "internal/adapters/dnsptr", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/casefile", mod + "/internal/adapters/kibana", mod + "/internal/adapters/duckdb", mod + "/internal/adapters/greynoise", mod + "/internal/adapters/alertlog", mod + "/internal/adapters/webhook", mod + "/internal/adapters/watchstate", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "os/exec", "os", mod + "/internal/adapters/rdap", "net/http"}, why: "the PTR adapter depends on core and the standard library only and asks a DNS resolver through an injected net.Resolver; it has no HTTP"},
	{pkg: "internal/adapters/web", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/casefile", mod + "/internal/adapters", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "database/sql", "os", "os/exec", "path/filepath", "io/ioutil", "log", "crypto/tls", "net/http/httputil", "net/http/httptest", "net/rpc", "net/smtp", "net/url"}, why: "the dashboard is a serving adapter: core and the standard library only; it reads the evidence through core ports, so it has no SQL, no file and no process access, and it never calls out (net/http client symbols are banned by TestWebAdapterIsServingOnly)"},
	{pkg: "internal/estategraph", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/casefile", mod + "/internal/adapters", mod + "/internal/watchrun", "github.com/spf13/cobra", "github.com/duckdb", "github.com/a-h/templ", "gopkg.in/yaml", "net", "net/http", "net/url", "os", "os/exec", "io/ioutil", "log", "unsafe", "reflect", "html/template"}, why: "the estate graph model is a pure function of core.EstateGraph (core, the standard library and the graph library only): it reads no file, store or request and never prints, so the page that prints a label keeps the escaping"},
	{pkg: "internal/adapters/bgp", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/casefile", mod + "/internal/adapters", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "os/exec", "os"}, why: "the BGP adapter depends on core and the standard library only; net/http is allowed here and in the other remote adapters only"},
	{pkg: "internal/adapters/crtsh", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/casefile", mod + "/internal/adapters", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "os/exec", "os"}, why: "the certificate transparency adapter depends on core and the standard library only; net/http is allowed here and in the other remote adapters only"},
	{pkg: "internal/adapters/dnsfwd", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/casefile", mod + "/internal/adapters", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "os/exec", "os", "net/http"}, why: "the forward-DNS adapter depends on core and the standard library only and asks a DNS resolver through an injected net.Resolver; it has no HTTP"},
	{pkg: "internal/ops", stdlibOnly: true, why: "an operation definition, its reflector and its argument check are pure: the standard library only, so the command line, the Go API and an MCP server can all depend on one definition without pulling in each other"},
	{pkg: "internal/piiguard", stdlibOnly: true, why: "the shared personal-field list and key digest is imported by detectors, so it depends on the standard library alone"},
	{pkg: "internal/adapters/plugin", forbid: []string{mod + "/internal/app", mod + "/internal/config", mod + "/internal/casefile", mod + "/internal/adapters", mod + "/plugins", "github.com/spf13/cobra", "github.com/duckdb", "net", "log"}, why: "the plugin host depends on core, yaml and the standard library only; it is the one package that starts a process (TestOSExecIsConfined) and it opens no network connection and writes no log, so nothing it holds can leave the machine"},
	{pkg: "internal/casefile", forbid: []string{mod + "/internal", "github.com/spf13/cobra", "net/http", "github.com/duckdb"}, why: "the case format is data: it imports the standard library and yaml only (os/exec is confined to guard.go, which a package-level test cannot see)"},
	{pkg: "internal/app", forbid: []string{mod + "/internal/adapters", mod + "/internal/config", "github.com/spf13/cobra", "github.com/duckdb", "gopkg.in/yaml", "net/http", "database/sql"}, why: "use cases see ports, never adapters, config, transport or storage"},
	{pkg: "internal/config", forbid: []string{mod + "/internal/app", "github.com/spf13/cobra"}, why: "config builds adapters; it does not run use cases or know the CLI"},
}

func imports(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-f", `{{join .Imports "\n"}}`, mod+"/"+pkg).Output()
	if err != nil {
		t.Fatalf("go list %s: %v", pkg, err)
	}
	return strings.Fields(string(out))
}

func TestDependencyRules(t *testing.T) {
	for _, r := range rules {
		t.Run(r.pkg, func(t *testing.T) {
			got := imports(t, r.pkg)
			for _, imp := range got {
				if r.stdlibOnly && strings.Contains(strings.SplitN(imp, "/", 2)[0], ".") {
					t.Errorf("%s imports %s: %s", r.pkg, imp, r.why)
				}
				for _, f := range r.forbidEq {
					if imp == f {
						t.Errorf("%s imports %s: %s", r.pkg, imp, r.why)
					}
				}
				for _, f := range r.forbid {
					if strings.HasPrefix(imp, f) {
						t.Errorf("%s imports %s: %s", r.pkg, imp, r.why)
					}
				}
			}
		})
	}
}

// netHTTPAllowed are the only packages that may import net/http: the adapters that
// call a remote API (kibana, greynoise, sansisc, rdap, bgp and crtsh, which ask a registry or a
// public data service and never the address or domain they are asked about, and the alert webhook). Everything else (core, app, storage, detectors, config, the case
// format) has no network.
var netHTTPAllowed = map[string]bool{
	mod + "/internal/adapters/kibana":    true,
	mod + "/internal/adapters/greynoise": true,
	mod + "/internal/adapters/sansisc":   true,
	mod + "/internal/adapters/webhook":   true,
	mod + "/internal/adapters/rdap":      true,
	mod + "/internal/adapters/bgp":       true,
	mod + "/internal/adapters/crtsh":     true,
}

// netHTTPServing may import net/http to answer requests, never to make them. The web
// dashboard is the one: TestWebAdapterIsServingOnly checks which net/http and net
// symbols it uses.
var netHTTPServing = map[string]bool{
	mod + "/internal/adapters/web": true,
	// The root package returns the dashboard as an http.Handler (dashboard.go). It
	// uses the type only; it builds no client.
	mod: true,
}

func TestNetHTTPIsConfinedToTheRemoteAdapters(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .Imports " "}}`, mod+"/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		for _, imp := range f[1:] {
			if imp != "net/http" {
				continue
			}
			seen[f[0]] = true
			if !netHTTPAllowed[f[0]] && !netHTTPServing[f[0]] {
				t.Errorf("%s imports net/http: only the remote adapters (and the serving dashboard) may", f[0])
			}
		}
	}
	for pkg := range netHTTPAllowed {
		if !seen[pkg] {
			t.Errorf("%s was not found importing net/http: the confinement test is looking at the wrong thing", pkg)
		}
	}
}

// A reputation snapshot is context, not attribution (CDN edge addresses carry the
// reputation of the edge, not of the visitor). The hunt and its detectors must never
// read it, so it can never move a finding's severity.
func TestReputationNeverReachesDetectorsOrTheHunt(t *testing.T) {
	root := filepath.Join("..", "..")
	var files []string
	for _, pat := range []string{"internal/adapters/detectors/*/*.go", "internal/app/hunt.go", "internal/app/watch.go"} {
		m, err := filepath.Glob(filepath.Join(root, pat))
		if err != nil || len(m) == 0 {
			t.Fatalf("glob %s: %v (%d files)", pat, err, len(m))
		}
		files = append(files, m...)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{"core.Reputation", "core.Feed", "Reputation(", "AppendReputation", "greynoise", "sansisc", "dnsbl"} {
			if strings.Contains(string(b), banned) {
				t.Errorf("%s mentions %s: reputation must not feed a detector, a severity or the hunt", f, banned)
			}
		}
	}
}

// servingHTTPSymbols and servingNetSymbols are the only net/http and net identifiers
// a serving adapter may use. They are an allowlist, so a client call the next
// contributor reaches for (http.Get, http.Client, http.NewRequest, http.Transport,
// net.Dial, net.LookupHost, ...) fails the build instead of being argued about in review.
// Constants Status* and Method* are allowed by prefix.
var servingHTTPSymbols = map[string]bool{
	"Handler": true, "HandlerFunc": true, "ServeMux": true, "NewServeMux": true, "ResponseWriter": true,
	"Request": true, "Header": true, "Server": true, "Error": true, "ErrServerClosed": true,
	"TimeoutHandler": true,
}

var servingNetSymbols = map[string]bool{
	"Listener": true, "SplitHostPort": true, "JoinHostPort": true,
}

// clientSymbolsIn parses the non-test Go files of dir and returns every use of a
// net/http or net identifier outside the serving allowlists, as "file:line http.Get".
func clientSymbolsIn(t *testing.T, dir string) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}
	var bad []string
	files := 0
	for _, p := range pkgs {
		for name, f := range p.Files {
			files++
			names := map[string]string{} // local import name -> path
			for _, im := range f.Imports {
				path := strings.Trim(im.Path.Value, `"`)
				local := path[strings.LastIndex(path, "/")+1:]
				if im.Name != nil {
					local = im.Name.Name
				}
				if path == "net/http" || path == "net" {
					names[local] = path
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				path, ok := names[id.Name]
				if !ok {
					return true
				}
				sym := sel.Sel.Name
				allowed := false
				switch path {
				case "net/http":
					allowed = servingHTTPSymbols[sym] || strings.HasPrefix(sym, "Status") || strings.HasPrefix(sym, "Method")
				case "net":
					allowed = servingNetSymbols[sym]
				}
				if !allowed {
					bad = append(bad, fmt.Sprintf("%s:%d %s.%s", filepath.Base(name), fset.Position(sel.Pos()).Line, id.Name, sym))
				}
				return true
			})
		}
	}
	if files == 0 {
		t.Fatalf("no Go files found in %s: the scan is looking at the wrong place", dir)
	}
	sort.Strings(bad)
	return bad
}

// The scanner must flag a client; otherwise a clean result on the real package means nothing.
func TestServingScannerFlagsClientSymbols(t *testing.T) {
	dir := t.TempDir()
	src := `package x
import ("net"; "net/http")
func f() { _, _ = http.Get("http://192.0.2.1"); _ = &http.Client{}; _, _ = net.Dial("tcp", "192.0.2.1:80"); _, _ = http.NewRequest("GET", "", nil); _ = http.DefaultTransport; var _ http.Handler; var _ net.Listener }
`
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(clientSymbolsIn(t, dir), " ")
	for _, want := range []string{"http.Get", "http.Client", "net.Dial", "http.NewRequest", "http.DefaultTransport"} {
		if !strings.Contains(got, want) {
			t.Errorf("scanner missed %s (got %q)", want, got)
		}
	}
	if strings.Contains(got, "http.Handler") || strings.Contains(got, "net.Listener") {
		t.Errorf("scanner flagged a serving symbol: %q", got)
	}
}

// The dashboard shows attacker-controlled text. templ escapes every { value } for the
// place it lands in; these are the ways to turn that off or to run text as code, and none
// of them may appear in the adapter's own sources (generated files are the compiler's
// output of those sources, so they are covered by the .templ scan).
func TestWebAdapterHasNoRawHTMLOrScriptEscapeHatch(t *testing.T) {
	dir := filepath.Join("..", "adapters", "web")
	banned := []string{"templ.Raw", "templ.SafeURL", "templ.ComponentScript", "templ.JSFuncCall", "templ.JSONScript", "templ.Script", "templ.SafeScript", "templ.SafeCSS", "template.HTML", "template.JS", "template.URL", "unsafe.", "@templ."}
	n := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		name := d.Name()
		if strings.HasSuffix(name, "_templ.go") || strings.HasSuffix(name, "_test.go") || !(strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".templ")) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		n++
		for _, bad := range banned {
			for i, line := range strings.Split(string(b), "\n") {
				if t := strings.TrimSpace(line); strings.HasPrefix(t, "//") {
					continue
				}
				if strings.Contains(line, bad) {
					t.Errorf("%s:%d uses %s: text from the evidence would reach the page unescaped or as code", p, i+1, bad)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 6 {
		t.Fatalf("only %d web sources scanned: the guard is looking at the wrong place", n)
	}
}

func TestWebAdapterIsServingOnly(t *testing.T) {
	if bad := clientSymbolsIn(t, filepath.Join("..", "adapters", "web")); len(bad) > 0 {
		t.Errorf("the web adapter serves and never calls out, but uses: %s", strings.Join(bad, ", "))
	}
}

// adaptersDir is internal/adapters from the test's directory.
var adaptersDir = filepath.Join("..", "adapters")

// feedAdapters returns the adapter packages that implement core.Feed, found by the
// compile-time assertion every feed adapter carries, not by a list kept here. A new
// reputation feed is therefore covered by the tests below without anyone remembering to.
func feedAdapters(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(adaptersDir, "*", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("glob adapters: %v (%d files)", err, len(files))
	}
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "core.Feed = ") {
			seen[filepath.Base(filepath.Dir(f))] = true
		}
	}
	var out []string
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// The scan must find the feeds that exist, or "every feed is covered" proves nothing.
func TestFeedAdapterDiscoveryFindsTheKnownFeeds(t *testing.T) {
	got := strings.Join(feedAdapters(t), ",")
	for _, want := range []string{"greynoise", "sansisc", "dnsbl"} {
		if !strings.Contains(got, want) {
			t.Errorf("feed adapter %s not discovered (got %s)", want, got)
		}
	}
}

// Every feed adapter has its own dependency rule; nothing applies a default to a
// package without an entry.
func TestEveryFeedAdapterHasADependencyRule(t *testing.T) {
	ruled := map[string]bool{}
	for _, r := range rules {
		ruled[r.pkg] = true
	}
	for _, d := range feedAdapters(t) {
		if !ruled["internal/adapters/"+d] {
			t.Errorf("feed adapter %s has no rule in archtest", d)
		}
	}
}

// Reputation is context, not attribution: no feed adapter may be imported by a
// detector, by the use cases (which hold the hunt and the watch) or by the evidence
// store. Only the composition roots wire a feed.
func TestNoFeedAdapterIsImportedByADetectorTheHuntOrTheStore(t *testing.T) {
	feeds := feedAdapters(t)
	detectors, err := filepath.Glob(filepath.Join(adaptersDir, "detectors", "*"))
	if err != nil || len(detectors) == 0 {
		t.Fatalf("glob detectors: %v", err)
	}
	pkgs := []string{"internal/app", "internal/adapters/duckdb", "internal/adapters/alertlog", "internal/adapters/watchstate", "internal/adapters/web"}
	for _, d := range detectors {
		pkgs = append(pkgs, "internal/adapters/detectors/"+filepath.Base(d))
	}
	for _, pkg := range pkgs {
		for _, imp := range imports(t, pkg) {
			for _, f := range feeds {
				if imp == mod+"/internal/adapters/"+f {
					t.Errorf("%s imports the feed adapter %s: reputation must not feed a detector, a severity or the hunt", pkg, f)
				}
			}
		}
	}
}

// Adapters implement core ports and know nothing of each other. Sub-packages of one
// adapter (the detectors tree) may share their parent.
func TestAdaptersNeverImportEachOther(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .Imports " "}}`, mod+"/internal/adapters/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	prefix := mod + "/internal/adapters/"
	top := func(p string) string { return strings.SplitN(strings.TrimPrefix(p, prefix), "/", 2)[0] }
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		n++
		for _, imp := range f[1:] {
			if strings.HasPrefix(imp, prefix) && top(imp) != top(f[0]) {
				t.Errorf("%s imports %s: adapters depend on core only and never on each other", f[0], imp)
			}
		}
	}
	if n < 10 {
		t.Fatalf("only %d adapter packages listed: the scan is looking at the wrong thing", n)
	}
}

// osExecAllowed are the only packages that may import os/exec. internal/adapters/plugin
// starts the operator's allowlisted plugins; internal/casefile asks git whether the
// evidence directory is ignored. Everything else (core, app, config, every other
// adapter, the detectors) starts no process.
var osExecAllowed = map[string]bool{
	mod + "/internal/adapters/plugin": true,
	mod + "/internal/casefile":        true,
}

func TestOSExecIsConfined(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .Imports " "}}`, mod+"/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		for _, imp := range f[1:] {
			if imp != "os/exec" {
				continue
			}
			seen[f[0]] = true
			if !osExecAllowed[f[0]] {
				t.Errorf("%s imports os/exec: only the plugin host (and the case git guard) may start a process", f[0])
			}
		}
	}
	for pkg := range osExecAllowed {
		if !seen[pkg] {
			t.Errorf("%s was not found importing os/exec: the confinement test is looking at the wrong thing", pkg)
		}
	}
}

// badPluginImports returns the imports a plugin package must not have: anything that is
// not the standard library or the public sdk, and the standard library's ways out of the
// process (network, exec). The examples are what operators copy, so they stay inert.
func badPluginImports(imports []string) []string {
	var bad []string
	for _, imp := range imports {
		first := strings.SplitN(imp, "/", 2)[0]
		switch {
		case imp == mod+"/sdk":
		case strings.Contains(first, "."):
			bad = append(bad, imp+" (not the standard library)")
		case imp == "os/exec" || imp == "net" || (strings.HasPrefix(imp, "net/") && imp != "net/netip") || imp == "syscall" || imp == "plugin" || imp == "unsafe":
			bad = append(bad, imp+" (a way out of the process)")
		}
	}
	return bad
}

func TestPluginsAreStdlibOnlyAndInert(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}}`, mod+"/plugins/...", mod+"/sdk").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		n++
		for _, b := range badPluginImports(f[1:]) {
			t.Errorf("%s imports %s", f[0], b)
		}
	}
	if n < 4 {
		t.Fatalf("only %d plugin packages listed (want the sdk and three examples): the scan is looking at the wrong thing", n)
	}
}

func TestPluginScannerFlagsWhatItShould(t *testing.T) {
	got := strings.Join(badPluginImports([]string{"fmt", "encoding/json", mod + "/sdk", "github.com/x/y", mod + "/internal/core", "os/exec", "net/http", "net", "syscall"}), "|")
	for _, want := range []string{"github.com/x/y", mod + "/internal/core", "os/exec", "net/http", "net ", "syscall"} {
		if !strings.Contains(got, want) {
			t.Errorf("scanner missed %s (got %q)", want, got)
		}
	}
	if strings.Contains(got, "fmt") || strings.Contains(got, "sdk") || strings.Contains(got, "encoding/json") {
		t.Errorf("scanner flagged an allowed import: %q", got)
	}
}

// The plugins are separate programs. jb never links them: a plugin that jb imported
// would run inside the binary, not behind the host's limits.
func TestNothingImportsThePlugins(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}}`, mod+"/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if strings.HasPrefix(f[0], mod+"/plugins") {
			continue
		}
		n++
		for _, imp := range f[1:] {
			if strings.HasPrefix(imp, mod+"/plugins") {
				t.Errorf("%s imports %s: plugins are child processes, never linked into jb", f[0], imp)
			}
		}
	}
	if n < 20 {
		t.Fatalf("only %d packages scanned", n)
	}
}
