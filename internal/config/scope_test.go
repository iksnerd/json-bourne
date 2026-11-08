package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const scopeHead = `
sources:
  - {type: kibana, name: ingress, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: ingress-*, mapper: nginx_ingress, filter: [{match_phrase: {field: message, value: token}}]}
  - {type: kibana, name: kc, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: kc-*, mapper: keycloak%s}
detectors:
`

func scopeCfg(kcFilter, detectors string) string {
	return strings.Replace(scopeHead, "%s", kcFilter, 1) + detectors
}

const kcFiltered = `, filter: [{match_phrase: {field: message, value: REGISTER}}]`

const kcSignup = "  - {type: signup, name: kc-signup, event_field: event_type, create_values: [REGISTER], attempt_values: [REGISTER_ERROR]%s}\n"

func TestDetectorSourcesAreScopedAtBuild(t *testing.T) {
	f, err := Parse([]byte(scopeCfg("", strings.Replace(kcSignup, "%s", ", sources: [kc]", 1)+
		"  - {type: authspike, name: wide, key_field: client_ip, status_field: status}\n")))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": "k"}))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"kc-signup": {"kc"}}
	if !reflect.DeepEqual(rt.Scopes, want) {
		t.Errorf("Scopes = %v, want %v (a detector without sources: has no entry)", rt.Scopes, want)
	}
}

func TestDetectorSourcesAreRefusedWhenWrong(t *testing.T) {
	for name, tc := range map[string]struct{ sources, want string }{
		"unknown name":    {"sources: [kc, typo]", `unknown source "typo"`},
		"empty list":      {"sources: []", "empty list"},
		"not a list":      {"sources: kc", "list of source names"},
		"null":            {"sources: ~", "list of source names"},
		"duplicate name":  {"sources: [kc, kc]", `"kc" twice`},
		"default name":    {"sources: ['kibana:kc-*']", "unknown source"}, // kc has an explicit name
		"nested mapping":  {"sources: [{a: b}]", "list of source names"},
		"typo in the key": {"source: [kc]", "source"},
	} {
		_, err := Parse([]byte(scopeCfg("", strings.Replace(kcSignup, "%s", ", "+tc.sources, 1))))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want one containing %q", name, err, tc.want)
		}
	}
	// The error names the detector, its type and the bad name.
	_, err := Parse([]byte(scopeCfg("", strings.Replace(kcSignup, "%s", ", sources: [typo]", 1))))
	if err == nil || !strings.Contains(err.Error(), "detectors[0] (signup)") || !strings.Contains(err.Error(), "typo") {
		t.Errorf("error does not name the detector and the name: %v", err)
	}
}

// A source without an explicit name is addressed by its default, kibana:<index>.
func TestDetectorSourcesAcceptTheDefaultName(t *testing.T) {
	y := `
sources:
  - {type: kibana, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: kc-*, mapper: keycloak}
detectors:
  - {type: signup, event_field: event_type, create_values: [REGISTER], sources: ['kibana:kc-*']}
`
	if _, err := Parse([]byte(y)); err != nil {
		t.Fatal(err)
	}
}

// Every detector type takes sources:, not only the four that got empty_is_quiet.
func TestEveryDetectorTypeTakesSources(t *testing.T) {
	for name, det := range map[string]string{
		"signup":      "{type: signup, event_field: event_type, create_values: [REGISTER], sources: [kc]}",
		"authspike":   "{type: authspike, key_field: client_ip, status_field: outcome, fail_values: [error], sources: [kc]}",
		"newkey":      "{type: newkey, key_field: client_ip, path_field: path, sensitive_paths: [/x], sources: [ingress]}",
		"behaviour":   "{type: behaviour, key_field: client_ip, path_field: path, method_field: method, actions: [{name: a, class: rare, path: /x}], sources: [ingress]}",
		"fingerprint": "{type: fingerprint, actors: [a.yaml], sources: [ingress]}",
		"signature":   "{type: signature, field: status, present: true, key_field: client_ip, sources: [ingress]}",
	} {
		if _, err := Parse([]byte(scopeCfg("", "  - "+det+"\n"))); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// empty_is_quiet: the guard looks at the sources the detector reads, not at all of them.
func TestEmptyIsQuietGuardFollowsTheScope(t *testing.T) {
	quiet := func(extra string) string { return strings.Replace(kcSignup, "%s", ", empty_is_quiet: true"+extra, 1) }

	// kc filtered, ingress filtered: fine unscoped.
	if _, err := Parse([]byte(scopeCfg(kcFiltered, quiet("")))); err != nil {
		t.Fatalf("both filtered: %v", err)
	}
	// kc unfiltered, unscoped: refused, naming the source and the option.
	_, err := Parse([]byte(scopeCfg("", quiet(""))))
	if err == nil || !strings.Contains(err.Error(), "empty_is_quiet") || !strings.Contains(err.Error(), `"kc"`) || !strings.Contains(err.Error(), "sources:") {
		t.Fatalf("unfiltered kc, unscoped: %v", err)
	}
	// Scoped to the filtered ingress source, the unfiltered kc source is not read: allowed.
	if _, err := Parse([]byte(scopeCfg("", quiet(", sources: [ingress]")))); err != nil {
		t.Fatalf("scoped away from the unfiltered source: %v", err)
	}
	// Scoped to the unfiltered one: refused, and the hint about sources: is not repeated.
	_, err = Parse([]byte(scopeCfg("", quiet(", sources: [kc]"))))
	if err == nil || !strings.Contains(err.Error(), `"kc"`) || strings.Contains(err.Error(), "or list only") {
		t.Fatalf("scoped to the unfiltered kc: %v", err)
	}
}

// The option exists on all four detectors and each is held to the same guard.
func TestEmptyIsQuietIsRefusedWithoutAFilterOnEveryDetector(t *testing.T) {
	for name, det := range map[string]string{
		"signup":    "{type: signup, event_field: event_type, create_values: [REGISTER], empty_is_quiet: true, sources: [kc]}",
		"authspike": "{type: authspike, key_field: client_ip, status_field: outcome, fail_values: [error], empty_is_quiet: true, sources: [kc]}",
		"newkey":    "{type: newkey, key_field: client_ip, path_field: path, sensitive_paths: [/x], empty_is_quiet: true, sources: [kc]}",
		"behaviour": "{type: behaviour, key_field: client_ip, path_field: path, method_field: method, actions: [{name: a, class: rare, path: /x}], empty_is_quiet: true, sources: [kc]}",
	} {
		_, err := Parse([]byte(scopeCfg("", "  - "+det+"\n")))
		if err == nil || !strings.Contains(err.Error(), "empty_is_quiet") || !strings.Contains(err.Error(), "filter") {
			t.Errorf("%s: unfiltered source accepted or error unclear: %v", name, err)
		}
		if _, err := Parse([]byte(scopeCfg(kcFiltered, "  - "+det+"\n"))); err != nil {
			t.Errorf("%s: filtered source refused: %v", name, err)
		}
	}
}

// The worked examples in the docs are configs people will copy: they must load.
func TestDocumentedTwoSourceExamplesLoad(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "config", "detector-scoping.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(doc), "## Example: two sources")
	if !ok {
		t.Fatal("docs/config/detector-scoping.md lost its two-source example")
	}
	_, block, _ := strings.Cut(after, "```yaml\n")
	block, _, _ = strings.Cut(block, "```")
	f, err := Parse([]byte(block))
	if err != nil {
		t.Fatalf("CONFIG.md example: %v", err)
	}
	if got := f.Detectors[1].Sources; len(got) != 1 || got[0] != "keycloak" {
		t.Errorf("CONFIG.md example: signup sources = %v", got)
	}

	ex, err := os.ReadFile(filepath.Join("..", "..", "examples", "jb.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok = strings.Cut(string(ex), "# Two sources, each read by its own detectors.")
	if !ok {
		t.Fatal("jb.example.yaml lost its two-source example")
	}
	var un []string
	started := false
	for _, l := range strings.Split(after, "\n") {
		if strings.HasPrefix(l, "# sources:") {
			started = true
		}
		if started && !strings.HasPrefix(l, "#") {
			break // the block ends at the first line that is not a comment
		}
		if started {
			un = append(un, strings.TrimPrefix(strings.TrimPrefix(l, "#"), " "))
		}
	}
	g, err := Parse([]byte(strings.Join(un, "\n")))
	if err != nil {
		t.Fatalf("jb.example.yaml example: %v", err)
	}
	if len(g.Sources) != 2 || len(g.Detectors) != 2 {
		t.Errorf("jb.example.yaml example: %d sources, %d detectors", len(g.Sources), len(g.Detectors))
	}
}
