package casefile

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// A self-referencing alias overflows the stack, which Go cannot recover from, so each
// hostile document is parsed in a child process. The parent sees a crash as a failed
// exit, with "goroutine stack exceeds" on stderr.
const (
	childKindEnv = "JB_YAMLBOMB_KIND"
	childFileEnv = "JB_YAMLBOMB_FILE"
)

func TestYAMLBombChild(t *testing.T) {
	kind := os.Getenv(childKindEnv)
	if kind == "" {
		t.Skip("child of TestHostileYAMLIsRefusedNotCrashed")
	}
	data, err := os.ReadFile(os.Getenv(childFileEnv))
	if err != nil {
		t.Fatal(err)
	}
	switch kind {
	case "case":
		_, err = Parse(data)
	case "estate":
		_, err = ParseEstate(data)
	case "actor":
		_, err = ParseActor(data)
	case "snapshot":
		_, err = ParseEstateSnapshot(data)
	}
	if err == nil {
		os.Stdout.WriteString("RESULT: accepted\n")
		return
	}
	os.Stdout.WriteString("RESULT: refused: " + err.Error() + "\n")
}

var headers = map[string]string{
	"case":     "apiVersion: jb.case/v1\n",
	"estate":   "apiVersion: jb.estate/v2\n",
	"actor":    "apiVersion: jb.actor/v1\n",
	"snapshot": "apiVersion: jb.estate-snapshot/v2\ncomplete: true\n",
}

func hostileDocs() map[string]string {
	var lolz strings.Builder
	lolz.WriteString("a0: &a0 [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n")
	prev := "a0"
	for i := 1; i <= 9; i++ {
		name := "a" + string(rune('0'+i))
		lolz.WriteString(name + ": &" + name + " [" + strings.Repeat("*"+prev+",", 9) + "]\n")
		prev = name
	}
	return map[string]string{
		"self alias":             "loop: &x [*x]\n",
		"anchor holds own alias": "loop: &x\n  inner: *x\n",
		"alias cycle of two":     "a: &a [*b]\nb: &b [*a]\n",
		"deep nesting":           "deep: " + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + "\n",
		"expansion bomb":         lolz.String(),
	}
}

// wantText is what each hostile document's refusal must say, so each limit is tested
// on its own (the depth limit alone would also stop a cycle).
var wantText = map[string]string{
	"self alias":             "contains itself",
	"anchor holds own alias": "contains itself",
	"deep nesting":           "deeper",
	"expansion bomb":         "more than",
}

func TestHostileYAMLIsRefusedNotCrashed(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for kind, header := range headers {
		for name, body := range hostileDocs() {
			t.Run(kind+"/"+name, func(t *testing.T) {
				f := t.TempDir() + "/doc.yaml"
				if err := os.WriteFile(f, []byte(header+body), 0o600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, exe, "-test.run=^TestYAMLBombChild$", "-test.v")
				cmd.Env = append(os.Environ(), childKindEnv+"="+kind, childFileEnv+"="+f)
				out, err := cmd.CombinedOutput()
				text := string(out)
				if err != nil {
					head := text
					if len(head) > 300 {
						head = head[:300]
					}
					t.Fatalf("the parser crashed or hung instead of refusing: %v\n%s", err, head)
				}
				if !strings.Contains(text, "RESULT: refused") {
					t.Errorf("hostile document was not refused:\n%s", text)
				}
				// Case and actor files lack required keys here and fail on that first;
				// estate and snapshot files reach the walk.
				if w := wantText[name]; w != "" && (kind == "estate" || kind == "snapshot") && !strings.Contains(text, w) {
					t.Errorf("refusal does not say %q:\n%s", w, text)
				}
			})
		}
	}
}

// The actor walk shares one budget across its pieces and refuses the same documents.
func TestActorScanRefusesHostileDocuments(t *testing.T) {
	for name, body := range hostileDocs() {
		if name == "alias cycle of two" {
			continue // the YAML parser itself refuses a forward alias
		}
		var root yaml.Node
		if err := yaml.Unmarshal([]byte(body), &root); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := scanActorCredentials(&root); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Anchors and aliases that a real file may use keep loading.
func TestSharedAnchorsStillScan(t *testing.T) {
	shared := "defaults: &d {note: hello}\none: *d\ntwo: *d\nlist: [*d, *d, *d]\n"
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(shared), &root); err != nil {
		t.Fatal(err)
	}
	if err := scanCredentials(&root); err != nil {
		t.Fatalf("scan refused a valid shared anchor: %v", err)
	}
	var cred yaml.Node
	if err := yaml.Unmarshal([]byte("k: &k \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"\nuse: *k\n"), &cred); err != nil {
		t.Fatal(err)
	}
	if err := scanCredentials(&cred); err == nil {
		t.Fatal("a credential behind an alias was not found")
	}
}
