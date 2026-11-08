// Package conformance_test runs one corpus of documents and expected events through
// (i) each example plugin, started by the real host as a real child process, and (ii)
// the built-in mapper where the same fixture applies. Passing both is the evidence that
// a configured plugin can do what a built-in does, without a line of product code.
package conformance_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/kibana"
	"github.com/iksnerd/json-bourne/internal/adapters/plugin"
)

type wantEvent struct {
	TS     string         `json:"ts"`
	Fields map[string]any `json:"fields"`
}

type testCase struct {
	Name       string         `json:"name"`
	Doc        map[string]any `json:"doc"`
	Want       *wantEvent     `json:"want"`
	Unparsable bool           `json:"unparsable"`
	Fatal      string         `json:"fatal"`
	Builtin    bool           `json:"builtin"` // also run through the fixture's built-in mapper
}

type fixture struct {
	Plugin  string         `json:"plugin"`
	Config  map[string]any `json:"config"`
	Builtin string         `json:"builtin"`
	Cases   []testCase     `json:"cases"`
}

var binDir string // plugin binaries, built once, each in its own 0755 directory

func TestMain(m *testing.M) {
	_, self, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(self), "..", "..")
	tmp, err := os.MkdirTemp("", "jb-conformance")
	if err != nil {
		panic(err)
	}
	binDir, _ = filepath.EvalSymlinks(tmp)
	for _, p := range []string{"kvlines", "regexlines", "jsondoc"} {
		dir := filepath.Join(binDir, p)
		if err := os.Mkdir(dir, 0o755); err != nil {
			panic(err)
		}
		_ = os.Chmod(dir, 0o755)
		cmd := exec.Command("go", "build", "-o", filepath.Join(dir, p), "./examples/plugins/"+p)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			os.Stderr.Write(out)
			os.Exit(2)
		}
	}
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

func norm(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCorpus(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.json")
	if len(files) < 4 {
		t.Fatalf("found %d fixture files; the corpus is missing", len(files))
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var fx fixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		t.Run(filepath.Base(f), func(t *testing.T) { runFixture(t, fx) })
	}
}

func runFixture(t *testing.T, fx fixture) {
	path := filepath.Join(binDir, fx.Plugin, fx.Plugin)
	h, err := plugin.NewHost(plugin.Options{
		Entry:  plugin.Entry{Name: "example." + fx.Plugin, Path: path, SHA256: ""},
		Config: fx.Config,
		Limits: plugin.Limits{Deadline: 10 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// All non-fatal cases ride one batch: exactly one result per document, in order.
	var batch []testCase
	for _, c := range fx.Cases {
		if c.Fatal == "" {
			batch = append(batch, c)
		}
	}
	docs := make([]map[string]any, len(batch))
	for i, c := range batch {
		docs[i] = c.Doc
	}
	res, err := h.MapBatch(context.Background(), docs)
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if len(res) != len(batch) {
		t.Fatalf("%d results for %d documents", len(res), len(batch))
	}
	nUnp, nEv := 0, 0
	for i, c := range batch {
		t.Run("plugin/"+c.Name, func(t *testing.T) {
			r := res[i]
			if c.Unparsable {
				if !r.Unparsable {
					t.Fatalf("want unparsable, got event %v", r.Event.Fields)
				}
				return
			}
			if r.Unparsable {
				t.Fatalf("plugin called a good document unparsable")
			}
			wt, err := time.Parse(time.RFC3339Nano, c.Want.TS)
			if err != nil {
				t.Fatal(err)
			}
			if !r.Event.Time.Equal(wt) {
				t.Errorf("time = %s, want %s", r.Event.Time, wt)
			}
			if got, want := norm(t, r.Event.Fields), norm(t, c.Want.Fields); !reflect.DeepEqual(got, want) {
				t.Errorf("fields = %v\nwant     %v", got, want)
			}
		})
		if c.Unparsable {
			nUnp++
		} else {
			nEv++
		}
	}
	if nUnp == 0 || nEv == 0 {
		t.Errorf("fixture has %d events and %d unparsable cases: it must have both to mean anything", nEv, nUnp)
	}

	// Fatal cases: a fault in the document set fails the call; it is never a quiet pass.
	for _, c := range fx.Cases {
		if c.Fatal == "" {
			continue
		}
		t.Run("plugin-fatal/"+c.Name, func(t *testing.T) {
			r, err := h.MapBatch(context.Background(), []map[string]any{c.Doc})
			if err == nil || !errors.Is(err, plugin.ErrPlugin) || !strings.Contains(err.Error(), c.Fatal) {
				t.Fatalf("res=%v err=%v, want ErrPlugin containing %q", r, err, c.Fatal)
			}
		})
	}

	// The built-in, where the same fixture applies, must agree with the plugin and the corpus.
	if fx.Builtin == "" {
		return
	}
	bm, ok := kibana.LookupMapper(fx.Builtin)
	if !ok {
		t.Fatalf("built-in mapper %q is not registered", fx.Builtin)
	}
	ran := 0
	for _, c := range fx.Cases {
		if !c.Builtin {
			continue
		}
		ran++
		t.Run("builtin/"+c.Name, func(t *testing.T) {
			ev, err := bm(c.Doc)
			switch {
			case c.Fatal != "":
				if err == nil || errors.Is(err, kibana.ErrUnparsable) || !strings.Contains(err.Error(), c.Fatal) {
					t.Fatalf("built-in err = %v, want a hard error containing %q", err, c.Fatal)
				}
			case c.Unparsable:
				if !errors.Is(err, kibana.ErrUnparsable) {
					t.Fatalf("built-in err = %v, want ErrUnparsable", err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				wt, _ := time.Parse(time.RFC3339Nano, c.Want.TS)
				if !ev.Time.Equal(wt) {
					t.Errorf("built-in time = %s, want %s", ev.Time, wt)
				}
				if got, want := norm(t, ev.Fields), norm(t, c.Want.Fields); !reflect.DeepEqual(got, want) {
					t.Errorf("built-in fields = %v\nwant           %v", got, want)
				}
			}
		})
	}
	if ran < 5 {
		t.Errorf("only %d cases compared against the built-in", ran)
	}
}
