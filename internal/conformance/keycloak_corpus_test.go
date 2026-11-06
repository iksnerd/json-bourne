package conformance_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/kibana"
	"github.com/iksnerd/json-bourne/internal/adapters/plugin"
)

// The built-in keycloak mapper's own corpus (internal/logmap/keycloak/testdata/corpus)
// run through two implementations: the registered built-in, and the kvlines plugin with
// an equivalent mapper_config. They are not the same mapper, and the places where they
// legitimately differ are written down in testdata/keycloak/kvlines_differences.json,
// one entry per case with the reason. The test fails if a case differs and has no entry
// (a silent divergence), and if an entry no longer differs (a stale claim).

const keycloakCorpusDir = "../logmap/keycloak/testdata/corpus"

// kvlinesKeycloakConfig is what an operator would write to get Keycloak events out of
// kvlines. It cannot express three things the built-in does: outcome, the realmName to
// realmId fallback, and the Keycloak type grammar. They surface as differences.
var kvlinesKeycloakConfig = map[string]any{
	"separators": ",",
	// The built-in accepts a message up to 16 KiB; kvlines' default is 8 KiB.
	"max_line_bytes": 16384,
	"required":       []any{"type"},
	"fields": map[string]any{
		"event_type": map[string]any{"from": "type", "required": true},
		"error":      map[string]any{"from": "error"},
		"client_ip":  map[string]any{"from": "ipAddress", "type": "ip", "omit": []any{"-", "null"}},
		"client_id":  map[string]any{"from": "clientId", "omit": []any{"-", "null"}},
		"realm":      map[string]any{"from": "realmName", "omit": []any{"-", "null"}},
		"username":   map[string]any{"from": "username", "omit": []any{"-", "null"}},
		"email":      map[string]any{"from": "email", "omit": []any{"-", "null"}},
	},
}

type kcWant struct {
	Time       string         `json:"time"`
	Fields     map[string]any `json:"fields"`
	Unparsable bool           `json:"unparsable"`
	BadTime    bool           `json:"bad_time"`
}

type kcDiff struct {
	Reason     string         `json:"reason"`
	Unparsable bool           `json:"unparsable"`
	Fields     map[string]any `json:"fields"`
}

func loadKeycloakCorpus(t *testing.T) (names []string, docs map[string]map[string]any, wants map[string]kcWant) {
	t.Helper()
	ins, err := filepath.Glob(filepath.Join(keycloakCorpusDir, "*.in.json"))
	if err != nil || len(ins) < 30 {
		t.Fatalf("keycloak corpus not found: %d files, err %v", len(ins), err)
	}
	docs, wants = map[string]map[string]any{}, map[string]kcWant{}
	skipped := 0
	for _, in := range ins {
		name := strings.TrimSuffix(filepath.Base(in), ".in.json")
		raw, err := os.ReadFile(in)
		if err != nil {
			t.Fatal(err)
		}
		var d map[string]any
		if err := json.Unmarshal(raw, &d); err != nil || d == nil {
			// Not a JSON object (or not JSON at all): the plugin and registry interfaces
			// take a decoded document, so these byte-level cases belong to the built-in's
			// own TestCorpus and cannot be expressed here.
			skipped++
			continue
		}
		wb, err := os.ReadFile(strings.TrimSuffix(in, ".in.json") + ".want.json")
		if err != nil {
			t.Fatal(err)
		}
		var w kcWant
		if err := json.Unmarshal(wb, &w); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		names = append(names, name)
		docs[name], wants[name] = d, w
	}
	sort.Strings(names)
	if skipped != 4 {
		t.Fatalf("%d corpus documents are not JSON objects, want the 4 byte-level cases; update this count deliberately", skipped)
	}
	return
}

// projected is the built-in's wanted fields reduced to the fields kvlines is configured
// to emit, minus outcome (which kvlines cannot derive; asserted separately).
func projected(w map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range w {
		if _, ok := kvlinesKeycloakConfig["fields"].(map[string]any)[k]; ok {
			out[k] = v
		}
	}
	return out
}

func TestKeycloakCorpusBuiltinAndKvlines(t *testing.T) {
	names, docs, wants := loadKeycloakCorpus(t)

	var diffs map[string]kcDiff
	raw, err := os.ReadFile("testdata/keycloak/kvlines_differences.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &diffs); err != nil {
		t.Fatal(err)
	}
	for n, d := range diffs {
		if _, ok := docs[n]; !ok {
			t.Errorf("difference %q names a corpus case that does not exist", n)
		}
		if strings.TrimSpace(d.Reason) == "" {
			t.Errorf("difference %q has no reason", n)
		}
		if !d.Unparsable && d.Fields == nil {
			t.Errorf("difference %q states neither unparsable nor fields", n)
		}
	}

	// (i) the registered built-in gives the corpus result for every case.
	bm, ok := kibana.LookupMapper("keycloak")
	if !ok {
		t.Fatal("built-in keycloak mapper is not registered")
	}
	for _, n := range names {
		w := wants[n]
		t.Run("builtin/"+n, func(t *testing.T) {
			ev, err := bm(docs[n])
			switch {
			case w.Unparsable:
				if !errors.Is(err, kibana.ErrUnparsable) {
					t.Fatalf("err = %v, want ErrUnparsable", err)
				}
			case w.BadTime:
				if err == nil || errors.Is(err, kibana.ErrUnparsable) {
					t.Fatalf("err = %v, want a hard bad-time error", err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				if got, want := norm(t, ev.Fields), norm(t, w.Fields); !reflect.DeepEqual(got, want) {
					t.Errorf("fields = %v\nwant     %v", got, want)
				}
			}
		})
	}

	// (ii) kvlines with the equivalent config, one batch, same order.
	newHost := func() *plugin.Host {
		h, err := plugin.NewHost(plugin.Options{
			Entry:  plugin.Entry{Name: "example.kvlines", Path: filepath.Join(binDir, "kvlines", "kvlines")},
			Config: kvlinesKeycloakConfig,
			Limits: plugin.Limits{Deadline: 30 * time.Second},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { h.Close() })
		return h
	}
	h := newHost()

	var batch []string
	for _, n := range names {
		if wants[n].BadTime {
			// A bad timestamp fails the whole call on both sides.
			if _, err := newHost().MapBatch(context.Background(), []map[string]any{docs[n]}); err == nil || !errors.Is(err, plugin.ErrPlugin) || !strings.Contains(err.Error(), "bad or missing @timestamp") {
				t.Errorf("kvlines/%s: err = %v, want ErrPlugin 'bad or missing @timestamp'", n, err)
			}
			continue
		}
		batch = append(batch, n)
	}
	in := make([]map[string]any, len(batch))
	for i, n := range batch {
		in[i] = docs[n]
	}
	res, err := h.MapBatch(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != len(batch) {
		t.Fatalf("%d results for %d documents", len(res), len(batch))
	}
	sawDiff := map[string]bool{}
	for i, n := range batch {
		r, w := res[i], wants[n]
		t.Run("kvlines/"+n, func(t *testing.T) {
			if !r.Unparsable {
				if _, has := r.Event.Fields["outcome"]; has {
					t.Errorf("kvlines emitted outcome; it cannot derive one from the config")
				}
			}
			agrees := false
			switch {
			case w.Unparsable:
				agrees = r.Unparsable
			case r.Unparsable:
				agrees = false
			default:
				agrees = reflect.DeepEqual(norm(t, r.Event.Fields), norm(t, projected(w.Fields)))
			}
			d, listed := diffs[n]
			if agrees {
				if listed {
					t.Errorf("listed as a difference but kvlines agrees with the built-in: remove the stale entry")
				}
				return
			}
			sawDiff[n] = true

			if !listed {
				t.Fatalf("kvlines differs from the built-in and the difference is not recorded:\n  kvlines unparsable=%v fields=%v\n  built-in %v", r.Unparsable, r.Event.Fields, w)
			}
			if d.Unparsable != r.Unparsable {
				t.Fatalf("recorded unparsable=%v, kvlines unparsable=%v (fields %v)", d.Unparsable, r.Unparsable, r.Event.Fields)
			}
			if !d.Unparsable {
				if got, want := norm(t, r.Event.Fields), norm(t, d.Fields); !reflect.DeepEqual(got, want) {
					t.Errorf("kvlines fields = %v\nrecorded       %v", got, want)
				}
			}
		})
	}
	for n := range diffs {
		if !sawDiff[n] && wants[n].BadTime {
			t.Errorf("difference %q is a bad-time case; those are fatal on both sides and not differences", n)
		}
	}
}
