package casefile

import (
	"fmt"
	"strings"
	"testing"
)

const validImport = `{
  "apiVersion": "jb.estate-facts/v1",
  "method": "export of a synthetic scan store, converted by the operator's script",
  "source_note": "synthetic store, export dated 2026-11-05",
  "observed": "2026-11-05T08:00:00Z",
  "facts": [
    {"node": "ip:192.0.2.10", "key": "port.open", "values": ["22", "443"]},
    {"node": "ip:192.0.2.10", "key": "os", "values": ["linux"], "observed": "2026-11-04T08:00:00Z"}
  ]
}`

func mustImport(t *testing.T, doc string) *FactsImport {
	t.Helper()
	f, err := ParseFactsImport([]byte(doc))
	if err != nil {
		t.Fatalf("valid import refused: %v", err)
	}
	return f
}

func TestParseFactsImportValid(t *testing.T) {
	f := mustImport(t, validImport)
	if f.Count() != 3 || len(f.Facts) != 2 {
		t.Fatalf("%+v", f)
	}
}

func TestParseFactsImportRefusals(t *testing.T) {
	rep := func(old, new string) string {
		if !strings.Contains(validImport, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(validImport, old, new, 1)
	}
	cases := map[string]struct{ doc, want string }{
		"empty":                 {"", "empty"},
		"not json":              {"nodes: []", "JSON"},
		"unknown top key":       {rep(`"facts"`, `"vendor": "x", "facts"`), "unknown field"},
		"unknown entry key":     {rep(`"key": "os"`, `"key": "os", "score": 9`), "unknown field"},
		"wrong apiVersion":      {rep("jb.estate-facts/v1", "jb.estate-facts/v2"), "apiVersion"},
		"missing apiVersion":    {rep(`"apiVersion": "jb.estate-facts/v1",`, ""), "apiVersion"},
		"missing method":        {rep(`"method": "export of a synthetic scan store, converted by the operator's script",`, ""), "method"},
		"missing source note":   {rep(`"source_note": "synthetic store, export dated 2026-11-05",`, ""), "source_note"},
		"missing observed":      {rep(`"observed": "2026-11-05T08:00:00Z",`, ""), "observed"},
		"observed without zone": {rep("2026-11-05T08:00:00Z", "2026-11-05T08:00:00"), "observed"},
		"multi-line method":     {rep("converted by", `converted\nby`), "one line"},
		"bad key":               {rep(`"key": "os"`, `"key": "OS"`), "key"},
		"bad node":              {rep(`"node": "ip:192.0.2.10", "key": "os"`, `"node": "", "key": "os"`), "node"},
		"no values":             {rep(`"values": ["linux"]`, `"values": []`), "values"},
		"number value":          {rep(`"values": ["linux"]`, `"values": [22]`), "string"},
		"blank value":           {rep(`"linux"`, `"  "`), "value"},
		"multi-line value":      {rep(`"linux"`, `"a\nb"`), "one line"},
		"duplicate value":       {rep(`["22", "443"]`, `["22", "22"]`), "duplicate"},
		"no facts":              {`{"apiVersion":"jb.estate-facts/v1","method":"m","source_note":"s","observed":"2026-11-05T08:00:00Z","facts":[]}`, "facts"},
		"trailing data":         {validImport + "\n{}", "more than one"},
		"credential":            {rep(`"linux"`, `"ghp_abcdefghijklmnopqrstuvwxyz0123456789"`), "credential"},
		"too long method":       {rep("converted by the operator's script", strings.Repeat("m", 600)), "bytes"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseFactsImport([]byte(c.doc))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestParseFactsImportCaps(t *testing.T) {
	build := func(n int) string {
		var vals []string
		for i := 0; i < n; i++ {
			vals = append(vals, fmt.Sprintf("%q", fmt.Sprint(i)))
		}
		return fmt.Sprintf(`{"apiVersion":"jb.estate-facts/v1","method":"m","source_note":"s","observed":"2026-11-05T08:00:00Z","facts":[{"node":"ip:192.0.2.10","key":"port.open","values":[%s]}]}`, strings.Join(vals, ","))
	}
	if _, err := ParseFactsImport([]byte(build(MaxFactsImportFacts))); err != nil {
		t.Fatalf("%d facts refused: %v", MaxFactsImportFacts, err)
	}
	if _, err := ParseFactsImport([]byte(build(MaxFactsImportFacts + 1))); err == nil || !strings.Contains(err.Error(), "facts") {
		t.Errorf("%d facts accepted: %v", MaxFactsImportFacts+1, err)
	}
	big := strings.Repeat(" ", MaxFactsImportSize) + build(1)
	if _, err := ParseFactsImport([]byte(big)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("an oversized file was accepted: %v", err)
	}
}

func TestApplyFactsImport(t *testing.T) {
	base := mustEstate(t, validEstate)
	imp := mustImport(t, validImport)
	got, res, err := ApplyFactsImport(base, imp)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 3 || res.Unchanged != 0 {
		t.Fatalf("%+v", res)
	}
	if len(base.Nodes[0].Facts) != 0 {
		t.Error("the input estate was changed")
	}
	facts := got.Nodes[0].Facts
	if len(facts) != 3 {
		t.Fatalf("%+v", facts)
	}
	for _, f := range facts {
		if f.Source != "scan-cache" || !strings.Contains(f.Method, "converted by the operator's script") || !strings.Contains(f.Method, "synthetic store, export dated 2026-11-05") {
			t.Errorf("provenance: %+v", f)
		}
	}
	if facts[2].Observed != "2026-11-04T08:00:00Z" || facts[0].Observed != "2026-11-05T08:00:00Z" {
		t.Errorf("observed: the entry time overrides the file time: %+v", facts)
	}
	// Importing the same export again changes nothing.
	again, res, err := ApplyFactsImport(got, imp)
	if err != nil || res.Added != 0 || res.Unchanged != 3 || len(again.Nodes[0].Facts) != 3 {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestApplyFactsImportRefusesWhatWouldNotLoad(t *testing.T) {
	base := mustEstate(t, validEstate)
	t.Run("node not in the file", func(t *testing.T) {
		imp := mustImport(t, strings.Replace(validImport, `"node": "ip:192.0.2.10", "key": "os"`, `"node": "ip:203.0.113.9", "key": "os"`, 1))
		if _, _, err := ApplyFactsImport(base, imp); err == nil || !strings.Contains(err.Error(), "ip:203.0.113.9") {
			t.Errorf("an import for an unknown node must be refused whole, got %v", err)
		}
	})
	t.Run("more than 50 facts on a node", func(t *testing.T) {
		var vals []string
		for i := 0; i < maxNodeFacts+1; i++ {
			vals = append(vals, fmt.Sprintf("%q", fmt.Sprint(i)))
		}
		doc := fmt.Sprintf(`{"apiVersion":"jb.estate-facts/v1","method":"m","source_note":"s","observed":"2026-11-05T08:00:00Z","facts":[{"node":"ip:192.0.2.10","key":"port.open","values":[%s]}]}`, strings.Join(vals, ","))
		if _, _, err := ApplyFactsImport(base, mustImport(t, doc)); err == nil || !strings.Contains(err.Error(), "facts") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("an existing assessment stays", func(t *testing.T) {
		b := mustEstate(t, readCorpus(t, "valid/assessment-fact-basis"))
		got, _, err := ApplyFactsImport(b, mustImport(t, validImport))
		if err != nil || len(got.Assessments) != 1 || len(got.Nodes[0].Facts) != 4 {
			t.Errorf("%v %+v", err, got)
		}
	})
}

// What is written must be what the loader reads back: a credential that slipped into a
// value is refused at write time, not found later when the file will not load.
func TestMarshalEstateRefusesWhatTheLoaderWouldReject(t *testing.T) {
	e := mustEstate(t, validEstate)
	e.Nodes[0].Label = "192.0.2.10"
	e.Nodes[2].Label = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	if _, err := MarshalEstate(e); err == nil || !strings.Contains(err.Error(), "credential") {
		t.Errorf("got %v", err)
	}
}
