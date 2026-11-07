package casefile

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

// fuzzCap bounds the input a target works on. The loaders cap a real file at 1 MiB; the
// fuzzer gains nothing from megabytes, and under -race they only make each run slow.
const fuzzCap = 16 << 10

// fuzzBudget is how long one input may take. A parser that needs longer on 64 KiB has a
// complexity bug, and the fuzzer's crasher shows the input.
const fuzzBudget = 10 * time.Second

func seedFile(f *testing.F, path string) {
	f.Helper()
	if b, err := os.ReadFile(path); err == nil {
		f.Add(b)
	}
}

// bounded skips an input over the cap and arms a watchdog: a parse that has not returned
// within fuzzBudget kills the worker, so the fuzzer saves the input as a crasher instead
// of stalling on it. The returned func disarms it.
func bounded(t *testing.T, data []byte) func() {
	t.Helper()
	if len(data) > fuzzCap {
		t.Skip("over the fuzz size cap")
	}
	w := time.AfterFunc(fuzzBudget, func() { panic("parser did not return within the fuzz budget") })
	return func() { w.Stop() }
}

func FuzzParseEstate(f *testing.F) {
	seedFile(f, "../../examples/case/estate/example-estate.yaml")
	f.Add([]byte("apiVersion: jb.estate/v2\nid: x\ncaveat: c\nnodes: []\n"))
	f.Add([]byte("apiVersion: jb.estate/v2\nloop: &x [*x]\n"))
	f.Add([]byte("apiVersion: jb.estate/v2\na: &a [1,1]\nb: [*a,*a]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		done := bounded(t, data)
		e, err := ParseEstate(data)
		done()
		if err != nil {
			return
		}
		if e == nil {
			t.Fatal("no value and no error")
		}
		// An accepted estate writes out as a file that loads and says the same.
		out, err := MarshalEstate(e)
		if err != nil {
			t.Fatalf("accepted estate does not marshal: %v", err)
		}
		back, err := ParseEstate(out)
		if err != nil {
			t.Fatalf("written estate does not load: %v\n%s", err, out)
		}
		again, err := MarshalEstate(back)
		if err != nil || string(again) != string(out) {
			t.Fatalf("estate does not round-trip: %v\nfirst:\n%s\nsecond:\n%s", err, out, again)
		}
	})
}

func FuzzParseEstateSnapshot(f *testing.F) {
	f.Add([]byte("apiVersion: jb.estate-snapshot/v2\ncomplete: true\n"))
	f.Add([]byte("apiVersion: jb.estate-snapshot/v2\ncomplete: false\nloop: &x [*x]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		done := bounded(t, data)
		s, err := ParseEstateSnapshot(data)
		done()
		if err != nil {
			return
		}
		if s == nil {
			t.Fatal("no value and no error")
		}
		out, err := MarshalEstateSnapshot(s)
		if err != nil {
			t.Fatalf("accepted snapshot does not marshal: %v", err)
		}
		if _, err := ParseEstateSnapshot(out); err != nil {
			t.Fatalf("written snapshot does not load: %v\n%s", err, out)
		}
	})
}

func FuzzParseCase(f *testing.F) {
	seedFile(f, "../../examples/case/case.yaml")
	f.Add([]byte("apiVersion: jb.case/v1\n"))
	f.Add([]byte("apiVersion: jb.case/v1\nloop: &x [*x]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		done := bounded(t, data)
		c, err := Parse(data)
		done()
		if err != nil {
			return
		}
		if c == nil {
			t.Fatal("no value and no error")
		}
		// Parsing is a function of the bytes: the same input gives the same case.
		c2, err := Parse(data)
		if err != nil || !reflect.DeepEqual(c, c2) {
			t.Fatalf("a second parse differs: %v", err)
		}
	})
}

func FuzzParseActor(f *testing.F) {
	seedFile(f, "../../examples/case/actors/example-actor.yaml")
	f.Add([]byte("apiVersion: jb.actor/v1\n"))
	f.Add([]byte("apiVersion: jb.actor/v1\nloop: &x [*x]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		done := bounded(t, data)
		a, err := ParseActor(data)
		done()
		if err != nil {
			return
		}
		if a == nil {
			t.Fatal("no value and no error")
		}
		a2, err := ParseActor(data)
		if err != nil || !reflect.DeepEqual(a, a2) {
			t.Fatalf("a second parse differs: %v", err)
		}
	})
}

const factsSeed = `{"apiVersion":"jb.estate-facts/v1","method":"synthetic export","source_note":"synthetic store, dated 2026-11-05","observed":"2026-11-05T08:00:00Z","facts":[{"node":"ip:192.0.2.10","key":"os","values":["linux"]},{"node":"host:edge.example.com","key":"tech","values":["nginx","php"]}]}`

func FuzzParseFactsImport(f *testing.F) {
	f.Add([]byte(factsSeed))
	// The JSON-lines shape: a header object, then one entry per line.
	f.Add([]byte(`{"apiVersion":"jb.estate-facts/v1","method":"m","source_note":"n","observed":"2026-11-05T08:00:00Z"}` + "\n" +
		`{"node":"ip:192.0.2.10","key":"os","values":["linux"]}` + "\n" +
		`{"node":"ip:192.0.2.11","key":"os","values":["bsd"],"observed":"2026-11-05T09:00:00Z"}` + "\n"))
	f.Add([]byte(`{"a":`))
	f.Add([]byte(`{}{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		done := bounded(t, data)
		imp, err := ParseFactsImport(data)
		done()
		if err != nil {
			return
		}
		if imp == nil {
			t.Fatal("no value and no error")
		}
		if err := imp.validate(); err != nil {
			t.Fatalf("accepted import does not validate: %v", err)
		}
		// Written as one document it parses back to the same import.
		out, err := json.Marshal(imp)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseFactsImport(out)
		if err != nil {
			t.Fatalf("re-encoded import is refused: %v\n%s", err, out)
		}
		if !reflect.DeepEqual(imp, back) {
			t.Fatalf("import does not round-trip:\n%+v\n%+v", imp, back)
		}
	})
}
