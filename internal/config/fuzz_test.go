package config

import (
	"os"
	"reflect"
	"testing"
	"time"
)

// fuzzCap bounds the input; fuzzBudget bounds one parse. A parse still running after the
// budget panics the worker, so the fuzzer saves the input instead of stalling on it.
const (
	fuzzCap    = 16 << 10
	fuzzBudget = 10 * time.Second
)

func FuzzParse(f *testing.F) {
	for _, p := range []string{
		"../../examples/case/config/hunt.yaml",
		"../../examples/case/config/fingerprint.yaml",
		"../../examples/jb.example.yaml",
		"../../examples/hunt-plugin-nginx.example.yaml",
	} {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("commands: [intel]\n"))
	f.Add([]byte("sources: &a [*a]\n"))
	f.Add([]byte("a: &a [1,1,1]\nb: &b [*a,*a,*a]\nc: [*b,*b,*b]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzCap {
			t.Skip("over the fuzz size cap")
		}
		w := time.AfterFunc(fuzzBudget, func() { panic("Parse did not return within the fuzz budget") })
		cfg, err := Parse(data)
		w.Stop()
		if err != nil {
			return
		}
		if cfg == nil {
			t.Fatal("no value and no error")
		}
		// Parse is a function of the bytes: an accepted config parses to the same value.
		again, err := Parse(data)
		if err != nil {
			t.Fatalf("a second parse refuses what the first accepted: %v", err)
		}
		if !reflect.DeepEqual(cfg, again) {
			t.Fatal("a second parse of the same bytes differs")
		}
	})
}
