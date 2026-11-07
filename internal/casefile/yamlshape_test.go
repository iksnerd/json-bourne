package casefile

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func mappingOf(n int) []byte {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "k%d: v\n", i)
	}
	return []byte(b.String())
}

func TestCheckYAMLShapeBoundary(t *testing.T) {
	if err := CheckYAMLShape("case file", mappingOf(1000)); err != nil {
		t.Fatalf("limit keys must load: %v", err)
	}
	err := CheckYAMLShape("case file", mappingOf(1001))
	if err == nil {
		t.Fatal("limit+1 keys must be refused")
	}
	for _, want := range []string{"case file", "1000"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must name %q", err, want)
		}
	}
	nested := "a:\n  b:\n" + strings.ReplaceAll(string(mappingOf(1001)), "k", "    k")
	if CheckYAMLShape("x", []byte(nested)) == nil {
		t.Error("a nested oversized mapping must be refused")
	}
	if err := CheckYAMLShape("x", []byte("a: [unclosed")); err != nil {
		t.Errorf("a document that does not parse is left to the decoder, got %v", err)
	}
}

// shapeDoc builds a document of about size bytes in one of three shapes.
func shapeDoc(head, shape string, size int) []byte {
	var b strings.Builder
	b.WriteString(head)
	switch shape {
	case "one-mapping":
		for i := 0; b.Len() < size; i++ {
			fmt.Fprintf(&b, "k%d: v\n", i)
		}
	case "nested": // many mappings of 100 keys each: not quadratic
		b.WriteString("x:\n")
		for i := 0; b.Len() < size; i++ {
			fmt.Fprintf(&b, "  m%d:\n", i)
			for j := 0; j < 100; j++ {
				fmt.Fprintf(&b, "    k%d: v\n", j)
			}
		}
	case "sequence":
		b.WriteString("x:\n")
		for i := 0; b.Len() < size; i++ {
			fmt.Fprintf(&b, "  - {a: %d, b: v}\n", i)
		}
	}
	return []byte(b.String())
}

// TestLoadersRefuseHugeMappingFast: before the shape check a 1 MiB single mapping took
// tens of seconds in yaml.v3; now every loader refuses it at once. The nested and
// sequence shapes are linear and must reach the real decoder (and fail there on their
// unknown key `x`, not on the shape limit).
func TestLoadersRefuseHugeMappingFast(t *testing.T) {
	loaders := []struct {
		name string
		head string
		f    func([]byte) error
	}{
		{"case", "apiVersion: " + APIVersion + "\n", func(d []byte) error { _, e := Parse(d); return e }},
		{"actor", "apiVersion: " + ActorAPIVersion + "\n", func(d []byte) error { _, e := ParseActor(d); return e }},
		{"estate", "apiVersion: " + EstateAPIVersion + "\n", func(d []byte) error { _, e := ParseEstate(d); return e }},
		{"snapshot", "apiVersion: " + EstateSnapshotAPIVersion + "\ncomplete: true\n", func(d []byte) error { _, e := ParseEstateSnapshot(d); return e }},
	}
	for _, l := range loaders {
		t.Run(l.name, func(t *testing.T) {
			doc := shapeDoc(l.head, "one-mapping", 1<<20)
			start := time.Now()
			err := l.f(doc)
			if err == nil || !strings.Contains(err.Error(), "keys per mapping") {
				t.Fatalf("one huge mapping must be refused by the shape limit, got %v", err)
			}
			if d := time.Since(start); d > time.Second {
				t.Errorf("refusal took %v, want well under a second", d)
			}
			for _, shape := range []string{"nested", "sequence"} {
				err := l.f(shapeDoc(l.head, shape, 1<<20))
				if err != nil && strings.Contains(err.Error(), "keys per mapping") {
					t.Errorf("%s shape must not hit the mapping limit: %v", shape, err)
				}
			}
		})
	}
}

func FuzzCheckYAMLShape(f *testing.F) {
	f.Add(mappingOf(1000))
	f.Add(mappingOf(MaxMappingKeys + 1))
	f.Add([]byte("a: &x {b: 1}\nc: *x\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = CheckYAMLShape("fuzz", data)
	})
}
