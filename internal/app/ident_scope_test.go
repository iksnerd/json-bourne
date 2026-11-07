package app

import (
	"context"
	"testing"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/core"
)

// A DocKey is only unique inside its scope: two clusters can hold the same index and _id.
// Hunting each cluster alone must store two documents, not merge them into one.
func TestSameDocKeyInTwoScopesIsTwoDocuments(t *testing.T) {
	ctx := context.Background()
	st, err := duckdb.OpenTemp(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	n := 0
	det := fakeDetector{"d", func(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
		n = 0
		for _, err := range cur.Events(ctx, w) {
			if err != nil {
				return nil, err
			}
			n++
		}
		return nil, nil
	}}
	for i, c := range []struct{ name, scope string }{{"a", "https://c1.example.com"}, {"b", "https://c2.example.com"}} {
		d := Deps{Sources: []core.Source{scoped(c.name, c.scope, "d1")}, Detectors: []core.Detector{det}, Sink: st, Reader: st, Concurrency: 1}
		if _, err := Hunt(ctx, d, []string{"r1", "r2"}[i], win()); err != nil {
			t.Fatal(err)
		}
	}
	// The raw documents are equal and the DocKey is equal, so only the scope tells them apart.
	if n != 2 {
		t.Fatalf("read %d documents after hunting two clusters that hold the same index and _id, want 2", n)
	}
}
