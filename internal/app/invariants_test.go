package app

import (
	"context"
	"errors"
	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/core"
	"strings"
	"testing"
)

func TestSharedDocumentSurvivesOwnerChange(t *testing.T) {
	ctx := context.Background()
	st, err := duckdb.OpenTemp(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err = st.Migrate(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		a := scoped("a", "cluster", "d1")
		b := scoped("b", "cluster", "d1")
		if i == 1 {
			a.err = errors.New("page two failed")
		}
		n := 0
		det := fakeDetector{"d", func(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
			for _, err := range cur.Events(ctx, w) {
				if err != nil {
					return nil, err
				}
				n++
			}
			return nil, nil
		}}
		if _, err := Hunt(ctx, Deps{Sources: []core.Source{a, b}, Detectors: []core.Detector{det}, Sink: st, Reader: st, Concurrency: 1}, []string{"r1", "r2", "r3"}[i], win()); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("run%d read%d copies of one document after owner health changed", i, n)
		}
	}
}

func TestFallbackOwnerStoresOwnNormalization(t *testing.T) {
	a := scoped("a", "cluster", "d1")
	b := scoped("b", "cluster", "d1")
	a.events[0].Fields = map[string]any{"mapped_by": "a"}
	b.events[0].Fields = map[string]any{"mapped_by": "b"}
	a.err = errors.New("page two failed")
	got := ""
	det := fakeDetector{"d", func(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
		for e, err := range cur.Events(ctx, w) {
			if err != nil {
				return nil, err
			}
			got, _ = e.Fields["mapped_by"].(string)
		}
		return nil, nil
	}}
	m := newMem()
	if _, err := Hunt(context.Background(), Deps{Sources: []core.Source{a, b}, Detectors: []core.Detector{det}, Scopes: map[string][]string{"d": {"b"}}, Sink: m, Reader: m, Concurrency: 1}, "r", win()); err != nil {
		t.Fatal(err)
	}
	if got != "b" {
		t.Fatalf("healthy b's document uses normalization of %q", got)
	}
}

func TestSharedBufferCountsMappedPayload(t *testing.T) {
	old := sharedBufferLimit
	sharedBufferLimit = 600
	defer func() { sharedBufferLimit = old }()
	ds := &docSet{docs: map[string]*sharedDoc{}, failed: map[string]bool{}}
	e := core.Event{Time: t0, Source: "a", DocKey: "d1", Raw: []byte(`{}`), Fields: map[string]any{"payload": strings.Repeat("x", 4096)}}
	if err := ds.reserve(e); err == nil {
		t.Fatalf("accepted >4KiB mapped payload into a600-byte buffer; accounted=%d", ds.bytes)
	}
}
