package kibana

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// fakeBatch maps a document to an event unless its message says "bad".
type fakeBatch struct {
	calls  int
	err    error
	short  bool
	closed int
}

func (f *fakeBatch) MapBatch(_ context.Context, docs []map[string]any) ([]core.MapResult, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	out := make([]core.MapResult, 0, len(docs))
	for _, d := range docs {
		if m, _ := d["message"].(string); strings.Contains(m, "bad") {
			out = append(out, core.MapResult{Unparsable: true})
			continue
		}
		out = append(out, core.MapResult{Event: core.Event{Time: time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC), Fields: map[string]any{"m": d["message"]}}})
	}
	if f.short {
		out = out[:len(out)-1]
	}
	return out, nil
}

func (f *fakeBatch) Close() error { f.closed++; return nil }

func TestBatchMapperEventsAreCountedLikeBuiltIns(t *testing.T) {
	srv := serveMessages(t, []any{"one", "bad two", "three", "bad four"})
	defer srv.Close()
	fb := &fakeBatch{}
	s := newSource(srv, 0)
	s.Batch = fb
	evs, err := collect(t, s, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || fb.calls != 1 {
		t.Fatalf("events=%d calls=%d, want 2 events in one batch call", len(evs), fb.calls)
	}
	if st := s.Stats(); st.Fetched != 2 || st.Unparsable != 2 {
		t.Errorf("stats = %+v, want fetched 2, unparsable 2: plugin-reported documents count like built-in ones", st)
	}
	if evs[0].Source == "" || evs[0].DocKey == "" || len(evs[0].Raw) == 0 {
		t.Errorf("event lacks source, doc key or raw document: %+v", evs[0])
	}
}

func TestBatchMapperFailureFailsTheFetchNeverAQuietWindow(t *testing.T) {
	srv := serveMessages(t, []any{"one", "two"})
	defer srv.Close()
	s := newSource(srv, 0)
	s.Batch = &fakeBatch{err: errors.New("plugin x: no answer within 10s")}
	evs, err := collect(t, s, context.Background())
	if err == nil || errors.Is(err, core.ErrNoRecords) || !strings.Contains(err.Error(), "no answer") {
		t.Fatalf("err = %v, want the plugin's failure and not ErrNoRecords", err)
	}
	if len(evs) != 0 {
		t.Errorf("events = %d: nothing from a failed batch may be yielded", len(evs))
	}
}

func TestBatchMapperReturningTooFewResultsFailsTheFetch(t *testing.T) {
	srv := serveMessages(t, []any{"one", "two", "three"})
	defer srv.Close()
	s := newSource(srv, 0)
	s.Batch = &fakeBatch{short: true}
	_, err := collect(t, s, context.Background())
	if err == nil || !strings.Contains(err.Error(), "2 results for 3 documents") {
		t.Fatalf("err = %v", err)
	}
}

func TestSourceCloseClosesTheBatchMapper(t *testing.T) {
	fb := &fakeBatch{}
	s := &Source{Batch: fb}
	var _ io.Closer = s
	if err := s.Close(); err != nil || fb.closed != 1 {
		t.Fatalf("err=%v closed=%d", err, fb.closed)
	}
	if err := (&Source{}).Close(); err != nil {
		t.Fatal(err)
	}
}
