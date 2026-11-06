package kibana

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestLabelNamesTheSourceAndEventsCarryADocKey(t *testing.T) {
	f := &filterServer{matching: 1, windowTotal: 5}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	s := filteredSource(srv)
	if s.Name() != "kibana:logs-example" {
		t.Fatalf("default name = %q", s.Name())
	}
	s.Label = "token-paths"
	if s.Name() != "token-paths" {
		t.Fatalf("name = %q, want the label", s.Name())
	}
	evs, err := collect(t, s, context.Background())
	if err != nil || len(evs) != 1 {
		t.Fatalf("events=%d err=%v", len(evs), err)
	}
	if evs[0].Source != "token-paths" {
		t.Errorf("event source = %q, want the label (the stored source column)", evs[0].Source)
	}
	if evs[0].DocKey != "i/d0" {
		t.Errorf("DocKey = %q, want concrete index and _id", evs[0].DocKey)
	}
	if s.DocScope() != srv.URL {
		t.Errorf("DocScope = %q", s.DocScope())
	}
}
