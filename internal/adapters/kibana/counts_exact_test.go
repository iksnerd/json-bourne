package kibana

import (
	"context"
	"testing"
)

// Every count read from a backend reply is an exact nonnegative int64; anything else
// is a malformed reply (an error, so the source or probe is INCOMPLETE), never a clamp.
func TestHistoryCountsAreExactNonnegativeIntegers(t *testing.T) {
	bad := []string{"1.5", "1e2", "100.0", "-1", "9223372036854775808", `"7"`}
	for _, v := range bad {
		f := &fakeIndex{reply: `{"hits":{"total":{"value":100}},"aggregations":{"keys":{"buckets":{"k0":{"doc_count":` + v + `}}}}}`}
		s, _ := newKeySource(t, f, ModeTerm)
		if got, err := s.CountKeys(context.Background(), []string{"192.0.2.7"}, lookbackWin); err == nil {
			t.Errorf("doc_count %s accepted as %v", v, got)
		}
		for _, tot := range []string{`{"value":` + v + `}`, v} {
			f := &fakeIndex{reply: `{"hits":{"total":` + tot + `}}`}
			s, _ := newKeySource(t, f, ModeTerm)
			if got, err := s.CountAll(context.Background(), lookbackWin); err == nil {
				t.Errorf("hits.total %s accepted as %v", tot, got)
			}
		}
	}
	f := &fakeIndex{reply: `{"hits":{"total":{"value":9223372036854775807}},"aggregations":{"keys":{"buckets":{"k0":{"doc_count":9007199254740993}}}}}`}
	s, _ := newKeySource(t, f, ModeTerm)
	got, err := s.CountKeys(context.Background(), []string{"192.0.2.7"}, lookbackWin)
	if err != nil || got["192.0.2.7"] != 9007199254740993 {
		t.Errorf("exact large count: %v, %v", got, err)
	}
	if n, err := s.CountAll(context.Background(), lookbackWin); err != nil || n != 9223372036854775807 {
		t.Errorf("max int64 total: %d, %v", n, err)
	}
}
