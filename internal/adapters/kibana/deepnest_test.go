package kibana

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSearchRefusesDeeplyNestedBodyFast: a reply nested a million arrays deep must come
// back at once, not overflow the stack or spend seconds. encoding/json stops at depth
// 10000; this keeps that true for every place the client decodes into any.
func TestSearchRefusesDeeplyNestedBodyFast(t *testing.T) {
	const depth = 1_000_000
	deep := strings.Repeat("[", depth) + strings.Repeat("]", depth)
	bodies := map[string]string{
		"bare":       deep,
		"in_source":  `{"hits":{"total":1,"hits":[{"_id":"1","_source":{"a":` + deep + `},"sort":[1]}]}}`,
		"in_sort":    `{"hits":{"total":1,"hits":[{"_id":"1","_source":{},"sort":[` + deep + `]}]}}`,
		"in_agg":     `{"hits":{"hits":[]},"aggregations":{"a":` + deep + `}}`,
		"in_raw":     `{"rawResponse":{"hits":{"hits":[]},"aggregations":{"a":` + deep + `}}}`,
		"in_total":   `{"hits":{"total":` + deep + `,"hits":[]}}`,
		"object_run": strings.Repeat(`{"a":`, depth) + "1" + strings.Repeat("}", depth),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			start := time.Now()
			_, err := New(srv.URL, testKey).search(context.Background(), "logs-example", map[string]any{})
			if d := time.Since(start); d > time.Second {
				t.Errorf("took %v, want well under a second", d)
			}
			// A body that is nested past the decoder limit everywhere must be an error.
			if (name == "bare" || name == "object_run" || name == "in_source" || name == "in_sort" || name == "in_agg" || name == "in_raw" || name == "in_total") && err == nil {
				t.Error("a body nested past the decoder limit must be an error")
			}
		})
	}
}
