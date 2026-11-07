package kibana

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

const bodyMark = "BODY-MARK-must-not-be-echoed"

// partialFields are the fields of an Elasticsearch answer that mark it incomplete.
var partialFields = map[string]string{
	"timed_out":            `"timed_out":true,"_shards":{"total":5,"successful":5,"skipped":0,"failed":0}`,
	"one failed shard":     `"timed_out":false,"_shards":{"total":5,"successful":4,"skipped":0,"failed":1}`,
	"timed_out and failed": `"timed_out":true,"_shards":{"total":5,"successful":4,"skipped":0,"failed":1}`,
}

// partialReply builds an otherwise valid Kibana reply (wrapped in rawResponse, or bare)
// that carries bodyMark, so a test can see whether an error echoes the body.
func partialReply(extra string, bare bool) string {
	inner := `{` + extra + `,"leak":"` + bodyMark + `",` +
		`"hits":{"total":{"value":1},"hits":[{"_index":"logs-example","_id":"id1","_source":{"@timestamp":"2026-01-01T00:00:05Z","client_ip":"192.0.2.5","host":"www.example.com","path":"/a"},"sort":[1767225605000]}]},` +
		`"aggregations":{"keys":{"buckets":{"k0":{"doc_count":3}}}}}`
	if bare {
		return inner
	}
	return `{"rawResponse":` + inner + `}`
}

func assertPartial(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("a partial response was accepted as complete")
	}
	msg := err.Error()
	if !strings.Contains(msg, "partial") {
		t.Errorf("error does not name a partial response: %v", err)
	}
	if !errors.Is(err, core.ErrSourceUnavailable) {
		t.Errorf("error is not ErrSourceUnavailable (the hunt would not mark the run incomplete): %v", err)
	}
	for _, secret := range []string{bodyMark, testKey, "192.0.2.5", "192.0.2.7"} {
		if strings.Contains(msg, secret) {
			t.Errorf("error echoes %q: %v", secret, err)
		}
	}
}

func partialServer(t *testing.T, reply string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func keySource(srv *httptest.Server) *Source {
	return &Source{Client: New(srv.URL, testKey), Index: "logs-example", KeyMatch: &KeyMatch{Field: "message", Mode: ModeTerm}}
}

func TestPartialResponseIsAnErrorEverywhereTheClientParsesOne(t *testing.T) {
	for name, extra := range partialFields {
		for _, bare := range []bool{false, true} {
			shape := "wrapped"
			if bare {
				shape = "bare"
			}
			reply := partialReply(extra, bare)
			prefix := name + "/" + shape
			t.Run(prefix+"/Fetch", func(t *testing.T) {
				srv := partialServer(t, reply)
				var gotErr error
				for _, err := range newSource(srv, 10).Fetch(context.Background(), window) {
					if err != nil {
						gotErr = err
						break
					}
				}
				assertPartial(t, gotErr)
			})
			t.Run(prefix+"/probe", func(t *testing.T) {
				// An empty filtered window: page 1 is complete and empty, then the
				// liveness probe answers partially.
				calls := 0
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if calls == 1 {
						_, _ = w.Write(fixture(t, "empty.json"))
						return
					}
					_, _ = w.Write([]byte(reply))
				}))
				t.Cleanup(srv.Close)
				s := newSource(srv, 10)
				s.Query = map[string]any{"match_phrase": map[string]any{"path": "/nothing"}}
				var gotErr error
				for _, err := range s.Fetch(context.Background(), window) {
					if err != nil {
						gotErr = err
						break
					}
				}
				if calls < 2 {
					t.Fatalf("the liveness probe never ran (%d calls)", calls)
				}
				assertPartial(t, gotErr)
			})
			t.Run(prefix+"/CountKeys", func(t *testing.T) {
				_, err := keySource(partialServer(t, reply)).CountKeys(context.Background(), []string{"192.0.2.7"}, lookbackWin)
				assertPartial(t, err)
			})
			t.Run(prefix+"/CountAll", func(t *testing.T) {
				_, err := keySource(partialServer(t, reply)).CountAll(context.Background(), lookbackWin)
				assertPartial(t, err)
			})
		}
	}
}

// A clean answer, skipped shards, and successful < total with nothing failed are not partial.
func TestCompleteResponsesAreNotPartial(t *testing.T) {
	for name, extra := range map[string]string{
		"no fields":      `"x":1`,
		"clean":          `"timed_out":false,"_shards":{"total":5,"successful":5,"skipped":0,"failed":0}`,
		"skipped only":   `"timed_out":false,"_shards":{"total":5,"successful":2,"skipped":3,"failed":0}`,
		"shortfall only": `"timed_out":false,"_shards":{"total":5,"successful":4,"skipped":0,"failed":0}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := keySource(partialServer(t, partialReply(extra, false)))
			if _, err := s.CountKeys(context.Background(), []string{"192.0.2.7"}, lookbackWin); err != nil {
				t.Errorf("CountKeys: %v", err)
			}
			if _, err := s.CountAll(context.Background(), lookbackWin); err != nil {
				t.Errorf("CountAll: %v", err)
			}
		})
	}
}
