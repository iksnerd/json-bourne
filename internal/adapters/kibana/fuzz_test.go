package kibana

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	fuzzCap    = 64 << 10
	fuzzMark   = "FUZZ-BODY-MARK-must-not-be-echoed"
	fuzzBudget = 10 * time.Second
)

func readTestdata(name string) ([]byte, error) { return os.ReadFile("testdata/" + name) }

// partialIn reports whether the body, read independently of the client, says the answer
// is partial: the search timed out or a shard failed. It looks where the client does:
// inside rawResponse when that is present, else at the top level.
func partialIn(data []byte) bool {
	var wrap struct {
		Raw json.RawMessage `json:"rawResponse"`
	}
	body := data
	if json.Unmarshal(data, &wrap) == nil && len(wrap.Raw) > 0 {
		body = wrap.Raw
	}
	var m struct {
		TimedOut bool `json:"timed_out"`
		Shards   struct {
			Failed int `json:"failed"`
		} `json:"_shards"`
	}
	if json.Unmarshal(body, &m) != nil {
		return false
	}
	return m.TimedOut || m.Shards.Failed > 0
}

// FuzzSearchResponse serves the fuzzed bytes as Kibana's answer and reads them through
// the client and through a full Fetch. Whatever arrives (partial, malformed, truncated),
// the source returns an error or a result, never a panic and never a hang; a body that
// says partial is never accepted as a result; and an error echoes neither the API key
// nor the body.
func FuzzSearchResponse(f *testing.F) {
	var body atomic.Pointer[[]byte]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(*body.Load())
	}))
	f.Cleanup(srv.Close)

	for _, name := range []string{"page1.json", "page2.json", "page3.json", "empty.json"} {
		if b, err := readTestdata(name); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(`{"rawResponse":{"timed_out":true,"_shards":{"failed":0},"hits":{"total":{"value":1},"hits":[]}}}`))
	f.Add([]byte(`{"timed_out":false,"_shards":{"failed":2},"leak":"` + fuzzMark + `","hits":{"total":1,"hits":[]}}`))
	f.Add([]byte(`{"hits":{"total":{"value":1},"hits":[{"_index":"i","_id":"1","_source":{"@timestamp":"2026-01-01T00:00:05Z"},"sort":[1767225605000]}]}}`))
	f.Add([]byte(`{"hits":{"hits":[{"_id":"1","_source":`))
	f.Add([]byte(`{"rawResponse":null}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"hits":{"total":1e999,"hits":[{"sort":[1e999]}]}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzCap {
			t.Skip("over the fuzz size cap")
		}
		body.Store(&data)
		ctx, cancel := context.WithTimeout(context.Background(), fuzzBudget/2)
		defer cancel()
		w := time.AfterFunc(fuzzBudget, func() { panic("the source did not return within the fuzz budget") })
		defer w.Stop()

		checkErr := func(what string, err error) {
			msg := err.Error()
			if strings.Contains(msg, testKey) || strings.Contains(msg, fuzzMark) {
				t.Fatalf("%s: error echoes a secret or the body: %v", what, err)
			}
		}

		c := New(srv.URL, testKey)
		resp, err := c.search(ctx, "logs-example", map[string]any{})
		switch {
		case err != nil:
			checkErr("search", err)
		case resp == nil:
			t.Fatal("search: no value and no error")
		case partialIn(data):
			t.Fatalf("search: a partial answer was accepted as complete: %s", data)
		}
		if err != nil && partialIn(data) && ctx.Err() == nil && !errors.Is(err, core.ErrSourceUnavailable) {
			t.Fatalf("search: partial answer refused without ErrSourceUnavailable, so the hunt would not be incomplete: %v", err)
		}

		s := &Source{Client: c, Index: "logs-example", PageSize: 10}
		n := 0
		for _, ferr := range s.Fetch(ctx, window) {
			if ferr != nil {
				checkErr("fetch", ferr)
				break
			}
			if n++; n > 10000 {
				t.Fatal("fetch yielded an unbounded stream from one fixed reply")
			}
		}
	})
}
