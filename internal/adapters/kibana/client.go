// Package kibana is a read-only core.Source backed by the Elasticsearch search
// endpoint proxied by Kibana. Only POST /internal/search/es — no writes, ever.
package kibana

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	// SearchPath is the only Kibana route this client uses. /api/console/proxy
	// can 404 on some Kibana versions; /internal/search/es is what the Kibana UI itself calls.
	SearchPath = "/internal/search/es"
	// MaxWindow caps how many docs we ask for per call. Keep it modest; ES happily
	// returns 10k but the JSON blows up memory and the result is unusable in a terminal.
	MaxWindow = 2000
)

// Client talks to one Kibana instance.
type Client struct {
	URL  string
	key  string // unexported, and redacted by String/GoString, so %+v of a Client never prints it
	HTTP *http.Client
}

// New builds a client with sane timeouts.
func New(url, key string) *Client {
	return &Client{
		URL:  url,
		key:  key,
		HTTP: &http.Client{Timeout: 120 * time.Second},
	}
}

// hit is one returned document. Source is left raw so callers can pull fields
// without us guessing the schema.
type hit struct {
	Index  string
	ID     string
	Source map[string]any
}

// response is the useful subset of an ES search reply.
type response struct {
	Total int64 // index-wide match count, NOT the number of Hits fetched
	Hits  []hit
	Aggs  map[string]any
	// LastSort is the sort cursor of the final hit, for search_after paging.
	// Offset paging (from/size) cannot pass index.max_result_window (10k).
	LastSort []any
}

// search runs a query body against one or more indexes.
//
// The body is passed through untouched — this is deliberate. Every query the team
// has ever needed is an ES DSL fragment; abstracting it away would only mean
// re-discovering the syntax later.
func (c *Client) search(ctx context.Context, index string, body map[string]any) (*response, error) {
	payload, err := json.Marshal(map[string]any{
		"params": map[string]any{
			"index": index,
			"body":  body,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+SearchPath, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	// The four headers below are what Kibana's internal API requires. Missing any
	// one of them returns 400/401 with a misleading message.
	req.Header.Set("Authorization", "ApiKey "+c.key)
	req.Header.Set("kbn-xsrf", "true")
	req.Header.Set("x-elastic-internal-origin", "Kibana")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		// The key travels in a header, never in the URL, so the url.Error is safe to wrap.
		return nil, fmt.Errorf("%w: kibana request: %w", core.ErrSourceUnavailable, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read kibana response: %w", core.ErrSourceUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		// The body is deliberately not echoed: a proxy may reflect request headers.
		return nil, fmt.Errorf("%w: kibana returned HTTP %d", core.ErrSourceUnavailable, resp.StatusCode)
	}

	// Kibana wraps the ES reply in rawResponse; some versions return ES shape directly.
	var wrapper struct {
		RawResponse json.RawMessage `json:"rawResponse"`
	}
	esBody := raw
	if err := json.Unmarshal(raw, &wrapper); err == nil && len(wrapper.RawResponse) > 0 {
		esBody = wrapper.RawResponse
	}

	var es struct {
		Hits struct {
			Total any `json:"total"`
			Hits  []struct {
				Index  string         `json:"_index"`
				ID     string         `json:"_id"`
				Source map[string]any `json:"_source"`
				Sort   []any          `json:"sort"`
			} `json:"hits"`
		} `json:"hits"`
		Aggregations map[string]any `json:"aggregations"`
		TimedOut     bool           `json:"timed_out"`
		Shards       struct {
			Failed int `json:"failed"`
		} `json:"_shards"`
	}
	if err := json.Unmarshal(esBody, &es); err != nil {
		return nil, fmt.Errorf("decode kibana response: %w", err)
	}
	// A timed-out search or a failed shard returns what it had, as a normal 200. Counts
	// taken from it are low, so it is an error, never a result. Skipped shards are fine.
	// Neither the body nor the shard failure reasons are echoed.
	if es.TimedOut || es.Shards.Failed > 0 {
		return nil, fmt.Errorf("%w: kibana returned a partial response (timed out: %t, failed shards: %d)",
			core.ErrSourceUnavailable, es.TimedOut, es.Shards.Failed)
	}

	out := &response{Aggs: es.Aggregations}
	out.Total = totalValue(es.Hits.Total)
	for _, h := range es.Hits.Hits {
		out.Hits = append(out.Hits, hit{Index: h.Index, ID: h.ID, Source: h.Source})
		if len(h.Sort) > 0 {
			out.LastSort = h.Sort
		}
	}
	return out, nil
}

// totalValue handles both the modern {"value":N} form and the legacy bare number.
func totalValue(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case map[string]any:
		if n, ok := t["value"].(float64); ok {
			return int64(n)
		}
	}
	return 0
}

// String and GoString redact the credential: a Client reaches logs through %v and %+v.
func (c Client) String() string   { return "kibana.Client{URL:" + c.URL + ", key:<redacted>}" }
func (c Client) GoString() string { return c.String() }
