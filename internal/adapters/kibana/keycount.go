package kibana

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Match modes of KeyMatch (RFC 0014). There is no default: a wrong mode returns zero for
// every key (a term on an analysed field) or over-counts (a phrase), so the operator
// chooses.
const (
	// ModeTerm matches the key as the exact value of a keyword field.
	ModeTerm = "term"
	// ModePhrase matches the key as a phrase in an analysed field. It can over-count (an
	// IPv6 address splits into tokens; an address can be a hop of a forwarded-for chain
	// or sit in the body of the text), which hides a new key and never invents one.
	ModePhrase = "phrase"
)

// KeyMatch says how a key is found in this index: which raw field of the index holds it
// and how it is matched. It is index vocabulary, so it lives on the source, beside the
// source's filter.
type KeyMatch struct {
	Field string
	Mode  string
}

const (
	maxKeyBytes = 256
	// keysAgg is the name of the filters aggregation. Buckets are named k0, k1, ...: a key
	// is a value in the request body and never a name.
	keysAgg = "keys"
)

var (
	_ core.KeyCounter = (*Source)(nil)

	errNoKeyMatch = errors.New("kibana: history needs key_match (field and mode) on this source")
)

// KeyMode is the match mode of this source ("term" or "phrase"), or "" without key_match.
func (s *Source) KeyMode() string {
	if s.KeyMatch == nil {
		return ""
	}
	return s.KeyMatch.Mode
}

// IndexName is the index this source reads. With the cluster (DocScope) it identifies
// the store a history count is taken from.
func (s *Source) IndexName() string { return s.Index }

// safeKey reports whether k may be sent: letters, digits and . : @ _ - only, 1 to 256
// bytes. A key reaches the index as a JSON string value, so this is a second line, and
// it keeps query syntax (a quote, a wildcard, a space, an operator) out of a phrase.
func safeKey(k string) bool {
	if k == "" || len(k) > maxKeyBytes {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == ':', c == '@', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func (s *Source) keyMatch() (*KeyMatch, error) {
	km := s.KeyMatch
	if km == nil || km.Field == "" || (km.Mode != ModeTerm && km.Mode != ModePhrase) {
		return nil, errNoKeyMatch
	}
	return km, nil
}

func (s *Source) historyRange(w core.Window) map[string]any {
	tf := s.TimeField
	if tf == "" {
		tf = "@timestamp"
	}
	return map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"range": map[string]any{tf: map[string]any{
			"gte": w.From.UTC().Format(time.RFC3339Nano),
			"lt":  w.To.UTC().Format(time.RFC3339Nano),
		}}},
	}}}
}

// CountKeys counts, in one search request, how many events of any kind carry each key in
// w. The source's own filter is not applied: it dropped events, and the question is how
// many exist. Every key maps to its count, 0 included. A key that is not safe to send
// fails the call before any request. No error or log line carries a key.
func (s *Source) CountKeys(ctx context.Context, keys []string, w core.Window) (map[string]int64, error) {
	return s.countKeys(ctx, s.Index, keys, w)
}

func (s *Source) countKeys(ctx context.Context, index string, keys []string, w core.Window) (map[string]int64, error) {
	km, err := s.keyMatch()
	if err != nil {
		return nil, err
	}
	distinct := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	refused := 0
	for _, k := range keys {
		if !safeKey(k) {
			refused++
			continue
		}
		if _, dup := seen[k]; !dup {
			seen[k] = struct{}{}
			distinct = append(distinct, k)
		}
	}
	if refused > 0 {
		return nil, fmt.Errorf("kibana: history refused %d key(s) that are empty, over %d bytes or use characters outside letters, digits and . : @ _ -; nothing was sent", refused, maxKeyBytes)
	}
	if len(distinct) == 0 {
		return map[string]int64{}, nil
	}
	buckets := make(map[string]any, len(distinct))
	for i, k := range distinct {
		kind := "match_phrase"
		if km.Mode == ModeTerm {
			kind = "term"
		}
		buckets["k"+strconv.Itoa(i)] = map[string]any{kind: map[string]any{km.Field: k}}
	}
	body := map[string]any{
		"size":             0,
		"track_total_hits": false,
		"query":            s.historyRange(w),
		"aggs":             map[string]any{keysAgg: map[string]any{"filters": map[string]any{"filters": buckets}}},
	}
	resp, err := s.Client.search(ctx, index, body)
	if err != nil {
		return nil, fmt.Errorf("kibana: history count: %w", err)
	}
	agg, ok := resp.Aggs[keysAgg].(map[string]any)
	if !ok {
		return nil, errors.New("kibana: history count: the answer has no aggregation")
	}
	got, ok := agg["buckets"].(map[string]any)
	if !ok {
		return nil, errors.New("kibana: history count: the answer has no buckets")
	}
	out := make(map[string]int64, len(distinct))
	for i, k := range distinct {
		b, ok := got["k"+strconv.Itoa(i)].(map[string]any)
		if !ok {
			return nil, errors.New("kibana: history count: the answer lacks a bucket for a key")
		}
		n, ok := b["doc_count"].(float64)
		if !ok || n < 0 {
			return nil, errors.New("kibana: history count: a bucket has no valid count")
		}
		out[k] = int64(n)
	}
	return out, nil
}

// CountAll reports how many events of any kind the index holds in w: the same range as
// CountKeys, with no key clause and no source filter. A zero means this index cannot
// show history for w.
func (s *Source) CountAll(ctx context.Context, w core.Window) (int64, error) {
	return s.countAll(ctx, s.Index, w)
}

func (s *Source) countAll(ctx context.Context, index string, w core.Window) (int64, error) {
	if _, err := s.keyMatch(); err != nil {
		return 0, err
	}
	body := map[string]any{
		"size":             0,
		"track_total_hits": true,
		"query":            s.historyRange(w),
	}
	resp, err := s.Client.search(ctx, index, body)
	if err != nil {
		return 0, fmt.Errorf("kibana: history liveness count: %w", err)
	}
	return resp.Total, nil
}

// CountingIndices returns a counter that probes the union of indices, one request for
// CountKeys and one for CountAll, with this source's cluster, time field and key_match.
// The expressions go out as one comma-separated target, so Elasticsearch counts a
// document that matches several of them once. An empty expression, or one holding a
// comma or whitespace, is refused: it would change what the target means.
func (s *Source) CountingIndices(indices []string) (core.KeyCounter, error) {
	if len(indices) == 0 {
		return nil, errors.New("kibana: history needs at least one index")
	}
	seen := make(map[string]struct{}, len(indices))
	distinct := make([]string, 0, len(indices))
	for _, in := range indices {
		if in == "" || strings.ContainsAny(in, ", \t\r\n") {
			return nil, errors.New("kibana: history refused an index expression that is empty or holds a comma or whitespace")
		}
		if _, dup := seen[in]; !dup {
			seen[in] = struct{}{}
			distinct = append(distinct, in)
		}
	}
	return indexUnion{s: s, index: strings.Join(distinct, ",")}, nil
}

// indexUnion is a core.KeyCounter over one multi-target index expression of a source.
type indexUnion struct {
	s     *Source
	index string
}

func (u indexUnion) CountKeys(ctx context.Context, keys []string, w core.Window) (map[string]int64, error) {
	return u.s.countKeys(ctx, u.index, keys, w)
}

func (u indexUnion) CountAll(ctx context.Context, w core.Window) (int64, error) {
	return u.s.countAll(ctx, u.index, w)
}
