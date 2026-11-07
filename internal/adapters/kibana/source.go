package kibana

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"slices"
	"sync"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	// DefaultPageSize is used when Source.PageSize is zero.
	DefaultPageSize = 1000
	// MaxPageSize bounds a page; ES refuses more than index.max_result_window anyway.
	MaxPageSize = 10000
)

// Mapper turns one raw hit's _source into a normalised event. Injecting it keeps
// the adapter independent of any one log format.
type Mapper func(src map[string]any) (core.Event, error)

// Stats separates two numbers that must never be subtracted from each other.
// HitsTotal is the index-wide match count ES reported for the first page of the
// last Fetch; Fetched is how many documents this adapter actually received.
type Stats struct {
	HitsTotal int64
	Fetched   int
	// Unparsable counts documents the mapper refused with ErrUnparsable. They are
	// not in Fetched and not yielded; this is the only place they show.
	Unparsable int
	// IndexTotal is set only when a filtered fetch matched nothing: the number of
	// documents in the same window without the filter. A positive value is what makes
	// an empty filtered result a quiet answer and not a dead source.
	IndexTotal int64
	// Probed is true when that probe ran and found the index alive. IndexTotal is
	// meaningful only then.
	Probed bool
}

// Source streams events for a window from one index, paging by timestamp cursor.
type Source struct {
	Client *Client
	Index  string
	// Label names the source in events, run ids and output. Empty means "kibana:<Index>".
	// Two sources on one index need different labels.
	Label     string
	TimeField string         // defaults to "@timestamp"
	Query     map[string]any // optional ES query clause ANDed with the window filter
	Map       Mapper         // defaults to DefaultMap
	// Batch, when set, maps each page of new documents in one call and replaces Map. It is
	// how an out-of-process mapper plugs in. An error from it fails the fetch: the source
	// never goes on without the documents it could not map.
	Batch    core.BatchMapper
	PageSize int // defaults to DefaultPageSize
	// KeyMatch, when set, lets the source count keys for a detector's history probe
	// (core.KeyCounter). Without it CountKeys and CountAll refuse.
	KeyMatch *KeyMatch

	mu    sync.Mutex
	stats Stats
}

var _ core.Source = (*Source)(nil)

// Name identifies the source in events and errors.
func (s *Source) Name() string {
	if s.Label != "" {
		return s.Label
	}
	return "kibana:" + s.Index
}

// DocScope is the cluster this source reads, so Hunt can count a document once when two
// sources on the same cluster both return it (core.DocScoped).
func (s *Source) DocScope() string { return s.Client.URL }

var _ core.DocScoped = (*Source)(nil)

// Stats reports the counts of the most recent Fetch. See Stats for why the two
// fields are kept apart.
func (s *Source) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// Unparsable is Stats().Unparsable, so the use case can see it without importing
// this package (core.ParseCounter).
func (s *Source) Unparsable() int { return s.Stats().Unparsable }

var _ core.ParseCounter = (*Source)(nil)

// Liveness reports whether the most recent Fetch matched nothing through a filter and
// then proved the index alive by counting the same window without it. The count is the
// answer of that probe, not a total minus anything.
func (s *Source) Liveness() core.Liveness {
	st := s.Stats()
	return core.Liveness{Probed: st.Probed, IndexTotal: st.IndexTotal}
}

var _ core.LivenessReporter = (*Source)(nil)

// Close releases the batch mapper's resources (a plugin's child process) if it holds
// any. It is safe to call more than once and on a source without a batch mapper.
func (s *Source) Close() error {
	if c, ok := s.Batch.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (s *Source) setStats(st Stats) {
	s.mu.Lock()
	s.stats = st
	s.mu.Unlock()
}

// DefaultMap puts @timestamp in Time and the whole _source in Fields and Raw.
func DefaultMap(src map[string]any) (core.Event, error) {
	ts, _ := src["@timestamp"].(string)
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return core.Event{}, fmt.Errorf("kibana: bad or missing @timestamp: %w", err)
	}
	raw, err := json.Marshal(src)
	if err != nil {
		return core.Event{}, fmt.Errorf("kibana: marshal raw: %w", err)
	}
	return core.Event{Time: t, Fields: src, Raw: raw}, nil
}

// Fetch streams every event in the half-open window [From, To). It stops when ctx
// ends, yielding ctx.Err(). A window with no events at all yields core.ErrNoRecords.
func (s *Source) Fetch(ctx context.Context, w core.Window) iter.Seq2[core.Event, error] {
	return func(yield func(core.Event, error) bool) {
		s.setStats(Stats{})
		tf := s.TimeField
		if tf == "" {
			tf = "@timestamp"
		}
		mp := s.Map
		if mp == nil {
			mp = DefaultMap
		}
		size := s.PageSize
		if size <= 0 {
			size = DefaultPageSize
		}
		size = min(size, MaxPageSize)

		filter := []any{map[string]any{"range": map[string]any{tf: map[string]any{
			"gte": w.From.UTC().Format(time.RFC3339Nano),
			"lt":  w.To.UTC().Format(time.RFC3339Nano),
		}}}}
		if s.Query != nil {
			filter = append(filter, s.Query)
		}

		// Paging is by timestamp cursor, not search_after on an _id tiebreaker: on our
		// Kibana (8.5.1) any sort that includes _id returns total 0 and no hits with no
		// error, which reads as a quiet window. Every page after the first re-runs the
		// query with time >= the last timestamp seen; documents already read are
		// dropped by index and id, so a tie across a page boundary is neither lost nor
		// doubled.
		seen := map[string]struct{}{}
		cursor := int64(-1)
		var st Stats
		for first := true; ; first = false {
			if err := ctx.Err(); err != nil {
				yield(core.Event{}, err)
				return
			}
			pageFilter := filter
			if cursor >= 0 {
				pageFilter = append(slices.Clone(filter), map[string]any{"range": map[string]any{tf: map[string]any{
					"gte": cursor, "format": "epoch_millis",
				}}})
			}
			body := map[string]any{
				"size":             size,
				"track_total_hits": true,
				"query":            map[string]any{"bool": map[string]any{"filter": pageFilter}},
				"sort":             []any{map[string]any{tf: "asc"}},
			}
			resp, err := s.Client.search(ctx, s.Index, body)
			if err != nil {
				yield(core.Event{}, err)
				return
			}
			if first {
				st.HitsTotal = resp.Total
			}
			// Documents already read (a tie across a page boundary) are dropped first, so
			// the mapper only ever sees a document once.
			fresh := make([]hit, 0, len(resp.Hits))
			for _, h := range resp.Hits {
				k := h.Index + "/" + h.ID
				if _, dup := seen[k]; dup {
					continue
				}
				seen[k] = struct{}{}
				fresh = append(fresh, h)
			}
			added := len(fresh)
			var batch []core.MapResult
			if s.Batch != nil && len(fresh) > 0 {
				srcs := make([]map[string]any, len(fresh))
				for i, h := range fresh {
					srcs[i] = h.Source
				}
				var berr error
				batch, berr = s.Batch.MapBatch(ctx, srcs)
				if berr != nil {
					yield(core.Event{}, fmt.Errorf("map page of %d documents: %w", len(fresh), berr))
					return
				}
				if len(batch) != len(fresh) {
					yield(core.Event{}, fmt.Errorf("map page: mapper returned %d results for %d documents", len(batch), len(fresh)))
					return
				}
			}
			for i, h := range fresh {
				var ev core.Event
				var err error
				if batch != nil {
					if batch[i].Unparsable {
						err = ErrUnparsable
					} else {
						ev = batch[i].Event
						if raw, merr := json.Marshal(h.Source); merr != nil {
							err = fmt.Errorf("kibana: marshal raw: %w", merr)
						} else {
							ev.Raw = raw
						}
					}
				} else {
					ev, err = mp(h.Source)
				}
				if errors.Is(err, ErrUnparsable) {
					st.Unparsable++
					s.setStats(st)
					continue
				}
				if err != nil {
					yield(core.Event{}, fmt.Errorf("map hit %s: %w", h.ID, err))
					return
				}
				if ev.Source == "" {
					ev.Source = s.Name()
				}
				ev.DocKey = h.Index + "/" + h.ID
				st.Fetched++
				s.setStats(st)
				if !yield(ev, nil) {
					return
				}
			}
			s.setStats(st)
			if len(resp.Hits) < size {
				break
			}
			if added == 0 {
				yield(core.Event{}, fmt.Errorf("kibana: a full page of %d documents shares one %s millisecond; cannot page past it (narrow the window or raise PageSize)", size, tf))
				return
			}
			if len(resp.LastSort) == 0 {
				yield(core.Event{}, errors.New("kibana: response carries no sort cursor; cannot page"))
				return
			}
			ms, ok := resp.LastSort[0].(float64)
			if !ok {
				yield(core.Event{}, fmt.Errorf("kibana: sort cursor %v is not an epoch_millis timestamp", resp.LastSort[0]))
				return
			}
			cursor = int64(ms)
		}
		if st.Fetched == 0 && st.Unparsable > 0 {
			yield(core.Event{}, fmt.Errorf("%w: %s returned %d unparsable documents and none that parsed for [%s, %s); the mapper does not match this index",
				core.ErrNoRecords, s.Name(), st.Unparsable, w.From.UTC().Format(time.RFC3339), w.To.UTC().Format(time.RFC3339)))
			return
		}
		if st.Fetched == 0 && s.Query != nil {
			// A selective filter makes "nothing matched" a normal answer, but only if the
			// index is shown to be alive in the same window. Count it without the filter:
			// a silent index or a wrong index name still fails below as no records.
			probe := map[string]any{
				"size":             0,
				"track_total_hits": true,
				"query": map[string]any{"bool": map[string]any{"filter": []any{
					map[string]any{"range": map[string]any{tf: map[string]any{
						"gte": w.From.UTC().Format(time.RFC3339Nano),
						"lt":  w.To.UTC().Format(time.RFC3339Nano),
					}}},
				}}},
			}
			resp, err := s.Client.search(ctx, s.Index, probe)
			if err != nil {
				yield(core.Event{}, fmt.Errorf("kibana: liveness probe for an empty filtered window: %w", err))
				return
			}
			if resp.Total > 0 {
				st.IndexTotal, st.Probed = resp.Total, true
				s.setStats(st)
				return
			}
		}
		if st.Fetched == 0 {
			yield(core.Event{}, fmt.Errorf("%w: %s returned no hits for [%s, %s)",
				core.ErrNoRecords, s.Name(), w.From.UTC().Format(time.RFC3339), w.To.UTC().Format(time.RFC3339)))
		}
	}
}
