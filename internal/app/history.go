package app

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/iksnerd/json-bourne/internal/core"
)

// indexNamer is implemented by a source that can say which index it reads. With
// core.DocScoped (the cluster) it identifies the store a count is taken from.
type indexNamer interface{ IndexName() string }

// modeNamer is implemented by a source that matches keys in a stated mode.
type modeNamer interface{ KeyMode() string }

// indexUnioner is implemented by a source that can count its cluster over the union of
// several index expressions in one request, which Elasticsearch de-duplicates.
type indexUnioner interface {
	CountingIndices(indices []string) (core.KeyCounter, error)
}

// historyGroup is one cluster. Several sources can read it, with different filters and
// index patterns that may overlap; the probe drops the filters, so counting each source
// or pattern would count a shared document again. The cluster is probed once, over the
// union of its sources' index expressions.
type historyGroup struct {
	label   string // for errors: the source that speaks for the group, and its indices
	kc      core.KeyCounter
	rep     indexUnioner // the source that speaks for the group, when it can count a union
	indices []string
}

// keyHistory is the core.KeyHistory of one detector, built from the sources it reads.
// It holds no mutable state after construction, so it is safe for concurrent use.
type keyHistory struct {
	groups []historyGroup
	modes  []string
	err    error // a source that cannot count; reported when Counts is called, not before
}

var _ core.KeyHistory = (*keyHistory)(nil)

// newKeyHistory groups srcs by cluster (core.DocScoped). A source without core.KeyCounter makes
// every Counts call fail, naming it: the history is only asked for by a detector that
// needs it, so a detector that never asks is not refused for the sources it reads.
func newKeyHistory(srcs []core.Source) *keyHistory {
	h := &keyHistory{}
	groupAt := map[string]int{}
	for _, s := range srcs {
		kc, ok := s.(core.KeyCounter)
		if !ok {
			if h.err == nil {
				h.err = fmt.Errorf("history: source %q cannot count keys (it is not a kibana source with key_match)", s.Name())
			}
			continue
		}
		index := ""
		if in, ok := s.(indexNamer); ok {
			index = in.IndexName()
		}
		scope := ""
		if ds, ok := s.(core.DocScoped); ok {
			scope = ds.DocScope()
		}
		iu, canUnion := s.(indexUnioner)
		key := scope
		if scope == "" || index == "" {
			key = "\x00source\x00" + s.Name() // cannot prove two sources share a cluster
		} else if !canUnion {
			key += "\x00" + index // cannot probe a union, so each index is its own group
		}
		if gi, ok := groupAt[key]; ok {
			if g := &h.groups[gi]; index != "" && !slices.Contains(g.indices, index) {
				g.indices = append(g.indices, index)
			}
			continue
		}
		groupAt[key] = len(h.groups)
		g := historyGroup{label: fmt.Sprintf("source %q", s.Name()), kc: kc}
		if index != "" {
			g.indices = []string{index}
		}
		if canUnion && scope != "" && index != "" {
			g.rep = iu
		}
		h.groups = append(h.groups, g)
		if mn, ok := s.(modeNamer); ok {
			if m := mn.KeyMode(); m != "" && !slices.Contains(h.modes, m) {
				h.modes = append(h.modes, m)
			}
		}
	}
	for i := range h.groups {
		g := &h.groups[i]
		if len(g.indices) > 0 {
			g.label += fmt.Sprintf(" (index %q)", strings.Join(g.indices, ","))
		}
		if len(g.indices) > 1 && g.rep != nil {
			kc, err := g.rep.CountingIndices(g.indices)
			if err != nil {
				if h.err == nil {
					h.err = fmt.Errorf("history: %s: %w", g.label, err)
				}
				continue
			}
			g.kc = kc
		}
	}
	slices.Sort(h.modes)
	return h
}

// MatchMode names how the sources match a key: "term", "phrase", or both joined by "+"
// when the indices differ. The finding records it.
func (h *keyHistory) MatchMode() string { return strings.Join(h.modes, "+") }

// Counts sums, over the distinct indices, how many events of any kind carried each key
// in w. Before it counts keys it asks every index how many events it holds in w at all:
// an index with none cannot show history, and its zeros would make every key look new.
// That, a source that cannot count and any failure are errors.
func (h *keyHistory) Counts(ctx context.Context, keys []string, w core.Window) (map[string]int64, error) {
	if h.err != nil {
		return nil, h.err
	}
	if len(h.groups) == 0 {
		return nil, fmt.Errorf("history: the detector reads no source that can count keys")
	}
	for _, g := range h.groups {
		n, err := g.kc.CountAll(ctx, w)
		if err != nil {
			return nil, fmt.Errorf("history: %s: %w", g.label, err)
		}
		if n == 0 {
			return nil, fmt.Errorf("history: %s holds no events in [%s, %s), so it cannot show history; a zero count would make every key look new",
				g.label, w.From.UTC().Format("2006-01-02T15:04:05Z"), w.To.UTC().Format("2006-01-02T15:04:05Z"))
		}
	}
	total := make(map[string]int64, len(keys))
	for _, k := range keys {
		total[k] = 0
	}
	for _, g := range h.groups {
		got, err := g.kc.CountKeys(ctx, keys, w)
		if err != nil {
			return nil, fmt.Errorf("history: %s: %w", g.label, err)
		}
		for _, k := range keys {
			n, ok := got[k]
			if !ok {
				return nil, fmt.Errorf("history: %s did not answer for every key", g.label)
			}
			total[k] += n
		}
	}
	return total, nil
}

// historyFor builds the KeyHistory of one detector from the sources it reads: the sources
// of its scope, else all of them. Hunt is the one place detectors run, and Activity and
// Watch both run through it, so there is one path.
func (d Deps) historyFor(detector string) core.KeyHistory {
	names, scoped := d.Scopes[detector]
	var srcs []core.Source
	for _, s := range d.Sources {
		if !scoped || slices.Contains(names, s.Name()) {
			srcs = append(srcs, s)
		}
	}
	return newKeyHistory(srcs)
}
