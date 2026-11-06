package core

import (
	"context"
	"errors"
)

// The store keys an event by its source label (docs/ARCHITECTURE.md, "Event
// identity"). The same documents saved once under a source's default label
// (kibana:<index>) and again under an explicit name are therefore two sets, and a
// detector that reads both counts every document twice. These types let a command
// say so (SourceOverlap) and fix it (SourceRelabeler) without changing the identity rule.

var (
	// ErrSourceOverlap means the target label already holds documents the old label also
	// holds, and a plain relabel would not say what to do with them.
	ErrSourceOverlap = errors.New("the new source label already holds some of the same documents")
	// ErrNoSuchSource means no stored event carries the label to rename.
	ErrNoSuchSource = errors.New("no stored event carries that source label")
)

// SourceOverlap says that Docs distinct documents (by time, kind and content digest) are
// stored under both labels. A < B.
type SourceOverlap struct {
	A, B string
	Docs int64
}

// SourceOverlapReader finds documents stored under more than one source label inside a
// window. It reads only, bounded by limit pairs of labels, and an empty result means
// no label shares a document with another.
type SourceOverlapReader interface {
	SourceOverlaps(ctx context.Context, w Window, limit int) ([]SourceOverlap, error)
}

// RenameSourceRequest asks to relabel every event stored under Old as New. Run ids are
// never touched. DryRun counts and changes nothing (and works on a read-only handle).
// Merge permits New to already hold some of Old's documents: the rows of Old that
// would collide with a row under New on the identity rule are dropped.
type RenameSourceRequest struct {
	Old, New string
	Merge    bool
	DryRun   bool
}

// RenameSourceResult counts a rename. On a refusal (ErrSourceOverlap, ErrNoSuchSource)
// the counts describe what was found and Applied is false.
type RenameSourceResult struct {
	Old, New   string
	Applied    bool
	Events     int64 // rows under Old
	Runs       int64 // runs holding rows under Old
	NewEvents  int64 // rows already under New
	Overlap    int64 // distinct (time, kind, digest) documents under both labels
	Dropped    int64 // rows of Old removed because New holds them (Merge only)
	Relabelled int64 // rows that carry New afterwards because of this rename
	NoRaw      int64 // rows of Old with no raw document: their digest covers the old label and is left as stored
}

// SourceRelabeler renames a source label in the store, in one transaction.
type SourceRelabeler interface {
	RenameSource(ctx context.Context, req RenameSourceRequest) (RenameSourceResult, error)
}
