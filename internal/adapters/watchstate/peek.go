package watchstate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/safefile"
)

var _ core.WatchStatePeeker = Store{}

// maxPeekBytes bounds what a viewer will read; the writer's file is a few KiB.
const maxPeekBytes = 8 << 20

// Peek reads the state like Load but changes nothing: a corrupt file is reported
// (wrapping core.ErrStateCorrupt) and left where it is, because moving it aside is
// the watcher's decision. A missing file is core.ErrAbsent, not an empty state, so a
// viewer can say "no watch has run here".
func (s Store) Peek(ctx context.Context) (core.WatchState, error) {
	if err := ctx.Err(); err != nil {
		return core.WatchState{}, err
	}
	b, err := safefile.ReadAll(s.Path, maxPeekBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return core.WatchState{}, fmt.Errorf("%w: no watch state at %s", core.ErrAbsent, s.Path)
	case errors.Is(err, safefile.ErrTooLarge), errors.Is(err, safefile.ErrNotRegular):
		return core.WatchState{}, fmt.Errorf("%w: %v", core.ErrStateCorrupt, err)
	case err != nil:
		return core.WatchState{}, fmt.Errorf("read watch state: %w", err)
	}
	st, perr := parse(b)
	if perr != nil {
		return core.WatchState{}, fmt.Errorf("%w: %s: %v", core.ErrStateCorrupt, s.Path, perr)
	}
	return st, nil
}
