package watchstate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/iksnerd/json-bourne/internal/core"
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
	f, err := os.Open(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return core.WatchState{}, fmt.Errorf("%w: no watch state at %s", core.ErrAbsent, s.Path)
	}
	if err != nil {
		return core.WatchState{}, fmt.Errorf("read watch state: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxPeekBytes+1))
	if err != nil {
		return core.WatchState{}, fmt.Errorf("read watch state: %w", err)
	}
	if len(b) > maxPeekBytes {
		return core.WatchState{}, fmt.Errorf("%w: %s is larger than %d bytes", core.ErrStateCorrupt, s.Path, maxPeekBytes)
	}
	st, perr := parse(b)
	if perr != nil {
		return core.WatchState{}, fmt.Errorf("%w: %s: %v", core.ErrStateCorrupt, s.Path, perr)
	}
	return st, nil
}
