package config

import (
	"context"
	"fmt"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
)

// OpenRunStore opens and migrates the store a hunt or activity run writes to. With
// noStore it is a private temporary store (duckdb.OpenTemp) and the configured path is
// never opened, created or changed; otherwise it is the file at cfg.StorePath(). Either
// way the run is the same code over the same schema. The caller must Close the result
// on every path; Close removes a temporary store.
//
// keepOut lists directories (the case, its evidence directory) that a temporary store
// must not be inside. If TMPDIR points into one, the run is refused and the directory
// already made is removed.
func OpenRunStore(ctx context.Context, cfg *File, noStore bool, keepOut ...string) (*duckdb.Store, error) {
	var st *duckdb.Store
	var err error
	if noStore {
		st, err = duckdb.OpenTemp(ctx)
		if err == nil {
			for _, k := range keepOut {
				if k != "" && InsideDir(k, st.TempDir()) {
					dir := st.TempDir()
					_ = st.Close() // removes the directory
					return nil, fmt.Errorf("--no-store: the temporary directory %s would be inside %s; set TMPDIR to a directory outside the case", dir, k)
				}
			}
		}
	} else {
		st, err = duckdb.OpenContext(ctx, cfg.StorePath(), false, duckdb.OpenOptions{})
	}
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if _, err := st.Migrate(); err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	return st, nil
}
