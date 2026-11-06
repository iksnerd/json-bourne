package duckdb

import (
	"database/sql"
	"fmt"
	"runtime/debug"
)

const driverModule = "github.com/duckdb/duckdb-go/v2"

// DriverVersion is the version of the duckdb-go module this binary was built with, or
// "unknown" when the build carries no module information.
func DriverVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == driverModule {
				if d.Replace != nil && d.Replace.Version != "" {
					return d.Replace.Version
				}
				return d.Version
			}
		}
	}
	return "unknown"
}

// EngineVersion starts a private in-memory database and asks it for its version. It
// touches no file, and proves the cgo library loads.
func EngineVersion() (string, error) {
	db, err := sql.Open("duckdb", "")
	if err != nil {
		return "", fmt.Errorf("open in-memory duckdb: %w", err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow(`SELECT version()`).Scan(&v); err != nil {
		return "", fmt.Errorf("select version(): %w", err)
	}
	return v, nil
}
