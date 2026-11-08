package contract

import (
	"context"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/jb"
)

// The compile-time table: every function of the command-to-function table in docs/LIBRARY.md is
// assigned to a variable of its documented type. A changed parameter, result or
// receiver stops this package from compiling.
var (
	_ func(context.Context, *jb.Config, jb.HuntOptions) (*jb.Result, error)                               = jb.Hunt
	_ func(context.Context, string, jb.CaseHuntOptions) (*jb.Result, error)                               = jb.HuntCase
	_ func(context.Context, string, jb.ActivityOptions) (*jb.ActivityResult, error)                       = jb.Activity
	_ func(context.Context, string, jb.WatchOptions) (*jb.CycleReport, error)                             = jb.Watch
	_ func(string, jb.WatchStatusOptions) (*jb.WatchStatusResult, error)                                  = jb.WatchStatus
	_ func(string) (*jb.CaseCheckResult, error)                                                           = jb.CaseCheck
	_ func(string, jb.CaseShowOptions) (*jb.CaseShowResult, error)                                        = jb.CaseShow
	_ func(context.Context, jb.DoctorOptions) (*jb.DoctorResult, error)                                   = jb.Doctor
	_ func(context.Context, string, jb.ActorStatusOptions) (*jb.ActorStatusResult, error)                 = jb.ActorStatus
	_ func(context.Context, string, jb.DBOptions) (*jb.DBStatusResult, error)                             = jb.DBStatus
	_ func(context.Context, string, jb.DBOptions) (*jb.DBUsageResult, error)                              = jb.DBUsage
	_ func(context.Context, string, jb.ReputationOptions) (*jb.ReputationResult, error)                   = jb.Reputation
	_ func(context.Context, string, jb.DBPruneOptions) (*jb.DBPruneResult, error)                         = jb.DBPrune
	_ func(context.Context, string, jb.DBCompactOptions) (*jb.DBCompactResult, error)                     = jb.DBCompact
	_ func(context.Context, string, jb.DBRenameSourceOptions) (*jb.DBRenameSourceResult, error)           = jb.DBRenameSource
	_ func(context.Context, string, []string, jb.IntelOptions) (*jb.IntelResult, error)                   = jb.Intel
	_ func(context.Context, string, []string, jb.EstateIPOptions) (*jb.EstateIPResult, error)             = jb.EstateIP
	_ func(context.Context, string, []string, jb.EstateExternalOptions) (*jb.EstateExternalResult, error) = jb.EstateASN
	_ func(context.Context, string, []string, jb.EstateExternalOptions) (*jb.EstateExternalResult, error) = jb.EstateDNS
	_ func(context.Context, string, []string, jb.EstateExternalOptions) (*jb.EstateExternalResult, error) = jb.EstateCT
	_ func(context.Context, string, jb.EstateRefreshOptions) (*jb.EstateRefreshResult, error)             = jb.EstateRefresh
	_ func(context.Context, string, jb.EstateDiffOptions) (*jb.EstateDiffResult, error)                   = jb.EstateDiff
	_ func(string, string, jb.EstateOptions) (*jb.EstatePromoteResult, error)                             = jb.EstatePromote
	_ func(string, string, jb.EstateFactsImportOptions) (*jb.EstateFactsImportResult, error)              = jb.EstateFactsImport
	_ func(jb.DashboardOptions) (http.Handler, *jb.DashboardInfo, error)                                  = jb.DashboardHandler
	_ func(context.Context, jb.ServeOptions) error                                                        = jb.Serve

	// Beyond the table: the entry points of the rest of the surface.
	_ func(string) (*jb.Config, error)                                   = jb.LoadConfig
	_ func(error) bool                                                   = jb.IsUsage
	_ func() []jb.Operation                                              = jb.Operations
	_ func(context.Context, string, map[string]any, jb.Env) (any, error) = jb.Call
	_ func(context.Context, string, map[string]any, jb.Env) (any, error) = jb.CallTool
	_ func(string) (time.Duration, time.Duration)                        = jb.EstateExternalDefaults
	_ func(jb.ReputationResult) bool                                     = func(r jb.ReputationResult) bool { return (&r).Complete() }
)

// documented lists every function name the table above covers.
var documented = map[string]bool{
	"Hunt": true, "HuntCase": true, "Activity": true, "Watch": true, "WatchStatus": true,
	"CaseCheck": true, "CaseShow": true, "Doctor": true, "ActorStatus": true,
	"DBStatus": true, "DBUsage": true, "Reputation": true, "DBPrune": true, "DBCompact": true,
	"DBRenameSource": true, "Intel": true, "EstateIP": true, "EstateASN": true, "EstateDNS": true,
	"EstateCT": true, "EstateRefresh": true, "EstateDiff": true, "EstatePromote": true,
	"EstateFactsImport": true, "DashboardHandler": true, "Serve": true,
}

// TestEveryFunctionOfTheLibraryTableIsInTheCompileTable fails when docs/LIBRARY.md documents a
// function this module does not pin (a new function needs a line above), and when this
// module pins one that page no longer documents.
func TestEveryFunctionOfTheLibraryTableIsInTheCompileTable(t *testing.T) {
	b, err := os.ReadFile("../docs/LIBRARY.md")
	if err != nil {
		t.Fatal(err)
	}
	var cell []string
	in := false
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "| Command | Function |") {
			in = true
			continue
		}
		if !in {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			break
		}
		parts := strings.Split(line, "|")
		if len(parts) >= 3 && !strings.HasPrefix(strings.TrimSpace(parts[2]), "---") {
			cell = append(cell, parts[2])
		}
	}
	if len(cell) == 0 {
		t.Fatal("the command-to-function table of docs/LIBRARY.md was not found")
	}
	paren := regexp.MustCompile(`\([^)]*\)`)
	ident := regexp.MustCompile("`([A-Z][A-Za-z]*)`")
	inLibrary := map[string]bool{}
	for _, c := range cell {
		for _, m := range ident.FindAllStringSubmatch(paren.ReplaceAllString(c, ""), -1) {
			inLibrary[m[1]] = true
		}
	}
	for name := range inLibrary {
		if !documented[name] {
			t.Errorf("docs/LIBRARY.md documents %s but the compile table does not cover it", name)
		}
	}
	for name := range documented {
		if !inLibrary[name] {
			t.Errorf("the compile table covers %s but the docs/LIBRARY.md table does not list it", name)
		}
	}
}

// Not covered by a typed assignment, on purpose:
//   - Config has no exported field or method (RFC 0017, step 6), so there is nothing to
//     list beyond LoadConfig and the functions that take a *Config, which are above.
//   - The aliased result types (Result, ActivityResult, CaseShowResult, CycleReport,
//     WatchStatusResult, StoreUsage and others) are aliases of internal types. Their
//     exported fields are API, but a compile table cannot list them without naming
//     the internal package; the JSON shape goldens (shapes_*_test.go) pin their keys.
