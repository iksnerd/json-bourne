package main

import (
	"os"
	"strings"
	"testing"
)

// TestEstateAndIntelCommandsCallTheLibrary holds RFC 0013's "one path" rule for these
// commands: each calls its function in package jb and none re-implements it, so the
// CLI and the library cannot drift.
func TestEstateAndIntelCommandsCallTheLibrary(t *testing.T) {
	calls := map[string][]string{
		"intel.go":        {"jb.Intel("},
		"estate.go":       {"jb.EstateIP("},
		"estate_ext.go":   {"jb.EstateASN", "jb.EstateDNS", "jb.EstateCT"},
		"estate_drift.go": {"jb.EstateRefresh(", "jb.EstateDiff(", "jb.EstatePromote("},
	}
	// Each of these is a step of an operation the library owns.
	forbidden := []string{"app.Intel(", "app.CollectEstate", "app.CollectASN", "app.CollectDNS", "app.CollectCT",
		"app.RefreshEstate", "app.DiffEstates", "app.DriftFindings", "app.DeliverDrift", "app.PromoteSnapshot",
		"casefile.MergeEstate", "casefile.SaveEstateFile", "casefile.WriteEstateSnapshot", "casefile.LoadEstateFile",
		"rdap.New(", "bgp.New(", "dnsfwd.New(", "dnsptr.New(", "BuildFeeds(", "duckdb."}
	for file, want := range calls {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, w := range want {
			if !strings.Contains(src, w) {
				t.Errorf("%s does not call %s", file, w)
			}
		}
		for _, f := range forbidden {
			if strings.Contains(src, f) {
				t.Errorf("%s uses %s: that step belongs to the library", file, f)
			}
		}
	}
}
