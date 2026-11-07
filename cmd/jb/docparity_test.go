package main

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	jb "github.com/iksnerd/json-bourne"
	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/estateseam"
)

// RFC 0018 pins the key paths of every `--output json` document. The library owns the
// shape (RFC 0013), and the contract module pins it from the consumer side
// (contract/testdata). This test is the CLI side: for each document that the parity
// tests of hunt, activity, case check, doctor, actor status, watch status and the db
// commands do not cover, the CLI prints exactly the key paths of the library value
// asked the same question. It keeps no third copy of the shapes.
func TestCLIDocumentsHaveTheLibraryKeyPaths(t *testing.T) {
	same := func(t *testing.T, cliOut string, lib any, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("library: %v", err)
		}
		cli, want := keyPaths(decode(t, cliOut)), keyPaths(asJSON(t, lib))
		if len(cli) < 3 {
			t.Fatalf("suspiciously few key paths in the CLI document: %v\n%s", cli, cliOut)
		}
		if !reflect.DeepEqual(cli, want) {
			t.Errorf("key paths differ\n cli %v\n lib %v", cli, want)
		}
	}
	ctx := context.Background()

	t.Run("case show", func(t *testing.T) {
		_, out, _ := run(t, testDeps(huntEnv), "case", "show", "--case", exampleCase, "--config", "config/hunt.yaml", "--output", "json")
		lib, err := jb.CaseShow(exampleCase, jb.CaseShowOptions{Config: "config/hunt.yaml"})
		same(t, out, lib, err)
	})

	t.Run("intel", func(t *testing.T) {
		gn := fakeGreyNoise(t, 500)
		cliDir := intelCase(t, gn, "")
		libDir := intelCase(t, gn, "")
		d := intelDeps()
		_, out, _ := run(t, d, "intel", "--case", cliDir, "--output", "json", "192.0.2.7", "192.0.2.50")
		lib, err := jb.Intel(ctx, libDir, []string{"192.0.2.7", "192.0.2.50"}, jb.IntelOptions{Env: d.env})
		same(t, out, lib, err)
	})

	t.Run("estate ip", func(t *testing.T) {
		stubs := func() (*stubPTR, *stubRDAP) {
			return okPTR(), &stubRDAP{errs: map[string]error{"192.0.2.10": fmt.Errorf("%w: HTTP 503", core.ErrLookupFailed)}}
		}
		cliDir, libDir := copyExampleCase(t, ""), copyExampleCase(t, "")
		p, r := stubs()
		_, out, _ := run(t, estateDeps(p, r), "estate", "--case", cliDir, "--output", "json", "192.0.2.10")
		p, r = stubs()
		lib, err := jb.EstateIP(estateseam.With(ctx, estateseam.Ports{PTR: p, RDAP: r}), libDir, []string{"192.0.2.10"}, jb.EstateIPOptions{EstateOptions: jb.EstateOptions{Now: testDeps(nil).now}})
		same(t, out, lib, err)
	})

	t.Run("estate ct", func(t *testing.T) {
		cliDir, libDir := copyExampleCase(t, ""), copyExampleCase(t, "")
		enableExt(t, cliDir, "crt.sh")
		enableExt(t, libDir, "crt.sh")
		st, st2 := newExtStubs(), newExtStubs()
		st.ct.truncated, st2.ct.truncated = true, true
		d := st.deps()
		_, out, _ := run(t, d, "estate", "ct", "--case", cliDir, "--output", "json", "example.com")
		d2 := st2.deps()
		lib, err := jb.EstateCT(estateseam.With(ctx, estateseam.Ports{CT: st2.ct, Sleep: d2.sleep}), libDir, []string{"example.com"}, jb.EstateExternalOptions{EstateOptions: jb.EstateOptions{Now: d2.now}})
		same(t, out, lib, err)
	})

	t.Run("estate diff", func(t *testing.T) {
		dir := copyExampleCase(t, "")
		const file = "example-estate.yaml"
		_, out, _ := run(t, testDeps(nil), "estate", "diff", "--case", dir, "--file", file, "--from", file, "--to", file, "--output", "json")
		lib, err := jb.EstateDiff(ctx, dir, jb.EstateDiffOptions{EstateOptions: jb.EstateOptions{File: file, Now: testDeps(nil).now}, From: file, To: file})
		same(t, out, lib, err)
	})

	t.Run("estate facts import", func(t *testing.T) {
		dir := copyExampleCase(t, "")
		imp := writeCLIImport(t, cliImportDoc)
		const file = "example-estate.yaml"
		_, out, _ := run(t, testDeps(nil), "estate", "facts", "import", "--case", dir, "--file", file, "--output", "json", imp)
		lib, err := jb.EstateFactsImport(dir, imp, jb.EstateFactsImportOptions{EstateOptions: jb.EstateOptions{File: file, Now: testDeps(nil).now}})
		same(t, out, lib, err)
	})
}

// The `watch --once --output json` document has its own encoder (watchjson.go): the
// library returns a Go struct with no JSON tags, so there is no library JSON to compare
// with. Its key paths are pinned here, over a cycle that surfaces a finding.
func TestWatchOnceJSONKeyPaths(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	code, out, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once", "--output", "json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	wantKeys(t, "watch --once", keyPaths(decode(t, out)), []string{
		"alerts[].at", "alerts[].detector", "alerts[].kind", "alerts[].run", "alerts[].severity", "alerts[].tag", "alerts[].text",
		"failed", "healthy", "new", "optional_failed", "pruned.events", "pruned.findings", "pruned.runs",
		"recovered", "repeated", "run", "status", "suppressed", "window[]",
	})
}
