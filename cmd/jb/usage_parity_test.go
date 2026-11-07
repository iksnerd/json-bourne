package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	jb "github.com/iksnerd/json-bourne"
)

// TestUsageClassMatchesExitCode walks one table of caller mistakes and some failures
// that are not mistakes. For each row the CLI exits 2 exactly when jb.IsUsage is true
// for the same mistake made through the Go function. wantUsage pins the expected class
// so a table that drifts to all-false cannot pass.
func TestUsageClassMatchesExitCode(t *testing.T) {
	env := func(k string) (string, bool) { v, ok := huntEnv[k]; return v, ok }
	now := func() time.Time { return fixedNow }
	future := fixedNow.Add(time.Hour).Format(time.RFC3339)
	past := fixedNow.Add(-time.Hour)

	okDir, _ := watchCase(t, http.StatusOK)
	downDir, _ := watchCase(t, http.StatusInternalServerError)
	emptyDir := t.TempDir()
	srv := fakeKibana(t, http.StatusOK)
	cfgPath := writeConfig(t, srv.URL)
	cfg, err := jb.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	hunt := func(o jb.HuntOptions) func(context.Context) error {
		o.Env, o.Now = env, now
		return func(ctx context.Context) error { _, err := jb.Hunt(ctx, cfg, o); return err }
	}
	huntCaseLib := func(dir string, o jb.CaseHuntOptions) func(context.Context) error {
		o.Env, o.Now = env, now
		return func(ctx context.Context) error { _, err := jb.HuntCase(ctx, dir, o); return err }
	}
	activity := func(dir string, o jb.ActivityOptions) func(context.Context) error {
		o.Env, o.Now = env, now
		return func(ctx context.Context) error { _, err := jb.Activity(ctx, dir, o); return err }
	}
	watch := func(dir string, o jb.WatchOptions) func(context.Context) error {
		o.Env, o.Now, o.Once = env, now, true
		return func(ctx context.Context) error { _, err := jb.Watch(ctx, dir, o); return err }
	}

	rows := []struct {
		name      string
		cli       []string
		lib       func(context.Context) error
		wantUsage bool
	}{
		{"hunt negative window", []string{"hunt", "--config", cfgPath, "--window", "-5m"}, hunt(jb.HuntOptions{Window: -5 * time.Minute}), true},
		{"hunt until in the future", []string{"hunt", "--config", cfgPath, "--until", future}, hunt(jb.HuntOptions{Until: fixedNow.Add(time.Hour)}), true},
		{"hunt window too long for a past window", []string{"hunt", "--config", cfgPath, "--until", past.Format(time.RFC3339), "--window", "800h"}, hunt(jb.HuntOptions{Until: past, Window: 800 * time.Hour}), true},
		{"hunt case config outside the case", []string{"hunt", "--case", okDir, "--config", "../outside.yaml"}, huntCaseLib(okDir, jb.CaseHuntOptions{Config: "../outside.yaml"}), true},
		{"hunt case window negative", []string{"hunt", "--case", okDir, "--window", "-1h"}, huntCaseLib(okDir, jb.CaseHuntOptions{HuntOptions: jb.HuntOptions{Window: -time.Hour}}), true},
		{"hunt case not found", []string{"hunt", "--case", emptyDir}, huntCaseLib(emptyDir, jb.CaseHuntOptions{}), false},
		{"hunt credential missing", []string{"hunt", "--config", cfgPath}, func(ctx context.Context) error {
			_, err := jb.Hunt(ctx, cfg, jb.HuntOptions{Env: func(string) (string, bool) { return "", false }, Now: now})
			return err
		}, false},
		{"activity negative window", []string{"activity", "--case", okDir, "--window", "-1h"}, activity(okDir, jb.ActivityOptions{Window: -time.Hour}), true},
		{"activity until in the future", []string{"activity", "--case", okDir, "--until", future}, activity(okDir, jb.ActivityOptions{Until: fixedNow.Add(time.Hour)}), true},
		{"activity case not found", []string{"activity", "--case", emptyDir}, activity(emptyDir, jb.ActivityOptions{}), false},
		{"watch bad name", []string{"watch", "--case", okDir, "--once", "--name", "Bad Name"}, watch(okDir, jb.WatchOptions{Name: "Bad Name"}), true},
		{"watch window shorter than interval", []string{"watch", "--case", okDir, "--once", "--every", "10m", "--window", "5m"}, watch(okDir, jb.WatchOptions{Every: 10 * time.Minute, Window: 5 * time.Minute}), true},
		{"watch negative every", []string{"watch", "--case", okDir, "--once", "--every", "-1m"}, watch(okDir, jb.WatchOptions{Every: -time.Minute}), true},
		{"watch every below minimum", []string{"watch", "--case", okDir, "--once", "--every", "1s"}, watch(okDir, jb.WatchOptions{Every: time.Second}), true},
		{"watch case not found", []string{"watch", "--case", emptyDir, "--once"}, watch(emptyDir, jb.WatchOptions{}), false},
		{"watch unreachable source", []string{"watch", "--case", downDir, "--once"}, watch(downDir, jb.WatchOptions{}), false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			code, _, stderr := run(t, testDeps(huntEnv), r.cli...)
			libErr := r.lib(t.Context())
			if got := jb.IsUsage(libErr); got != r.wantUsage {
				t.Errorf("jb.IsUsage = %v, want %v (err: %v)", got, r.wantUsage, libErr)
			}
			if got := code == exitUsage; got != r.wantUsage {
				t.Errorf("CLI exit %d, want usage=%v: %s", code, r.wantUsage, stderr)
			}
			if r.wantUsage {
				var ue *jb.UsageError
				if !errors.As(libErr, &ue) {
					t.Errorf("errors.As to *jb.UsageError failed for %v", libErr)
				}
			}
		})
	}
}
