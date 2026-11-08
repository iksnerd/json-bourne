package contract

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/jb"
)

// An INCOMPLETE is never a clean result: whatever went wrong, Complete() is false and
// Failed() says what.
func TestAHuntThatDidNotFinishIsNeverComplete(t *testing.T) {
	for name, set := range map[string]func(*fakeKibana){
		"source down (502)":            func(k *fakeKibana) { k.status = http.StatusBadGateway },
		"source fails after the first": func(k *fakeKibana) { k.failFrom = 2 },
		"search timed out (timed_out)": func(k *fakeKibana) { k.timedOut = true },
	} {
		t.Run(name, func(t *testing.T) {
			k := newKibana(t, searchDocs())
			set(k)
			dir := exampleCase(t, k)
			// Two documents a page, so the window needs a second request (the one that fails).
			editFile(t, filepath.Join(dir, fpConfig), "index: logs-http-*", "index: logs-http-*\n    page_size: 2")
			res, err := jb.HuntCase(t.Context(), dir, huntOpts())
			if res == nil {
				t.Fatalf("no result beside the error %v", err)
			}
			if res.Complete() {
				t.Fatalf("Complete() is true for %s: %+v", name, res.Sources)
			}
			if len(res.Failed()) == 0 {
				t.Error("Failed() is empty although Complete() is false")
			}
			if res.Sources[0].Status == jb.StatusOK {
				t.Errorf("the source reports ok: %+v", res.Sources[0])
			}
		})
	}
}

func TestActivityIsIncompleteNotQuietWhenTheSourceFails(t *testing.T) {
	k := newKibana(t, searchDocs())
	k.status = http.StatusBadGateway
	dir := exampleCase(t, k)
	res, err := jb.Activity(t.Context(), dir, jb.ActivityOptions{Config: fpConfig, Window: time.Hour, Env: env, Now: fixedNow})
	if res == nil {
		t.Fatalf("no result, err = %v", err)
	}
	if res.Verdict != jb.VerdictIncomplete || res.Complete() || len(res.Reasons) == 0 {
		t.Errorf("verdict %s, complete %v, reasons %v: a failed source is INCOMPLETE and says why", res.Verdict, res.Complete(), res.Reasons)
	}
}

func TestWatchCycleIsNotQuietWhenTheSourceFails(t *testing.T) {
	k := newKibana(t, searchDocs())
	k.timedOut = true
	dir := exampleCase(t, k)
	rep, err := jb.Watch(t.Context(), dir, jb.WatchOptions{Once: true, Name: "t1", Config: fpConfig, Env: env, Now: fixedNow})
	if rep == nil {
		t.Fatalf("no report, err = %v", err)
	}
	if rep.Status.Healthy() || rep.Status == jb.CycleQuiet {
		t.Errorf("status %s: a partial response must not read as quiet", rep.Status)
	}
}

// RFC 0012: a detector that cannot finish keeps the findings it proved, beside its error.
func TestFindingsStayBesideTheErrorOfADetectorThatDidNotFinish(t *testing.T) {
	dir, _ := partialCase(t)
	o := huntOpts()
	o.Config = "config/behaviour.yaml"
	res, err := jb.HuntCase(t.Context(), dir, o)
	if res == nil {
		t.Fatalf("no result, err = %v", err)
	}
	if res.Complete() {
		t.Fatal("a detector that could not judge one action left the hunt complete")
	}
	if len(res.Findings) == 0 {
		t.Fatal("the finding the detector proved was thrown away")
	}
	d := res.Detectors[0]
	if d.Status == jb.StatusOK || d.Err == nil || d.Findings == 0 {
		t.Errorf("detector row = %+v, want a non-ok status, its error and a finding count", d)
	}

	act, err := jb.Activity(t.Context(), dir, jb.ActivityOptions{Config: "config/behaviour.yaml", Window: time.Hour, Env: env, Now: fixedNow})
	if act == nil {
		t.Fatalf("no activity result, err = %v", err)
	}
	if act.Verdict != jb.VerdictActive || act.Complete() {
		t.Errorf("verdict %s, complete %v: ACTIVE stands, and the answer says it is also incomplete", act.Verdict, act.Complete())
	}
}

// Complete() on the result types that can be built by hand: the documented rule for each.
func TestCompleteMethodsFollowTheirDocumentedRules(t *testing.T) {
	if !(&jb.ReputationResult{}).Complete() || (&jb.ReputationResult{Truncated: true}).Complete() {
		t.Error("ReputationResult: complete unless cut at the cap")
	}
	if !(jb.IntelResult{}).Complete() || (jb.IntelResult{Failures: []jb.IntelFailure{{}}}).Complete() {
		t.Error("IntelResult: complete only without failures")
	}
	if !(jb.EstateIPResult{}).Complete() || (jb.EstateIPResult{Failures: []jb.EstateIPFailure{{}}}).Complete() {
		t.Error("EstateIPResult: complete only without failures")
	}
	if !(jb.EstateExternalResult{}).Complete() || (jb.EstateExternalResult{Failures: []jb.EstateExternalFailure{{}}}).Complete() {
		t.Error("EstateExternalResult: complete only without failures")
	}
	if (jb.EstateRefreshResult{Failures: []jb.EstateSnapshotFailure{{}}}).Complete() {
		t.Error("EstateRefreshResult: a failed lookup makes the snapshot incomplete")
	}
	if (&jb.ActorStatusResult{Actors: []jb.ActorMatch{{Capped: true}}}).Complete() {
		t.Error("ActorStatusResult: a capped scan is not complete")
	}
	if (jb.DoctorResult{Checks: []jb.DoctorCheck{{Status: jb.CheckSkipped}}}).Complete() {
		t.Error("DoctorResult: a skipped check is not a pass")
	}
	if (jb.DoctorResult{Checks: []jb.DoctorCheck{{Status: jb.CheckFail}}}).OK() {
		t.Error("DoctorResult: a failed check is not OK")
	}
	for _, s := range []jb.CycleStatus{jb.CycleIncomplete, jb.CycleFailed} {
		if s.Healthy() {
			t.Errorf("cycle status %s is healthy", s)
		}
	}
	for _, s := range []jb.CycleStatus{jb.CycleQuiet, jb.CycleFindings} {
		if !s.Healthy() {
			t.Errorf("cycle status %s is not healthy", s)
		}
	}
}

func TestCaseCheckOutsideGitIsOKButNotComplete(t *testing.T) {
	res, err := jb.CaseCheck(exampleCase(t, nil)) // a temp dir is not a git work tree
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Complete() {
		t.Errorf("OK %v, Complete %v: a case outside git passes but nothing guards its evidence", res.OK, res.Complete())
	}
}

func TestDoctorWithNothingToCheckIsNotComplete(t *testing.T) {
	res, err := jb.Doctor(t.Context(), jb.DoctorOptions{Env: env})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() || res.Skipped() == 0 {
		t.Errorf("Complete %v, Skipped %d: nothing was configured, so checks were skipped", res.Complete(), res.Skipped())
	}
}
