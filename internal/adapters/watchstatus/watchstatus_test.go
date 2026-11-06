package watchstatus

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func sample() core.WatchStatus {
	return core.WatchStatus{
		Every: 5 * time.Minute, Window: time.Hour, TTL: 3 * time.Hour, Keep: 48 * time.Hour, Repeat: 30 * time.Minute,
		Updated: t0.Add(time.Minute),
		Last: &core.WatchCycleSummary{
			Run: "watch-a-20261105T115900Z", Verdict: "INCOMPLETE", Ended: t0.Add(time.Minute),
			Window: core.Window{From: t0.Add(-time.Hour), To: t0},
			New:    1, Suppressed: 2, Repeated: 3, Recovered: 4, Failed: []string{"source kibana:logs"},
		},
		NextDue: t0.Add(6 * time.Minute),
	}
}

func writer(dir string) Writer {
	return Writer{Path: filepath.Join(dir, "watch-status.a.json"), Name: "a", PID: 4242, Started: t0, Config: "config/hunt.yaml"}
}

func TestSaveThenReadRoundTrips(t *testing.T) {
	w := writer(t.TempDir())
	if err := w.Save(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	r, err := Read(w.Path)
	if err != nil {
		t.Fatal(err)
	}
	if r.APIVersion != APIVersion || r.Name != "a" || r.PID != 4242 || r.Config != "config/hunt.yaml" || !r.Started.Equal(t0) {
		t.Errorf("record = %+v", r)
	}
	if r.EverySeconds != 300 || r.WindowSeconds != 3600 || r.TTLSeconds != 10800 || r.KeepSeconds != 172800 || r.RepeatSeconds != 1800 {
		t.Errorf("options = %+v", r)
	}
	lc := r.LastCycle
	if lc == nil || lc.Verdict != "INCOMPLETE" || lc.Run != "watch-a-20261105T115900Z" || lc.New != 1 || lc.Suppressed != 2 ||
		lc.Repeated != 3 || lc.Recovered != 4 || len(lc.Failed) != 1 || !lc.Ended.Equal(t0.Add(time.Minute)) {
		t.Errorf("lastCycle = %+v", lc)
	}
	if !r.NextDue.Equal(t0.Add(6 * time.Minute)) {
		t.Errorf("nextDue = %v", r.NextDue)
	}
}

func TestRecordBeforeTheFirstCycleHasNoLastCycleAndFailedIsNeverNull(t *testing.T) {
	w := writer(t.TempDir())
	st := sample()
	st.Last = nil
	if err := w.Save(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(w.Path)
	if strings.Contains(string(b), "lastCycle") {
		t.Errorf("a record with no cycle names lastCycle:\n%s", b)
	}
	st = sample()
	st.Last.Failed = nil
	w.Save(context.Background(), st)
	b, _ = os.ReadFile(w.Path)
	if !strings.Contains(string(b), `"failed": []`) {
		t.Errorf("failed must be [] for a reader that indexes it:\n%s", b)
	}
}

func TestSaveLeavesNoTempFileAndFailsOnAMissingDirectory(t *testing.T) {
	dir := t.TempDir()
	w := writer(dir)
	if err := w.Save(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("directory holds %d entries, want only the record", len(ents))
	}
	w.Path = filepath.Join(dir, "gone", "watch-status.a.json")
	if err := w.Save(context.Background(), sample()); err == nil {
		t.Error("Save into a missing directory succeeded")
	}
}

func TestReadIsStrict(t *testing.T) {
	dir := t.TempDir()
	w := writer(dir)
	w.Save(context.Background(), sample())
	good, _ := os.ReadFile(w.Path)

	cases := map[string]struct{ body, want string }{
		"unknown field": {strings.Replace(string(good), `"pid"`, `"extra": 1, "pid"`, 1), "unknown field"},
		"old version":   {strings.Replace(string(good), APIVersion, "jb.watch-status/v0", 1), "jb.watch-status/v0"},
		"no version":    {strings.Replace(string(good), `"apiVersion": "`+APIVersion+`",`, "", 1), "apiVersion"},
		"trailing data": {string(good) + "{}", "after top-level value"},
		"no pid":        {strings.Replace(string(good), `"pid": 4242`, `"pid": 0`, 1), "pid"},
		"no interval":   {strings.Replace(string(good), `"everySeconds": 300`, `"everySeconds": 0`, 1), "everySeconds"},
		"no started":    {strings.Replace(string(good), `"started": "2026-11-05T12:00:00Z"`, `"started": "0001-01-01T00:00:00Z"`, 1), "started"},
		"not json":      {"hello", ""},
	}
	for name, c := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
		os.WriteFile(p, []byte(c.body), 0o600)
		_, err := Read(p)
		if err == nil {
			t.Errorf("%s: Read accepted it", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q lacks %q", name, err, c.want)
		}
	}
}

func TestOldVersionErrorSaysToRewrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	os.WriteFile(p, []byte(`{"apiVersion":"jb.watch-status/v0"}`), 0o600)
	_, err := Read(p)
	if err == nil || !strings.Contains(err.Error(), "rewrite") {
		t.Errorf("error = %v, want it to say the watcher rewrites the file", err)
	}
}

func TestMissingFileIsErrNotExist(t *testing.T) {
	_, err := Read(filepath.Join(t.TempDir(), "none.json"))
	if !os.IsNotExist(unwrap(err)) {
		t.Errorf("err = %v, want a not-exist error", err)
	}
}

func unwrap(err error) error {
	for {
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return err
		}
		err = u.Unwrap()
	}
}

// The record is written for other programs: its key names are the contract.
func TestRecordKeysAreTheDocumentedOnes(t *testing.T) {
	w := writer(t.TempDir())
	w.Save(context.Background(), sample())
	b, _ := os.ReadFile(w.Path)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"apiVersion", "name", "pid", "started", "updated", "config", "everySeconds", "windowSeconds", "ttlSeconds", "keepSeconds", "repeatSeconds", "lastCycle", "nextDue"} {
		if _, ok := m[k]; !ok {
			t.Errorf("record lacks key %q:\n%s", k, b)
		}
	}
	lc := m["lastCycle"].(map[string]any)
	for _, k := range []string{"run", "verdict", "ended", "windowFrom", "windowTo", "new", "suppressed", "repeated", "recovered", "failed"} {
		if _, ok := lc[k]; !ok {
			t.Errorf("lastCycle lacks key %q", k)
		}
	}
}
