package core

import (
	"errors"
	"testing"
)

func TestClassifyRunWholeShape(t *testing.T) {
	for _, c := range []struct {
		id      string
		kind    RunKind
		watcher string
	}{
		{"hunt-20261106T040000Z", KindHunt, ""},
		{"hunt-20261106T040000Z/ingress", KindHunt, ""},
		{"hunt-20261106T040000Z/kibana:logs-*", KindHunt, ""},
		{"hunt-until-20261106T040000Z-w86400s", KindHuntUntil, ""},
		{"hunt-until-20261106T040000Z-w86400s/ingress", KindHuntUntil, ""},
		{"activity-20261106T040000Z", KindActivity, ""},
		{"activity-until-20261106T040000Z-w3600s", KindActivityUntil, ""},
		{"search-20261106T040000Z", KindSearch, ""},
		{"search-until-20261106T040000Z-w60s/x", KindSearchUntil, ""},
		{"watch-20261106T040000Z", KindWatch, ""},
		{"watch-a-20261106T040000Z/ingress", KindWatch, "a"},
		{"watch-a-b-20261106T040000Z", KindWatch, "a-b"},
		// near misses are other, never a kind
		{"hunt-", KindOther, ""},
		{"hunt-ancient", KindOther, ""},
		{"hunt-20261106T040000Z-extra", KindOther, ""},
		{"hunt-20261106T040000", KindOther, ""},
		{"hunt-until-20261106T040000Z", KindOther, ""},
		{"hunt-until-20261106T040000Z-w5", KindOther, ""},
		{"xhunt-20261106T040000Z", KindOther, ""},
		{"watchdog-20261106T040000Z", KindOther, ""},
		{"watch-A-20261106T040000Z", KindOther, ""},
		{"", KindOther, ""},
	} {
		k, w := ClassifyRun(c.id)
		if k != c.kind || w != c.watcher {
			t.Errorf("ClassifyRun(%q) = %q,%q; want %q,%q", c.id, k, w, c.kind, c.watcher)
		}
	}
}

func TestParsePrunableKinds(t *testing.T) {
	got, err := ParsePrunableKinds("hunt, activity,hunt")
	if err != nil || len(got) != 2 || got[0] != KindHunt || got[1] != KindActivity {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"", " ", "watch", "watch-a", "watch-20261106T040000Z", "hunt,watch", "all", "*", "hunt-*", "hunt,", "other", "Hunt", "hunts"} {
		if _, err := ParsePrunableKinds(bad); err == nil {
			t.Errorf("ParsePrunableKinds(%q) accepted", bad)
		}
	}
	if _, err := ParsePrunableKinds("watch"); !errors.Is(err, ErrWatchKind) {
		t.Errorf("watch: %v", err)
	}
}
