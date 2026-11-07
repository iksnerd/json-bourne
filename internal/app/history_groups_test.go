package app

import (
	"context"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

const hcluster = "https://kibana.example.com"

// perms returns every ordering of the sources built by mk (fresh fakes each time).
func perms(mk func() []*countSrc) [][]*countSrc {
	n := len(mk())
	var out [][]*countSrc
	var rec func(used []bool, idx []int)
	rec = func(used []bool, idx []int) {
		if len(idx) == n {
			base := mk()
			var o []*countSrc
			for _, i := range idx {
				o = append(o, base[i])
			}
			out = append(out, o)
			return
		}
		for i := 0; i < n; i++ {
			if !used[i] {
				used[i] = true
				rec(used, append(idx, i))
				used[i] = false
			}
		}
	}
	rec(make([]bool, n), nil)
	return out
}

func asSources(cs []*countSrc) []core.Source {
	var s []core.Source
	for _, c := range cs {
		s = append(s, c)
	}
	return s
}

// Two sources on one cluster that match the key in different fields are two requests, each
// with its own settings; their counts add. The first source's settings must not speak for both.
func TestHistoryDifferentKeyFieldsOnOneClusterAreSeparateRequestsAndSum(t *testing.T) {
	mk := func() []*countSrc {
		a := newCountSrc("a", hcluster, "logs-1", map[string]int64{"192.0.2.7": 10})
		b := newCountSrc("b", hcluster, "logs-2", map[string]int64{"192.0.2.7": 20})
		b.field, b.mode = "client_ip", "term"
		return []*countSrc{a, b}
	}
	for i, o := range perms(mk) {
		got, err := newKeyHistory(asSources(o)).Counts(context.Background(), []string{"192.0.2.7"}, lookWin)
		if err != nil {
			t.Fatal(err)
		}
		if got["192.0.2.7"] != 30 {
			t.Errorf("order %d: count = %d, want 30", i, got["192.0.2.7"])
		}
		if o[0].keyCalls+o[1].keyCalls != 2 {
			t.Errorf("order %d: %d key requests, want one per group", i, o[0].keyCalls+o[1].keyCalls)
		}
	}
}

// Three sources, two share settings and overlap, one differs: every order gives 30
// (the shared pair once, plus the other field), and the pair is one request.
func TestHistoryResultDoesNotDependOnSourceOrder(t *testing.T) {
	mk := func() []*countSrc {
		a := newCountSrc("a", hcluster, "logs-*", map[string]int64{"192.0.2.7": 10})
		b := newCountSrc("b", hcluster, "logs-web-*", map[string]int64{"192.0.2.7": 10})
		c := newCountSrc("c", hcluster, "other-*", map[string]int64{"192.0.2.7": 20})
		c.field = "client_ip"
		return []*countSrc{a, b, c}
	}
	for i, o := range perms(mk) {
		got, err := newKeyHistory(asSources(o)).Counts(context.Background(), []string{"192.0.2.7"}, lookWin)
		if err != nil {
			t.Fatal(err)
		}
		if got["192.0.2.7"] != 30 {
			t.Errorf("order %d: count = %d, want 30", i, got["192.0.2.7"])
		}
		var unions []string
		keyCalls := 0
		for _, s := range o {
			unions = append(unions, s.unions...)
			keyCalls += s.keyCalls
		}
		if len(unions) != 1 || unions[0] != "logs-*,logs-web-*" || keyCalls != 2 {
			t.Errorf("order %d: unions %v, key requests %d; want one union over both shared patterns in fixed order, 2 requests", i, unions, keyCalls)
		}
	}
}

func TestHistoryDifferentTimeFieldsAreSeparateGroups(t *testing.T) {
	mk := func() []*countSrc {
		a := newCountSrc("a", hcluster, "logs-1", map[string]int64{"192.0.2.7": 10})
		b := newCountSrc("b", hcluster, "logs-1", map[string]int64{"192.0.2.7": 20})
		b.timeField = "event.created"
		return []*countSrc{a, b}
	}
	for i, o := range perms(mk) {
		got, err := newKeyHistory(asSources(o)).Counts(context.Background(), []string{"192.0.2.7"}, lookWin)
		if err != nil {
			t.Fatal(err)
		}
		if got["192.0.2.7"] != 30 || o[0].keyCalls != 1 || o[1].keyCalls != 1 {
			t.Errorf("order %d: count %d, requests %d/%d: a different time field is its own request", i, got["192.0.2.7"], o[0].keyCalls, o[1].keyCalls)
		}
	}
}

// A group with no events makes the run fail whichever other group shows history; the
// error names the group by source and index, never a key.
func TestHistoryAZeroGroupOnASharedClusterIsIncompleteAndNamesNoKey(t *testing.T) {
	mk := func() []*countSrc {
		a := newCountSrc("a", hcluster, "logs-1", map[string]int64{"192.0.2.7": 30})
		b := newCountSrc("b", hcluster, "logs-2", nil)
		b.field = "client_ip"
		b.all = 0
		return []*countSrc{a, b}
	}
	for i, o := range perms(mk) {
		_, err := newKeyHistory(asSources(o)).Counts(context.Background(), []string{"192.0.2.7"}, lookWin)
		if err == nil || !strings.Contains(err.Error(), "logs-2") || !strings.Contains(err.Error(), "cannot show history") || strings.Contains(err.Error(), "192.0.2.7") {
			t.Fatalf("order %d: err = %v", i, err)
		}
		if o[0].keyCalls+o[1].keyCalls != 0 {
			t.Errorf("order %d: keys were counted before every group proved it could see", i)
		}
	}
}
