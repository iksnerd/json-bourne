package app

import (
	"context"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/core"
)

func withSubj(e *casefile.Estate, s string) *casefile.Estate { e.Subject = s; return e }

func TestDiffRefusesDifferentSubjectsWithAUsageErrorNamingBoth(t *testing.T) {
	for _, tc := range []struct{ a, b string }{{"operated", "adversary"}, {"operated", ""}, {"", "adversary"}} {
		_, err := DiffEstates(state("a.yaml", withSubj(refreshBase(), tc.a)), state("b.yaml", withSubj(refreshBase(), tc.b)))
		if err == nil || !core.IsUsage(err) {
			t.Fatalf("%q vs %q: want a usage error, got %v", tc.a, tc.b, err)
		}
		for _, want := range []string{"a.yaml", "b.yaml"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%q vs %q: error must name %s: %v", tc.a, tc.b, want, err)
			}
		}
		for _, s := range []string{tc.a, tc.b} {
			want := s
			if s == "" {
				want = "unclassified"
			}
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%q vs %q: error must name subject %q: %v", tc.a, tc.b, want, err)
			}
		}
	}
}

func TestDiffAcceptsSameSubjectAndBothUnclassified(t *testing.T) {
	for _, s := range []string{"", "operated", "adversary"} {
		if _, err := DiffEstates(state("a.yaml", withSubj(refreshBase(), s)), state("b.yaml", withSubj(refreshBase(), s))); err != nil {
			t.Errorf("subject %q: %v", s, err)
		}
	}
}

func TestRefreshSnapshotCopiesTheBaselineSubject(t *testing.T) {
	for _, s := range []string{"", "operated", "adversary"} {
		f, b := &fakeFwd{ns: map[string][]string{"example.com": {"ns1.example.com"}}}, &fakeBGP{}
		snap, err := RefreshEstate(context.Background(), refreshDeps(f, b, "dns"), RefreshRequest{BasedOnSHA256: testDigest, Base: withSubj(refreshBase(), s), MaxTargets: 10})
		if err != nil {
			t.Fatal(err)
		}
		if snap.Estate.Subject != s {
			t.Errorf("baseline subject %q, snapshot subject %q", s, snap.Estate.Subject)
		}
	}
}
