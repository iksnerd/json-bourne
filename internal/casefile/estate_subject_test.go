package casefile

import (
	"slices"
	"strings"
	"testing"
)

// withSubject inserts a subject line after the id of validEstate.
func withSubject(line string) string {
	return strings.Replace(validEstate, "id: estate-a\n", "id: estate-a\n"+line+"\n", 1)
}

func TestEstateSubjectOperatedAdversaryAndNone(t *testing.T) {
	for _, tc := range []struct{ doc, want string }{
		{validEstate, ""},
		{withSubject("subject: operated"), "operated"},
		{withSubject("subject: adversary"), "adversary"},
	} {
		if got := mustEstate(t, tc.doc).Subject; got != tc.want {
			t.Errorf("subject = %q, want %q", got, tc.want)
		}
	}
}

func TestEstateSubjectRejectsAnyOtherValueNamingBoth(t *testing.T) {
	for _, v := range []string{"mine", "Operated", `"<script>alert(1)</script>"`, `""`, "third-party"} {
		_, err := ParseEstate([]byte(withSubject("subject: " + v)))
		if err == nil {
			t.Errorf("subject %s accepted", v)
			continue
		}
		if !strings.Contains(err.Error(), "operated") || !strings.Contains(err.Error(), "adversary") {
			t.Errorf("subject %s: error must name both valid values, got %v", v, err)
		}
	}
}

func TestEstateSubjectRoundTripAndOmittedWhenAbsent(t *testing.T) {
	e := mustEstate(t, withSubject("subject: adversary"))
	b, err := MarshalEstate(e)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "subject: adversary") || mustEstate(t, string(b)).Subject != "adversary" {
		t.Errorf("subject lost on round trip:\n%s", b)
	}
	b, _ = MarshalEstate(mustEstate(t, validEstate))
	if strings.Contains("\n"+string(b), "\nsubject:") {
		t.Errorf("an unclassified file must not gain a subject key:\n%s", b)
	}
}

func TestEstateSchemaSubjectEnumEqualsLoader(t *testing.T) {
	s := loadEstateSchema(t)
	p, ok := s.Properties["subject"]
	if !ok {
		t.Fatal("schema has no subject property")
	}
	if got := asStrings(t, p.Enum); !slices.Equal(sorted(got), sorted(EstateSubjects)) {
		t.Errorf("subject enum: schema %v, loader %v", got, EstateSubjects)
	}
	if slices.Contains(s.Required, "subject") {
		t.Error("subject must be optional")
	}
}

func TestSnapshotRoundTripKeepsSubject(t *testing.T) {
	s := validSnapshot(t)
	s.Estate.Subject = "operated"
	b, err := MarshalEstateSnapshot(s)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseEstateSnapshot(b)
	if err != nil || back.Estate.Subject != "operated" {
		t.Fatalf("%v %+v", err, back)
	}
	s.Estate.Subject = "bogus"
	if _, err := MarshalEstateSnapshot(s); err == nil {
		t.Error("a snapshot with a bad subject was written")
	}
}
