package kibana

import "testing"

func TestProbeKeySeparatesFieldModeAndTimeField(t *testing.T) {
	base := func() *Source {
		return &Source{Client: New("http://x", testKey), Index: "i", KeyMatch: &KeyMatch{Field: "message", Mode: ModePhrase}}
	}
	a := base()
	b := base()
	b.Index = "other" // the index list is not part of the key
	if a.ProbeKey() != b.ProbeKey() {
		t.Error("sources that differ only by index must share a probe key")
	}
	c := base()
	c.TimeField = "@timestamp" // the default spelled out
	if a.ProbeKey() != c.ProbeKey() {
		t.Error("the default time field must equal an empty one")
	}
	for name, mut := range map[string]func(*Source){
		"field": func(s *Source) { s.KeyMatch.Field = "client_ip" },
		"mode":  func(s *Source) { s.KeyMatch.Mode = ModeTerm },
		"time":  func(s *Source) { s.TimeField = "event.created" },
	} {
		s := base()
		mut(s)
		if s.ProbeKey() == a.ProbeKey() {
			t.Errorf("a different %s must change the probe key", name)
		}
	}
}
