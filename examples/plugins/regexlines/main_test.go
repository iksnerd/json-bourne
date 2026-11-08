package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/sdk"
)

func doc(line string) map[string]any {
	return map[string]any{"@timestamp": "2026-11-05T12:00:00Z", "message": line}
}

func TestPatternIsRE2AndBoundedWork(t *testing.T) {
	// (a+)+$ is the classic catastrophic backtracking pattern. RE2 matches it in linear time.
	m, err := newMapper([]byte(`{"pattern":"^(?P<x>(a+)+)$","fields":{"x":{"from":"x"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("a", 8000) + "b"
	start := time.Now()
	_, err = m.Map(doc(line), 0)
	if !errors.Is(err, sdk.ErrUnparsable) {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s: matching is not linear", d)
	}
}

func TestOversizeLineIsUnparsable(t *testing.T) {
	m, _ := newMapper([]byte(`{"max_line_bytes":32,"pattern":"(?P<x>.*)","fields":{"x":{"from":"x"}}}`))
	if _, err := m.Map(doc(strings.Repeat("a", 33)), 0); !errors.Is(err, sdk.ErrUnparsable) {
		t.Fatalf("err = %v", err)
	}
}

func TestOnlyMappedGroupsAreEmitted(t *testing.T) {
	m, err := newMapper([]byte(`{"pattern":"^(?P<who>\\S+) (?P<ip>\\S+)$","fields":{"ip":{"from":"ip","type":"ip"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := m.Map(doc("dana@example.com 192.0.2.1"), 0)
	if err != nil || len(ev.Fields) != 1 || ev.Fields["ip"] != "192.0.2.1" {
		t.Fatalf("ev=%v err=%v: an unmapped group (PII) must not be emitted", ev.Fields, err)
	}
}

func TestBadConfigsAreRefused(t *testing.T) {
	for name, cfg := range map[string]string{
		"no pattern":         `{"fields":{"a":{"from":"x"}}}`,
		"invalid regex":      `{"pattern":"(?P<x>(","fields":{"a":{"from":"x"}}}`,
		"backreference":      `{"pattern":"(?P<x>a)\\1","fields":{"a":{"from":"x"}}}`,
		"no named group":     `{"pattern":"(a)","fields":{"a":{"from":"x"}}}`,
		"from not in groups": `{"pattern":"(?P<x>a)","fields":{"a":{"from":"y"}}}`,
		"huge pattern":       `{"pattern":"(?P<x>` + strings.Repeat("a", 5000) + `)","fields":{"a":{"from":"x"}}}`,
		"unknown key":        `{"pattern":"(?P<x>a)","fields":{"a":{"from":"x"}},"cmd":"x"}`,
	} {
		if _, err := newMapper([]byte(cfg)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNoPanicOnGarbage(t *testing.T) {
	m, _ := newMapper([]byte(`{"pattern":"^(?P<a>\\S*) \"(?P<b>[^\"]*)\"$","fields":{"a":{"from":"a"},"b":{"from":"b"}}}`))
	for i := 0; i < 5000; i++ {
		b := make([]byte, i%300)
		for j := range b {
			b[j] = byte((i*31 + j*17) % 256)
		}
		if _, err := m.Map(doc(string(b)), 0); err != nil && !errors.Is(err, sdk.ErrUnparsable) {
			t.Fatal(err)
		}
	}
}
