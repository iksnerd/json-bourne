package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/sdk"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var d map[string]any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestOnlyMappedPathsAreEmitted(t *testing.T) {
	m, err := newMapper([]byte(`{"fields":{"a":{"from":"x.y"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := m.Map(decode(t, `{"@timestamp":"2026-11-05T12:00:00Z","x":{"y":"v","email":"dana@example.com"},"card":"4111"}`), 0)
	if err != nil || len(ev.Fields) != 1 {
		t.Fatalf("ev=%v err=%v", ev.Fields, err)
	}
}

func TestOversizeDocumentIsUnparsable(t *testing.T) {
	m, _ := newMapper([]byte(`{"max_doc_bytes":10,"fields":{"a":{"from":"x"}}}`))
	if _, err := m.Map(decode(t, `{"@timestamp":"2026-11-05T12:00:00Z","x":"v"}`), 5000); !errors.Is(err, sdk.ErrUnparsable) {
		t.Fatalf("err = %v", err)
	}
}

func TestDeepPathAndDeepDocumentAreBounded(t *testing.T) {
	if _, err := newMapper([]byte(`{"fields":{"a":{"from":"` + strings.Repeat("a.", 20) + `a"}}}`)); err == nil {
		t.Fatal("a 21-segment path was accepted")
	}
	m, _ := newMapper([]byte(`{"fields":{"a":{"from":"a"}}}`))
	deep := `{"@timestamp":"2026-11-05T12:00:00Z","a":` + strings.Repeat(`{"a":`, 5000) + `1` + strings.Repeat("}", 5000) + `}`
	if _, err := m.Map(decode(t, deep), len(deep)); err != nil && !errors.Is(err, sdk.ErrUnparsable) {
		t.Fatal(err)
	}
}

func TestBadConfigsAreRefused(t *testing.T) {
	for name, cfg := range map[string]string{
		"unknown key": `{"fields":{"a":{"from":"b"}},"script":"x"}`,
		"no fields":   `{}`,
		"big doc cap": `{"max_doc_bytes":999999999,"fields":{"a":{"from":"b"}}}`,
	} {
		if _, err := newMapper([]byte(cfg)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
