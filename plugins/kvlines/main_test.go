package main

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/sdk"
)

const baseCfg = `{"separators":",","fields":{"kind":{"from":"type"},"ip":{"from":"ipAddress","type":"ip"}}}`

func doc(line string) map[string]any {
	return map[string]any{"@timestamp": "2026-11-05T12:00:00Z", "message": line}
}

func mk(t *testing.T, cfg string) sdk.Mapper {
	t.Helper()
	m, err := newMapper([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestOnlyMappedKeysAreEmitted(t *testing.T) {
	m := mk(t, baseCfg)
	ev, err := m.Map(doc(`type=LOGIN_ERROR, username="dana@example.com", ipAddress=192.0.2.1, password=hunter2`), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Fields) != 2 || ev.Fields["kind"] != "LOGIN_ERROR" {
		t.Fatalf("fields = %v: PII or secrets must not be emitted unless mapped", ev.Fields)
	}
}

func TestOversizeLineIsUnparsableAndNeverParsed(t *testing.T) {
	m := mk(t, `{"max_line_bytes":64,"fields":{"kind":{"from":"type"}}}`)
	_, err := m.Map(doc("type=A "+strings.Repeat("word ", 100)), 0)
	if !errors.Is(err, sdk.ErrUnparsable) {
		t.Fatalf("err = %v", err)
	}
}

func TestHardLineCapCannotBeRaisedByConfig(t *testing.T) {
	if _, err := newMapper([]byte(`{"max_line_bytes":10000000,"fields":{"a":{"from":"b"}}}`)); err == nil {
		t.Fatal("a 10 MB line cap was accepted")
	}
}

func TestPairCountIsBounded(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxPairs+5; i++ {
		fmt.Fprintf(&b, "k%d=v ", i)
	}
	_, err := mk(t, baseCfg).Map(doc(b.String()), 0)
	if !errors.Is(err, sdk.ErrUnparsable) {
		t.Fatalf("err = %v", err)
	}
}

func TestDuplicateKeyMakesTheLineUnparsable(t *testing.T) {
	_, err := mk(t, baseCfg).Map(doc(`type=LOGIN username="x ipAddress=192.0.2.9" ipAddress=192.0.2.1 type=ADMIN`), 0)
	if !errors.Is(err, sdk.ErrUnparsable) {
		t.Fatalf("err = %v", err)
	}
}

func TestNoPanicOnGarbage(t *testing.T) {
	m := mk(t, baseCfg)
	r := rand.New(rand.NewSource(1))
	alphabet := []byte(`=",\ ab1.:@/-` + "\x00\xff\t")
	for i := 0; i < 20000; i++ {
		n := r.Intn(200)
		b := make([]byte, n)
		for j := range b {
			b[j] = alphabet[r.Intn(len(alphabet))]
		}
		_, err := m.Map(doc(string(b)), 0)
		if err != nil && !errors.Is(err, sdk.ErrUnparsable) {
			t.Fatalf("line %q: %v", b, err)
		}
	}
}

func TestBadConfigsAreRefused(t *testing.T) {
	for name, cfg := range map[string]string{
		"unknown key": `{"fields":{"a":{"from":"b"}},"exec":"/bin/sh"}`,
		"no fields":   `{}`,
		"seps long":   `{"separators":"123456789","fields":{"a":{"from":"b"}}}`,
	} {
		if _, err := newMapper([]byte(cfg)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
