package sdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type fixedMapper struct {
	f func(map[string]any) (Event, error)
}

func (m fixedMapper) Map(d map[string]any, _ int) (Event, error) { return m.f(d) }

func run(t *testing.T, in string, f func(map[string]any) (Event, error)) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	err := Serve(strings.NewReader(in), &out, Plugin{Name: "t", Version: "1", New: func(json.RawMessage) (Mapper, error) { return fixedMapper{f}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("output line is not JSON: %q", l)
		}
		lines = append(lines, m)
	}
	return lines
}

func ok(map[string]any) (Event, error) {
	return Event{Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Fields: map[string]any{"a": 1}}, nil
}

func TestServeManifestThenOneResponsePerRequest(t *testing.T) {
	out := run(t, `{"v":1,"id":7,"config":{},"docs":[{"x":1},{"x":2}]}`+"\n"+`{"v":1,"id":8,"config":{},"docs":[]}`+"\n", ok)
	if len(out) != 3 || out[0]["role"] != "mapper" || out[1]["id"].(float64) != 7 || out[2]["id"].(float64) != 8 {
		t.Fatalf("output = %v", out)
	}
	if ev := out[1]["events"].([]any); len(ev) != 2 {
		t.Errorf("events = %v", ev)
	}
}

func TestUnparsableAndNotJSONDocsAreReportedPerDocument(t *testing.T) {
	f := func(d map[string]any) (Event, error) {
		if d["bad"] == true {
			return Event{}, errors.Join(ErrUnparsable, errors.New("x"))
		}
		return ok(d)
	}
	out := run(t, `{"v":1,"id":1,"config":{},"docs":[{"bad":true},{"x":1},[1,2],null]}`+"\n", f)
	r := out[1]
	if ev := r["events"].([]any); len(ev) != 4 || ev[0] != nil || ev[1] == nil || ev[2] != nil || ev[3] != nil {
		t.Fatalf("events = %v", ev)
	}
	if u := r["unparsable"].([]any); len(u) != 3 {
		t.Fatalf("unparsable = %v", u)
	}
}

func TestAPanicInAMapperIsALoudErrorWithoutTheDocument(t *testing.T) {
	out := run(t, `{"v":1,"id":1,"config":{},"docs":[{"secret":"s3cr3t-value"}]}`+"\n", func(map[string]any) (Event, error) { panic("boom s3cr3t-value") })
	msg, _ := out[1]["error"].(string)
	if msg == "" || strings.Contains(msg, "s3cr3t") {
		t.Fatalf("error = %q", msg)
	}
}

func TestAnOrdinaryErrorFailsTheRequestNotTheProcess(t *testing.T) {
	out := run(t, `{"v":1,"id":1,"config":{},"docs":[{}]}`+"\n"+`{"v":1,"id":2,"config":{},"docs":[{}]}`+"\n", func(map[string]any) (Event, error) { return Event{}, errors.New("fault") })
	if out[1]["error"] != "fault" || out[2]["error"] != "fault" {
		t.Fatalf("out = %v", out)
	}
}

func TestWrongProtocolVersionAnswersWithAnError(t *testing.T) {
	out := run(t, `{"v":9,"id":3,"config":{},"docs":[]}`+"\n", ok)
	if s, _ := out[1]["error"].(string); !strings.Contains(s, "version 9") {
		t.Fatalf("out = %v", out)
	}
}

func TestAnOverlongRequestLineEndsTheProcessWithAnError(t *testing.T) {
	var out bytes.Buffer
	err := Serve(strings.NewReader(strings.Repeat("a", MaxRequestLine+10)), &out, Plugin{Name: "t", New: func(json.RawMessage) (Mapper, error) { return fixedMapper{ok}, nil }})
	if err == nil {
		t.Fatal("an unbounded line was accepted")
	}
}

func TestLookupFindsNestedFlattenedAndIndexedValues(t *testing.T) {
	var doc map[string]any
	_ = json.Unmarshal([]byte(`{"a":{"b":[10,{"c":"x"}]},"log.level":"warn","k":{"l.m":1}}`), &doc)
	for path, want := range map[string]any{"a.b.1.c": "x", "log.level": "warn", "k.l.m": float64(1)} {
		if got, ok := Lookup(doc, path); !ok || got != want {
			t.Errorf("Lookup(%q) = %v, %v", path, got, ok)
		}
	}
	for _, path := range []string{"a.b.5", "a.x", "a.b.-1", strings.Repeat("a.", 30) + "a"} {
		if _, ok := Lookup(doc, path); ok {
			t.Errorf("Lookup(%q) found something", path)
		}
	}
}

func TestCoerceRefusesWhatItCannotRepresent(t *testing.T) {
	bad := []struct {
		v        any
		typ, lay string
	}{
		{"x", "int", ""}, {"2", "bool", ""}, {"1.2.3.4.5", "ip", ""}, {"not a time", "time", ""},
		{map[string]any{"a": 1}, "string", ""}, {[]any{1}, "string", ""}, {json.Number("1.5"), "int", ""},
		{"abc", "time", "unix"},
	}
	for _, c := range bad {
		if v, err := Coerce(c.v, c.typ, c.lay); err == nil {
			t.Errorf("Coerce(%v, %s) = %v, want an error", c.v, c.typ, v)
		}
	}
	good := []struct {
		v        any
		typ, lay string
		want     any
	}{
		{"42", "int", "", int64(42)}, {"true", "bool", "", true}, {"2001:db8:0:0:0:0:0:1", "ip", "", "2001:db8::1"},
		{"1700000000", "time", "unix", "2023-11-14T22:13:20Z"}, {json.Number("7"), "string", "", "7"},
	}
	for _, c := range good {
		if v, err := Coerce(c.v, c.typ, c.lay); err != nil || v != c.want {
			t.Errorf("Coerce(%v, %s) = %v, %v; want %v", c.v, c.typ, v, err, c.want)
		}
	}
}

func TestValidateRejectsAnUnmappedConfigAndBadNames(t *testing.T) {
	for name, c := range map[string]Common{
		"no fields":         {},
		"bad name":          {Fields: map[string]FieldSpec{"Bad-Name": {From: "x"}}},
		"no from":           {Fields: map[string]FieldSpec{"a": {}}},
		"unknown type":      {Fields: map[string]FieldSpec{"a": {From: "x", Type: "float"}}},
		"layout on string":  {Fields: map[string]FieldSpec{"a": {From: "x", Layout: "2006"}}},
		"both time sources": {Fields: map[string]FieldSpec{"a": {From: "x"}}, Time: &TimeSpec{DocField: "a", From: "b"}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	tooMany := Common{Fields: map[string]FieldSpec{}}
	for i := 0; i <= MaxFields; i++ {
		tooMany.Fields["f"+strings.Repeat("a", i%5)+string(rune('a'+i%26))+string(rune('a'+i/26))] = FieldSpec{From: "x"}
	}
	if err := tooMany.Validate(); err == nil {
		t.Errorf("%d fields accepted", len(tooMany.Fields))
	}
}

func TestDecodeStrictRefusesUnknownKeysAndOversizeConfig(t *testing.T) {
	var c Common
	if err := DecodeStrict(json.RawMessage(`{"fields":{},"nope":1}`), &c); err == nil {
		t.Error("unknown key accepted")
	}
	if err := DecodeStrict(json.RawMessage(`{"fields":"`+strings.Repeat("a", MaxConfigBytes)+`"}`), &c); err == nil {
		t.Error("oversize config accepted")
	}
}
