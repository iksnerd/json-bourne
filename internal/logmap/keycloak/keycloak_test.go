package keycloak

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The corpus is the contract. Each NAME.in.json is a document, each NAME.want.json
// is one of {"time","fields"}, {"unparsable":true} or {"bad_time":true}. A mapper
// that runs as a separate process is correct when it passes the same files.
type want struct {
	Time       string         `json:"time"`
	Fields     map[string]any `json:"fields"`
	Unparsable bool           `json:"unparsable"`
	BadTime    bool           `json:"bad_time"`
}

func TestCorpus(t *testing.T) {
	ins, err := filepath.Glob("testdata/corpus/*.in.json")
	if err != nil || len(ins) < 30 {
		t.Fatalf("corpus not found or too small: %d files, err %v", len(ins), err)
	}
	for _, in := range ins {
		name := strings.TrimSuffix(filepath.Base(in), ".in.json")
		t.Run(name, func(t *testing.T) {
			doc, err := os.ReadFile(in)
			if err != nil {
				t.Fatal(err)
			}
			wb, err := os.ReadFile(strings.TrimSuffix(in, ".in.json") + ".want.json")
			if err != nil {
				t.Fatal(err)
			}
			var w want
			if err := json.Unmarshal(wb, &w); err != nil {
				t.Fatal(err)
			}
			ev, err := Map(doc)
			switch {
			case w.Unparsable:
				if !errors.Is(err, ErrUnparsable) {
					t.Fatalf("err = %v, want ErrUnparsable (event %v)", err, ev.Fields)
				}
				if ev.Fields != nil {
					t.Errorf("an unparsable document returned fields: %v", ev.Fields)
				}
			case w.BadTime:
				if !errors.Is(err, ErrBadTime) || errors.Is(err, ErrUnparsable) {
					t.Fatalf("err = %v, want ErrBadTime and not ErrUnparsable", err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				wt, perr := time.Parse(time.RFC3339Nano, w.Time)
				if perr != nil {
					t.Fatal(perr)
				}
				if !ev.Time.Equal(wt) {
					t.Errorf("time = %v, want %v", ev.Time, wt)
				}
				if !reflect.DeepEqual(ev.Fields, w.Fields) {
					t.Errorf("fields = %#v\nwant     %#v", ev.Fields, w.Fields)
				}
				if string(ev.Raw) != string(doc) {
					t.Errorf("Raw is not the input document")
				}
			}
		})
	}
}

// No HTTP status is ever invented: a Keycloak event has none.
func TestNoStatusIsInvented(t *testing.T) {
	ins, _ := filepath.Glob("testdata/corpus/*.in.json")
	for _, in := range ins {
		doc, _ := os.ReadFile(in)
		ev, err := Map(doc)
		if err != nil {
			continue
		}
		for _, k := range []string{"status", "method", "path", "http_status"} {
			if _, has := ev.Fields[k]; has {
				t.Errorf("%s: field %q emitted; a Keycloak event carries no such value", filepath.Base(in), k)
			}
		}
	}
}

// Hostile input must never panic or allocate without bound.
func TestHostileInputDoesNotPanicAndIsBounded(t *testing.T) {
	big := strings.Repeat(`type="X", `, 30000)
	docs := [][]byte{
		nil, {}, []byte("\x00\xff"), []byte(`{"@timestamp":"2026-11-05T12:00:00Z","message":"` + strings.Repeat(`"`, 10000) + `"}`),
		[]byte(`{"@timestamp":"2026-11-05T12:00:00Z","message":"` + strings.Repeat(`a="`, 5000) + `"}`),
		[]byte(`{"@timestamp":"2026-11-05T12:00:00Z","message":"` + strings.Repeat(`", a="`, 2500) + `"}`),
		[]byte(`{"@timestamp":"2026-11-05T12:00:00Z","message":"` + big[:20000] + `"}`),
	}
	for i, d := range docs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("doc %d panicked: %v", i, r)
				}
			}()
			_, _ = Map(d)
		}()
	}
	allocs := testing.AllocsPerRun(5, func() { _, _ = Map(docs[len(docs)-1]) })
	if allocs > 2000 {
		t.Errorf("%v allocations for one 20 KB hostile document", allocs)
	}
}

func TestMapIsDeterministicAndKeepsNoState(t *testing.T) {
	doc, _ := os.ReadFile("testdata/corpus/register_success.in.json")
	orig := string(doc)
	a, _ := Map(doc)
	b, _ := Map(doc)
	for i := range doc {
		doc[i] = 'x' // the event must not alias the caller's buffer
	}
	if !reflect.DeepEqual(a.Fields, b.Fields) || string(a.Raw) != orig {
		t.Errorf("Map is not a pure function of its input")
	}
}

// Credential-bearing keys of a TRACE-level line (cookies, request URIs with one-time
// codes) must never reach an event, whether as a field or inside one. The corpus
// plants SYNTH-* markers in them.
func TestCredentialBearingKeysAreNeverEmitted(t *testing.T) {
	ins, _ := filepath.Glob("testdata/corpus/*.in.json")
	planted := 0
	for _, in := range ins {
		doc, _ := os.ReadFile(in)
		hasMarker := strings.Contains(string(doc), "SYNTH-")
		ev, err := Map(doc)
		if err != nil {
			continue
		}
		if hasMarker {
			planted++
		}
		for k, v := range ev.Fields {
			s, _ := v.(string)
			if strings.Contains(strings.ToLower(k), "cookie") || strings.Contains(strings.ToLower(k), "uri") || strings.Contains(s, "SYNTH-") {
				t.Errorf("%s: field %q=%q carries a credential-bearing value", filepath.Base(in), k, s)
			}
		}
	}
	if planted < 2 {
		t.Errorf("only %d corpus documents plant a SYNTH- marker; the test would pass for the wrong reason", planted)
	}
}

// A dynamic-client-registration rejection is Keycloak's own single-line service message with no
// key="value" pairs. It used to be counted unparsable; it is now a typed error event so a detector
// can count it. The type is a constant: no part of the text reaches a field, and it has no address.
func TestClientRegistrationRejected(t *testing.T) {
	doc := []byte(`{"@timestamp":"2026-11-07T09:06:55.000Z","message":"KC-SERVICES0099: Operation 'before register client' rejected. Policy 'Trusted Hosts' rejected request to client-registration service. Details: Host not trusted."}`)
	ev, err := Map(doc)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if got := ev.Fields["event_type"]; got != "CLIENT_REGISTRATION_REJECTED" {
		t.Errorf("event_type = %v, want CLIENT_REGISTRATION_REJECTED", got)
	}
	if got := ev.Fields["outcome"]; got != "error" {
		t.Errorf("outcome = %v, want error", got)
	}
	if _, ok := ev.Fields["client_ip"]; ok {
		t.Errorf("client_ip invented on a line that carries no address: %v", ev.Fields)
	}
	if !ev.Time.Equal(time.Date(2026, 11, 7, 9, 6, 55, 0, time.UTC)) {
		t.Errorf("time = %v", ev.Time)
	}
}

func TestClientRegistrationRejectNeedsTheServiceName(t *testing.T) {
	doc := []byte(`{"@timestamp":"2026-11-07T09:06:55Z","message":"KC-SERVICES0099: something else"}`)
	if _, err := Map(doc); !errors.Is(err, ErrUnparsable) {
		t.Fatalf("err = %v, want ErrUnparsable", err)
	}
}
