package plugin

import (
	"bufio"
	"bytes"
	"errors"
	"testing"
	"time"
)

const (
	fuzzCap    = 64 << 10
	fuzzBudget = 10 * time.Second
)

// FuzzDecodeResponse feeds the host's decoder the line a plugin wrote to stdout. The
// plugin is untrusted: whatever it prints, the host returns an error or exactly one
// result per document, never a panic, and a slot it accepts is a usable event.
func FuzzDecodeResponse(f *testing.F) {
	f.Add([]byte(`{"id":1,"events":[{"ts":"2026-11-05T12:00:00Z","fields":{"client_ip":"192.0.2.10","status":401}}]}`), int64(1), uint8(1))
	f.Add([]byte(`{"id":1,"events":[null,{"ts":"2026-11-05T12:00:00Z","fields":{"n":1e400,"big":123456789012345678901234567890,"nest":{"a":[1,2.5]}}}],"unparsable":[0]}`), int64(1), uint8(2))
	f.Add([]byte(`{"id":7,"error":"cannot map"}`), int64(7), uint8(1))
	f.Add([]byte(`{"id":1,"events":[null],"unparsable":[0,0]}`), int64(1), uint8(1))
	f.Add([]byte(`{"id":null}`), int64(1), uint8(0))
	f.Add([]byte(`[[[[[[[[[[`), int64(1), uint8(3))
	f.Fuzz(func(t *testing.T, line []byte, id int64, n uint8) {
		if len(line) > fuzzCap {
			t.Skip("over the fuzz size cap")
		}
		w := time.AfterFunc(fuzzBudget, func() { panic("decode did not return within the fuzz budget") })
		defer w.Stop()
		h := &Host{entry: Entry{Name: "fuzz"}}
		res, err := h.decode(nil, line, id, int(n))
		if err != nil {
			if !errors.Is(err, ErrPlugin) {
				t.Fatalf("a refusal is not an ErrPlugin: %v", err)
			}
			return
		}
		if len(res) != int(n) {
			t.Fatalf("%d results for %d documents", len(res), n)
		}
		for i, r := range res {
			if r.Unparsable {
				continue
			}
			if r.Event.Time.IsZero() || r.Event.Fields == nil {
				t.Fatalf("slot %d accepted without a time or fields: %+v", i, r.Event)
			}
		}
	})
}

// FuzzReadLine feeds the stdout reader arbitrary bytes. It returns a line within the
// limit or an error, and spends at most the limit in memory on any one line.
func FuzzReadLine(f *testing.F) {
	f.Add([]byte("{}\n"), uint16(16))
	f.Add([]byte("no newline"), uint16(4))
	f.Add(bytes.Repeat([]byte("x"), 200), uint16(10))
	f.Add([]byte("a\r\nb\n"), uint16(0))
	f.Fuzz(func(t *testing.T, data []byte, max uint16) {
		if len(data) > fuzzCap {
			t.Skip("over the fuzz size cap")
		}
		br := bufio.NewReaderSize(bytes.NewReader(data), 16) // small, so fragments are joined
		for i := 0; i <= len(data); i++ {
			line, err := readLine(br, int(max))
			if err != nil {
				return
			}
			if len(line) > int(max) {
				t.Fatalf("line of %d bytes over the limit %d", len(line), max)
			}
			if bytes.ContainsAny(line, "\n") {
				t.Fatalf("line holds a newline: %q", line)
			}
		}
		t.Fatal("readLine returned more lines than there are bytes")
	})
}
