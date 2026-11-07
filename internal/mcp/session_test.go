package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/ops"
)

// gateRegistry has one read-only tool, "hold", that blocks until the test releases it or
// its context is cancelled. It records how each call ended.
type gateRegistry struct {
	mu      sync.Mutex
	started chan string // one value per call that began, its "tag" argument
	release chan struct{}
	ended   map[string]string // tag -> "released" or "cancelled"
}

func newGate() *gateRegistry {
	return &gateRegistry{started: make(chan string, 64), release: make(chan struct{}), ended: map[string]string{}}
}

func (g *gateRegistry) Tools([]string) []ops.ToolEntry {
	return []ops.ToolEntry{{Name: "hold", Description: "Blocks.", InputSchema: ops.Schema{Type: "object", Properties: map[string]ops.Property{}, Required: []string{}}, Annotations: ops.ToolAnnotations{ReadOnlyHint: true}}}
}

func (g *gateRegistry) Call(ctx context.Context, _ string, args map[string]any) (any, error) {
	tag, _ := args["tag"].(string)
	g.started <- tag
	select {
	case <-g.release:
		g.mu.Lock()
		g.ended[tag] = "released"
		g.mu.Unlock()
		return map[string]any{"tag": tag}, nil
	case <-ctx.Done():
		g.mu.Lock()
		g.ended[tag] = "cancelled"
		g.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (g *gateRegistry) waitStarted(t *testing.T, want string) {
	t.Helper()
	select {
	case got := <-g.started:
		if got != want {
			t.Fatalf("call started %q, want %q", got, want)
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("call %q never started", want)
	}
}

func (g *gateRegistry) endedAs(tag string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ended[tag]
}

func hold(id, tag string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"hold","arguments":{"tag":"` + tag + `"}}}`
}

func cancelMsg(id string) string {
	return `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":` + id + `}}`
}

// expectQuiet fails if the server writes anything within d. A later ping proves the
// server is alive and that nothing was written before its answer.
func (c *client) expectNext(id float64) {
	c.t.Helper()
	c.send(`{"jsonrpc":"2.0","id":` + string(mustJSON(id)) + `,"method":"ping"}`)
	if m := c.recv(); m["id"] != id {
		c.t.Fatalf("expected only the ping reply %v, got %v", id, m)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestPingBeforeInitializeThenToolsRefusedWithSameSessionUsable(t *testing.T) {
	c := start(t, &fakeRegistry{})
	c.send(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if m := c.recv(); m["id"] != float64(1) || m["error"] != nil {
		t.Fatalf("ping = %v", m)
	}
	c.send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo"}}`)
	m := c.recv()
	if errCode(m) != -32600 || m["id"] != float64(2) {
		t.Fatalf("tools/call before initialize = %v", m)
	}
	// notifications/initialized without an initialize request does not initialise.
	c.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	c.send(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	if errCode(c.recv()) != -32600 {
		t.Fatal("notifications/initialized alone must not open the session")
	}
	// A failed initialize does not open it either.
	c.send(`{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}`)
	if errCode(c.recv()) != -32602 {
		t.Fatal("bad initialize accepted")
	}
	c.send(`{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
	if errCode(c.recv()) != -32600 {
		t.Fatal("failed initialize opened the session")
	}
}

func TestInitializeTwiceKeepsSessionOpen(t *testing.T) {
	c := start(t, &fakeRegistry{})
	c.init()
	c.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
	if m := c.recv(); m["error"] != nil {
		t.Fatalf("second initialize = %v", m)
	}
	// A failed second initialize does not close the session.
	c.send(`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}`)
	if errCode(c.recv()) != -32602 {
		t.Fatal("bad second initialize accepted")
	}
	c.send(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	if m := c.recv(); m["error"] != nil {
		t.Fatalf("session closed by failed re-initialize: %v", m)
	}
}

func TestNullAndAbsentIDsNeverGetAToolResponse(t *testing.T) {
	reg := &fakeRegistry{}
	c := start(t, reg)
	c.init()
	// Absent id: a notification. No response, and the tool does not run.
	c.send(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo"}}`)
	// Null id: an invalid request, answered once with id null, tool not run.
	c.send(`{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"echo"}}`)
	m := c.recv()
	if errCode(m) != -32600 || m["id"] != nil {
		t.Fatalf("null id = %v", m)
	}
	c.expectNext(7)
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if len(reg.calls) != 0 {
		t.Fatalf("tool ran for a notification or null id: %v", reg.calls)
	}
}

func TestStringAndNumberIDsAreNotConflated(t *testing.T) {
	g := newGate()
	c := start(t, g)
	c.init()
	c.send(hold("1", "num"))
	g.waitStarted(t, "num")
	c.send(hold(`"1"`, "str"))
	g.waitStarted(t, "str")
	// Cancelling the number leaves the string call running.
	c.send(cancelMsg("1"))
	deadline := time.Now().Add(60 * time.Second)
	for g.endedAs("num") == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if g.endedAs("num") != "cancelled" || g.endedAs("str") != "" {
		t.Fatalf("num=%q str=%q", g.endedAs("num"), g.endedAs("str"))
	}
	close(g.release)
	m := c.recv()
	if m["id"] != "1" || m["result"] == nil {
		t.Fatalf("string-id call response = %v", m)
	}
	c.expectNext(2)
}

func TestDuplicateIDInFlightIsRefusedAndFirstStaysCancellable(t *testing.T) {
	g := newGate()
	c := start(t, g)
	c.init()
	c.send(hold("5", "first"))
	g.waitStarted(t, "first")
	c.send(hold("5", "second"))
	m := c.recv()
	if errCode(m) != -32600 || m["id"] != float64(5) {
		t.Fatalf("duplicate in-flight id = %v", m)
	}
	// The first call is still tracked: cancelling id 5 cancels it and writes no response.
	c.send(cancelMsg("5"))
	deadline := time.Now().Add(60 * time.Second)
	for g.endedAs("first") == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if g.endedAs("first") != "cancelled" {
		t.Fatalf("first call = %q", g.endedAs("first"))
	}
	c.expectNext(6)
}

func TestIDReusedAfterCompletion(t *testing.T) {
	c := start(t, &fakeRegistry{})
	c.init()
	for i := 0; i < 3; i++ {
		c.send(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}`)
		m := c.recv()
		if m["id"] != float64(8) || m["error"] != nil {
			t.Fatalf("round %d = %v", i, m)
		}
	}
}

func TestCancelledCallWritesNoResponseAndIsUntracked(t *testing.T) {
	g := newGate()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &client{t: t, in: inW, out: bufio.NewReader(outR), done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := make(chan *server, 1)
	go func() {
		c.done <- serve(ctx, inR, outW, io.Discard, Config{Registry: g}, func(s *server) { srv <- s })
		outW.Close()
	}()
	s := <-srv
	c.init()
	c.send(hold("1", "a"))
	g.waitStarted(t, "a")
	c.send(cancelMsg("1"))
	c.send(cancelMsg("1")) // twice is harmless
	deadline := time.Now().Add(60 * time.Second)
	for g.endedAs("a") == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	c.expectNext(2) // nothing was written for id 1
	for s.calls.len() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := s.calls.len(); n != 0 {
		t.Fatalf("%d entries left tracked", n)
	}
}

func TestCancelRacesAreHarmless(t *testing.T) {
	g := newGate()
	c := start(t, g)
	c.init()
	// Before the call starts, for an unknown id, malformed ids and params.
	c.send(cancelMsg("9"))
	c.send(cancelMsg("null"))
	c.send(cancelMsg(`{"a":1}`))
	c.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":"x"}`)
	c.send(`{"jsonrpc":"2.0","method":"notifications/cancelled"}`)
	// The cancel that came first must not cancel a later call with that id.
	c.send(hold("9", "late"))
	g.waitStarted(t, "late")
	close(g.release)
	if m := c.recv(); m["id"] != float64(9) || m["result"] == nil {
		t.Fatalf("late call = %v", m)
	}
	// After the response was written: ignored, and does not affect the next reuse.
	c.send(cancelMsg("9"))
	c.send(hold("9", "again"))
	g.waitStarted(t, "again")
	if m := c.recv(); m["id"] != float64(9) || m["result"] == nil {
		t.Fatalf("reused id after stale cancel = %v", m)
	}
}

func TestEOFWaitsForInFlightCalls(t *testing.T) {
	g := newGate()
	c := start(t, g)
	c.init()
	c.send(hold("1", "a"))
	g.waitStarted(t, "a")
	c.in.Close()
	select {
	case <-c.done:
		t.Fatal("Serve returned while a call was in flight")
	case <-time.After(100 * time.Millisecond):
	}
	close(g.release)
	if m := c.recv(); m["id"] != float64(1) || m["result"] == nil {
		t.Fatalf("response after EOF = %v", m)
	}
	select {
	case err := <-c.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Serve did not return after the call finished")
	}
}

func TestParentCancelCancelsInFlightCallsAndReturns(t *testing.T) {
	g := newGate()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	defer inW.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, inR, outW, io.Discard, Config{Registry: g}); outW.Close() }()
	go io.Copy(io.Discard, outR)
	io.WriteString(inW, `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"x"}}`+"\n")
	io.WriteString(inW, hold("1", "a")+"\n")
	g.waitStarted(t, "a")
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Serve hung after parent cancel")
	}
	if g.endedAs("a") != "cancelled" {
		t.Fatalf("call = %q", g.endedAs("a"))
	}
}

func TestFrameLimits(t *testing.T) {
	c := start(t, &fakeRegistry{})
	c.init()
	// A frame over the limit is one parse error, and the next frame is still served.
	c.send(`{"jsonrpc":"2.0","id":1,"method":"ping","params":"` + strings.Repeat("a", maxLine) + `"}`)
	if m := c.recv(); errCode(m) != -32700 {
		t.Fatalf("oversize = %v", m)
	}
	c.expectNext(2)
}

func TestFinalFrameWithoutNewline(t *testing.T) {
	// A complete final frame without a newline is served; a truncated one is a parse error.
	for _, tc := range []struct {
		name, tail string
		code       float64
	}{
		{"complete", `{"jsonrpc":"2.0","id":3,"method":"ping"}`, 0},
		{"truncated", `{"jsonrpc":"2.0","id":3,"meth`, -32700},
		{"oversize", `{"jsonrpc":"2.0","id":3,"method":"ping","params":"` + strings.Repeat("a", maxLine), -32700},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := start(t, &fakeRegistry{})
			io.WriteString(c.in, tc.tail)
			c.in.Close()
			m := c.recv()
			if errCode(m) != tc.code {
				t.Fatalf("got %v", m)
			}
			select {
			case <-c.done:
			case <-time.After(60 * time.Second):
				t.Fatal("no exit at EOF")
			}
		})
	}
}

func TestCleanEOFWritesNothing(t *testing.T) {
	var out strings.Builder
	err := Serve(context.Background(), strings.NewReader("\n  \n"), &out, io.Discard, Config{Registry: &fakeRegistry{}})
	if err != nil || out.Len() != 0 {
		t.Fatalf("err=%v out=%q", err, out.String())
	}
}

type safeBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }

func TestConcurrentResponsesNeverInterleave(t *testing.T) {
	var out safeBuf
	var in strings.Builder
	in.WriteString(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"x"}}` + "\n")
	const n = 200
	big := strings.Repeat("z", 200)
	for i := 1; i <= n; i++ {
		in.WriteString(`{"jsonrpc":"2.0","id":` + string(mustJSON(i)) + `,"method":"tools/call","params":{"name":"echo","arguments":{"text":"` + big + `"}}}` + "\n")
	}
	if err := Serve(context.Background(), strings.NewReader(in.String()), &out, io.Discard, Config{Registry: &fakeRegistry{}}); err != nil {
		t.Fatal(err)
	}
	seen := map[float64]bool{}
	lines := strings.Split(strings.TrimSuffix(out.b.String(), "\n"), "\n")
	if len(lines) != n+1 {
		t.Fatalf("%d lines", len(lines))
	}
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("interleaved or broken line %q", l)
		}
		seen[m["id"].(float64)] = true
	}
	if len(seen) != n+1 {
		t.Fatalf("%d distinct ids", len(seen))
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestServeReturnsWriteError(t *testing.T) {
	inR, inW := io.Pipe()
	defer inW.Close()
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), inR, failWriter{}, io.Discard, Config{Registry: &fakeRegistry{}})
	}()
	io.WriteString(inW, `{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n")
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Serve returned nil although it cannot write")
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Serve kept running with a dead output")
	}
}

func TestReadOnlyDefaultSurvivesAnySequence(t *testing.T) {
	reg := &fakeRegistry{}
	c := start(t, reg)
	c.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wipe"}}`)
	c.recv()
	c.init()
	c.init() // initialize twice
	for i, line := range []string{
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wipe"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"wipe","arguments":{"apply":true}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"Wipe"}}`,
	} {
		c.send(line)
		if errCode(c.recv()) != -32602 {
			t.Fatalf("case %d: mutating tool callable", i)
		}
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if len(reg.calls) != 0 {
		t.Fatalf("calls = %v", reg.calls)
	}
}
