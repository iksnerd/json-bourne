package plugin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The host's states are distinct: closed, no child, usable child, request in flight,
// breaker open. These tests walk the transitions between them.

func TestFailedCallClearsTheChildAndALaterCallRelaunchesIt(t *testing.T) {
	e := install(t, "crash") // answers the first request, dies on the second
	dir := filepath.Dir(e.Path)
	h := newHost(t, e, Limits{}, nil)
	if _, err := h.MapBatch(context.Background(), docs(1)); err != nil {
		t.Fatal(err)
	}
	first := pidOf(t, dir, "pid")
	mustFail(t, h, 1, "")
	waitDead(t, first)
	if h.Breaks() != 1 {
		t.Fatalf("breaks = %d, want 1", h.Breaks())
	}
	res, err := h.MapBatch(context.Background(), docs(1))
	if err != nil || len(res) != 1 {
		t.Fatalf("relaunch: res=%d err=%v", len(res), err)
	}
	if h.Breaks() != 0 {
		t.Errorf("breaks = %d after a success", h.Breaks())
	}
	if n := strings.Count(readFile(dir, "launches"), "\n"); n != 2 {
		t.Errorf("launched %d times, want 2", n)
	}
}

func TestBreakerNeverSelfClosesAndSaysSo(t *testing.T) {
	e := install(t, "badjson")
	h := newHost(t, e, Limits{MaxBreaks: 2}, nil)
	mustFail(t, h, 1, "not valid JSON")
	mustFail(t, h, 1, "not valid JSON")
	time.Sleep(50 * time.Millisecond) // time passing must not half-open it
	for i := 0; i < 3; i++ {
		_, err := h.MapBatch(context.Background(), docs(1))
		if !errors.Is(err, ErrBreakerOpen) || !errors.Is(err, ErrPlugin) {
			t.Fatalf("call %d = %v", i, err)
		}
		if !strings.Contains(err.Error(), "breaker open") || !strings.Contains(err.Error(), "for the rest of this run") {
			t.Errorf("the error must say the breaker is open until the run ends: %v", err)
		}
	}
	if n := strings.Count(readFile(filepath.Dir(e.Path), "launches"), "\n"); n != 2 {
		t.Errorf("launched %d times, want 2", n)
	}
	if h.Breaks() != 2 {
		t.Errorf("breaks = %d: fail-fast calls must not keep counting", h.Breaks())
	}
}

func TestCallerDeadlineIsNotABreakButThePluginDeadlineIs(t *testing.T) {
	e := install(t, "slow")
	dir := filepath.Dir(e.Path)
	h := newHost(t, e, Limits{Deadline: 30 * time.Second}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	_, err := h.MapBatch(ctx, docs(1))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller's deadline", err)
	}
	if h.Breaks() != 0 {
		t.Errorf("a caller deadline counted as a plugin break (%d)", h.Breaks())
	}
	waitDead(t, pidOf(t, dir, "pid"))

	h2 := newHost(t, install(t, "slow"), Limits{Deadline: 600 * time.Millisecond}, nil)
	mustFail(t, h2, 1, "no answer within")
	if h2.Breaks() != 1 {
		t.Errorf("the plugin's own deadline must count: breaks = %d", h2.Breaks())
	}
}

func TestCancelDuringHandshakeIsNotABreakAndKillsTheChild(t *testing.T) {
	e := install(t, "slowhandshake")
	h := newHost(t, e, Limits{Deadline: 30 * time.Second}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { pidOf(t, filepath.Dir(e.Path), "pid"); cancel() }()
	if _, err := h.MapBatch(ctx, docs(1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if h.Breaks() != 0 {
		t.Errorf("breaks = %d", h.Breaks())
	}
	waitDead(t, pidOf(t, filepath.Dir(e.Path), "pid"))
}

func TestCloseIsTerminalAfterAFailedLaunch(t *testing.T) {
	e := install(t, "ok")
	h := newHost(t, e, Limits{}, nil)
	if err := os.Remove(e.Path); err != nil {
		t.Fatal(err)
	}
	if _, err := h.MapBatch(context.Background(), docs(1)); !errors.Is(err, ErrPlugin) {
		t.Fatalf("launch of a missing binary = %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
	}
	_, err := h.MapBatch(context.Background(), docs(1))
	if err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("a closed host answered or gave the wrong reason: %v", err)
	}
}

func TestCloseNeverLaunchedHostIsFine(t *testing.T) {
	h := newHost(t, install(t, "ok"), Limits{}, nil)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(h.entry.Path), "launches")); err == nil {
		t.Error("a closed host that never ran launched a child")
	}
}

func TestCloseDuringAnInFlightRequestEndsItPromptly(t *testing.T) {
	e := install(t, "slow") // hangs after the handshake, ignoring the request
	dir := filepath.Dir(e.Path)
	h := newHost(t, e, Limits{Deadline: 50 * time.Second}, nil)
	callErr := make(chan error, 1)
	go func() { _, err := h.MapBatch(context.Background(), docs(1)); callErr <- err }()
	pidOf(t, dir, "pid")
	pidOf(t, dir, "child.pid") // the handshake is next; the request follows

	closed := make(chan struct{})
	go func() { h.Close(); h.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(20 * time.Second):
		t.Fatal("Close waited for the in-flight request instead of ending it")
	}
	select {
	case err := <-callErr:
		if err == nil {
			t.Fatal("the in-flight request succeeded after Close")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the in-flight request never returned")
	}
	waitDead(t, pidOf(t, dir, "pid"))
	waitDead(t, pidOf(t, dir, "child.pid"))
	if _, err := h.MapBatch(context.Background(), docs(1)); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("after Close: %v", err)
	}
	if n := strings.Count(readFile(dir, "launches"), "\n"); n != 1 {
		t.Errorf("launched %d times; a closed host must not relaunch", n)
	}
}

func TestConcurrentCallsAreSerialisedAndIDsDoNotRepeat(t *testing.T) {
	e := install(t, "logrequest")
	h := newHost(t, e, Limits{}, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := h.MapBatch(context.Background(), docs(3))
			if err != nil || len(res) != 3 {
				t.Errorf("res=%d err=%v", len(res), err)
			}
		}()
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(readFile(filepath.Dir(e.Path), "requests")), "\n") {
		id := l[strings.Index(l, `"id":`):strings.Index(l, `,"config"`)]
		if seen[id] {
			t.Errorf("request %s sent twice", id)
		}
		seen[id] = true
	}
	if len(seen) != 8 {
		t.Errorf("%d distinct ids, want 8", len(seen))
	}
}

func TestEveryDocumentGetsExactlyOneSlotAcrossChunks(t *testing.T) {
	h := newHost(t, install(t, "ok"), Limits{MaxDocs: 4}, nil)
	in := docs(11)
	in[5]["bad"] = true
	res, err := h.MapBatch(context.Background(), in)
	if err != nil || len(res) != 11 {
		t.Fatalf("res=%d err=%v", len(res), err)
	}
	for i, r := range res {
		if r.Unparsable != (i == 5) {
			t.Errorf("slot %d unparsable=%v", i, r.Unparsable)
		}
		if !r.Unparsable && r.Event.Fields["x"] != i {
			t.Errorf("slot %d holds the wrong document: %v", i, r.Event.Fields)
		}
	}
}

func TestAFailedLaterChunkReturnsNoPartialAnswer(t *testing.T) {
	h := newHost(t, install(t, "crash"), Limits{MaxDocs: 2}, nil)
	mustFail(t, h, 5, "") // chunk 1 answers, chunk 2 crashes the child
}
