package contract

import (
	"context"
	"errors"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/jb"
)

// promptly is how long a cancelled call may take to return. The fake server holds the
// request open until the client gives up, so a call that ignored its context would hang
// for the whole test.
const promptly = 5 * time.Second

// settle waits (with a deadline, never a bare sleep) for the goroutine count to fall back
// to before, and reports the count it ended with.
func settle(before int) int {
	deadline := time.Now().Add(5 * time.Second)
	n := runtime.NumGoroutine()
	for n > before && time.Now().Before(deadline) {
		http.DefaultTransport.(*http.Transport).CloseIdleConnections()
		time.Sleep(20 * time.Millisecond)
		n = runtime.NumGoroutine()
	}
	return n
}

// blockedCase is a case whose Kibana never answers until the request is cancelled.
func blockedCase(t *testing.T) (string, *fakeKibana) {
	t.Helper()
	k := newKibana(t, searchDocs())
	k.block = make(chan struct{})
	return exampleCase(t, k), k
}

func cancelSoon(cancel context.CancelFunc, k *fakeKibana) {
	// Cancel once the request has reached the server, so the call is cancelled mid-flight.
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for k.requests() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
}

func TestCancelledHuntStopsPromptlyAndLeavesAUsableStore(t *testing.T) {
	// A first, healthy hunt creates the store and warms the HTTP machinery.
	healthy := newKibana(t, searchDocs())
	dir := exampleCase(t, healthy)
	if _, err := jb.HuntCase(t.Context(), dir, huntOpts()); err != nil {
		t.Fatal(err)
	}
	before := runtime.NumGoroutine()

	// Now the same case points at a Kibana that never answers.
	k := newKibana(t, searchDocs())
	k.block = make(chan struct{})
	editFile(t, dir+"/"+fpConfig, healthy.srv.URL, k.srv.URL)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cancelSoon(cancel, k)
	start := time.Now()
	res, err := jb.HuntCase(ctx, dir, huntOpts())
	if took := time.Since(start); took > promptly {
		t.Fatalf("a cancelled hunt took %s", took)
	}
	if res == nil {
		t.Fatalf("no result beside the error %v", err)
	}
	if res.Complete() {
		t.Error("a cancelled hunt is not complete")
	}
	if !errors.Is(err, context.Canceled) && res.Sources[0].Status != jb.StatusCanceled {
		t.Errorf("neither the error (%v) nor the source (%s) says canceled", err, res.Sources[0].Status)
	}

	k.close()
	healthy.close()
	if n := settle(before); n > before {
		buf := make([]byte, 1<<16)
		t.Errorf("goroutines: %d before, %d after a cancelled hunt\n%s", before, n, buf[:runtime.Stack(buf, true)])
	}

	// The store was not corrupted: it opens, and a hunt against a healthy server stores.
	st, err := jb.DBStatus(t.Context(), dir, jb.DBOptions{})
	if err != nil || st.Runs == 0 {
		t.Fatalf("reopening the store: %v %+v", err, st)
	}
	again := newKibana(t, searchDocs())
	editFile(t, dir+"/"+fpConfig, k.srv.URL, again.srv.URL)
	if r, err := jb.HuntCase(t.Context(), dir, huntOpts()); err != nil || !r.Complete() {
		t.Fatalf("a hunt after the cancelled one: %v", err)
	}
}

func TestCancelledActivityStopsPromptly(t *testing.T) {
	dir, k := blockedCase(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cancelSoon(cancel, k)
	start := time.Now()
	res, err := jb.Activity(ctx, dir, jb.ActivityOptions{Config: fpConfig, Window: time.Hour, Env: env, Now: fixedNow})
	if took := time.Since(start); took > promptly {
		t.Fatalf("a cancelled activity took %s", took)
	}
	if res != nil && (res.Verdict == jb.VerdictQuiet || res.Complete()) {
		t.Errorf("a cancelled question is never QUIET or complete: %s", res.Verdict)
	}
	if res == nil && err == nil {
		t.Error("neither a result nor an error")
	}
}

func TestCancelledWatchReturnsAndReleasesItsLock(t *testing.T) {
	k := newKibana(t, searchDocs())
	dir := exampleCase(t, k)
	before := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(t.Context())
	type out struct {
		rep *jb.CycleReport
		err error
	}
	done := make(chan out, 1)
	go func() {
		rep, err := jb.Watch(ctx, dir, jb.WatchOptions{Name: "w1", Config: fpConfig, Env: env, Window: time.Hour})
		done <- out{rep, err}
	}()

	// Wait, with a deadline, until the watcher holds its lock.
	deadline := time.Now().Add(10 * time.Second)
	for {
		ws, err := jb.WatchStatus(dir, jb.WatchStatusOptions{Names: []string{"w1"}})
		if err == nil && len(ws.Watchers) == 1 && ws.Watchers[0].State == jb.WatcherRunning {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("the watcher never reported running: %+v %v", ws, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A second watcher of the same name is refused while the first runs.
	_, err := jb.Watch(t.Context(), dir, jb.WatchOptions{Name: "w1", Config: fpConfig, Env: env, Once: true})
	if !errors.Is(err, jb.ErrWatcherRunning) {
		t.Errorf("want ErrWatcherRunning, got %v", err)
	}

	cancel()
	select {
	case o := <-done:
		if o.err != nil && !errors.Is(o.err, context.Canceled) {
			t.Errorf("a cancelled watch returned %v", o.err)
		}
	case <-time.After(promptly):
		t.Fatal("a cancelled watch did not return")
	}

	// The lock is released: the same name runs again, and the store opens.
	if rep, err := jb.Watch(t.Context(), dir, jb.WatchOptions{Name: "w1", Config: fpConfig, Env: env, Once: true, Window: time.Hour}); err != nil || rep == nil {
		t.Errorf("a watcher after the cancelled one: %v", err)
	}
	if _, err := jb.DBStatus(t.Context(), dir, jb.DBOptions{}); err != nil {
		t.Errorf("reopening the store after a cancelled watch: %v", err)
	}
	k.close()
	if n := settle(before); n > before {
		t.Errorf("goroutines: %d before, %d after a cancelled watch", before, n)
	}
}

func TestCancelledServeShutsDownAndFreesThePort(t *testing.T) {
	k := newKibana(t, searchDocs())
	dir := exampleCase(t, k)
	if _, err := jb.HuntCase(t.Context(), dir, huntOpts()); err != nil {
		t.Fatal(err)
	}
	before := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := make(chan jb.ServeInfo, 1)
	done := make(chan error, 1)
	go func() {
		done <- jb.Serve(ctx, jb.ServeOptions{
			Dashboard: jb.DashboardOptions{Case: dir, Config: fpConfig, Now: fixedNow},
			Addr:      "127.0.0.1:0",
			Ready:     func(i jb.ServeInfo) { ready <- i },
		})
	}()
	var info jb.ServeInfo
	select {
	case info = <-ready:
	case err := <-done:
		t.Fatalf("Serve returned before it was ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("Serve never became ready")
	}
	if info.Remote {
		t.Error("a loopback bind reported as remote")
	}
	resp, err := http.Get("http://" + info.Addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returns nil after a graceful shutdown, got %v", err)
		}
	case <-time.After(promptly):
		t.Fatal("Serve did not return after cancel")
	}
	if c, err := net.DialTimeout("tcp", info.Addr, time.Second); err == nil {
		c.Close()
		t.Error("the port still accepts connections after Serve returned")
	}
	k.close()
	if n := settle(before); n > before {
		t.Errorf("goroutines: %d before, %d after Serve", before, n)
	}
	if _, err := jb.DBStatus(t.Context(), dir, jb.DBOptions{}); err != nil {
		t.Errorf("reopening the store after Serve: %v", err)
	}
}

func TestServeRefusesANonLoopbackBind(t *testing.T) {
	err := jb.Serve(t.Context(), jb.ServeOptions{Dashboard: jb.DashboardOptions{Case: exampleCase(t, nil)}, Addr: "0.0.0.0:0"})
	if !jb.IsUsage(err) {
		t.Errorf("want a usage error for a non-loopback Addr, got %v", err)
	}
}
