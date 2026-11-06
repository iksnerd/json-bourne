package plugin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// ProtocolVersion is the only protocol version this host speaks.
const ProtocolVersion = 1

// RoleMapper is the only role this host runs.
const RoleMapper = "mapper"

// Defaults for Limits.
const (
	DefaultMaxDocs          = 200
	DefaultDeadline         = 10 * time.Second
	DefaultMaxResponseBytes = 4 << 20
	DefaultMaxRequestBytes  = 8 << 20
	DefaultStderrBytes      = 4 << 10
	DefaultMaxBreaks        = 3

	maxConfigBytes   = 64 << 10
	maxManifestBytes = 16 << 10
	shutdownGrace    = 2 * time.Second
)

// ErrPlugin wraps every failure of the plugin protocol: a timeout, a crash, bad JSON,
// the wrong number of results, oversized output, a refused launch. A caller that sees
// it must fail the source for the run. It is never an empty result.
var ErrPlugin = errors.New("plugin failed")

// ErrBreakerOpen is returned without launching anything once the plugin has broken
// MaxBreaks times in a row in this run.
var ErrBreakerOpen = errors.New("plugin breaker open: too many consecutive failures")

// Limits bound what a plugin may cost. A zero field takes its default.
type Limits struct {
	MaxDocs          int           // documents per request
	Deadline         time.Duration // per request (and for the handshake)
	MaxResponseBytes int           // one response line
	MaxRequestBytes  int           // one request line
	StderrBytes      int           // stderr tail kept
	MaxBreaks        int           // consecutive breaks before the breaker opens
}

func (l Limits) withDefaults() Limits {
	if l.MaxDocs <= 0 {
		l.MaxDocs = DefaultMaxDocs
	}
	if l.Deadline <= 0 {
		l.Deadline = DefaultDeadline
	}
	if l.MaxResponseBytes <= 0 {
		l.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if l.MaxRequestBytes <= 0 {
		l.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if l.StderrBytes <= 0 {
		l.StderrBytes = DefaultStderrBytes
	}
	if l.MaxBreaks <= 0 {
		l.MaxBreaks = DefaultMaxBreaks
	}
	return l
}

// Manifest is the one line a plugin prints when it starts.
type Manifest struct {
	V            int             `json:"v"`
	Role         string          `json:"role"`
	Name         string          `json:"name"`
	Version      string          `json:"version,omitempty"`
	ConfigSchema json.RawMessage `json:"config_schema,omitempty"`
}

// Options configure a Host.
type Options struct {
	Entry  Entry
	Config map[string]any // mapper_config: data handed to the plugin on every request
	Limits Limits
	// Env looks a variable up in the host's own environment (os.LookupEnv in
	// production). Only PATH, HOME, LANG and TMPDIR are ever read from it.
	Env func(string) (string, bool)
}

// Host runs one plugin as one long-lived child process for one source. It is safe for
// concurrent use, but requests are serialised: the protocol is one request in flight.
type Host struct {
	entry  Entry
	config json.RawMessage
	lim    Limits
	env    func(string) (string, bool)

	mu       sync.Mutex
	p        *proc
	nextID   int64
	breaks   int
	closed   bool
	manifest Manifest
}

var _ core.BatchMapper = (*Host)(nil)

// NewHost checks the entry once (so a bad plugin fails when the source is built, not
// halfway through a run) and returns a host that has not launched anything yet. The
// checks run again before every launch.
func NewHost(o Options) (*Host, error) {
	if _, err := Verify(o.Entry); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPlugin, err)
	}
	cfg := json.RawMessage(`{}`)
	if o.Config != nil {
		b, err := json.Marshal(o.Config)
		if err != nil {
			return nil, fmt.Errorf("plugin %s: mapper_config is not JSON: %w", o.Entry.Name, err)
		}
		if len(b) > maxConfigBytes {
			return nil, fmt.Errorf("plugin %s: mapper_config is %d bytes, at most %d", o.Entry.Name, len(b), maxConfigBytes)
		}
		cfg = b
	}
	env := o.Env
	if env == nil {
		env = os.LookupEnv
	}
	return &Host{entry: o.Entry, config: cfg, lim: o.Limits.withDefaults(), env: env}, nil
}

// Manifest is what the plugin announced in its most recent handshake (zero before the first).
func (h *Host) Manifest() Manifest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.manifest
}

// Breaks is the current count of consecutive breaks.
func (h *Host) Breaks() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.breaks
}

// childEnv is the whole environment of the child: PATH, HOME, LANG and TMPDIR when
// the host has them, and nothing else. API keys in jb's environment never reach it.
func (h *Host) childEnv() []string {
	out := make([]string, 0, 4)
	for _, k := range []string{"PATH", "HOME", "LANG", "TMPDIR"} {
		if v, ok := h.env(k); ok {
			out = append(out, k+"="+v)
		}
	}
	return out
}

type lineMsg struct {
	line []byte
	err  error
}

type proc struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	lines  chan lineMsg  // closed when stdout ends
	done   chan struct{} // closed after the process has been reaped
	quit   chan struct{} // closed by kill: the reader must stop offering lines
	once   sync.Once
	stderr *boundedTail
	exit   error
}

func (h *Host) start() (*proc, error) {
	v, err := Verify(h.entry) // every launch, not once
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPlugin, err)
	}
	cmd := exec.Command(v.Path)
	cmd.Dir = v.Dir
	cmd.Env = h.childEnv()
	cmd.WaitDelay = shutdownGrace
	ownGroup(cmd)
	p := &proc{cmd: cmd, lines: make(chan lineMsg), done: make(chan struct{}), quit: make(chan struct{}), stderr: &boundedTail{cap: h.lim.StderrBytes}}
	cmd.Stderr = p.stderr
	if p.stdin, err = cmd.StdinPipe(); err != nil {
		return nil, fmt.Errorf("%w: plugin %s: %v", ErrPlugin, h.entry.Name, err)
	}
	if p.stdout, err = cmd.StdoutPipe(); err != nil {
		return nil, fmt.Errorf("%w: plugin %s: %v", ErrPlugin, h.entry.Name, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: plugin %s: cannot start: %v", ErrPlugin, h.entry.Name, err)
	}
	go p.read(h.lim.MaxResponseBytes)
	return p, nil
}

// read feeds stdout lines to p.lines until stdout ends, then reaps the process. Wait is
// called only after the last read so a final line is never lost to the pipe closing.
func (p *proc) read(max int) {
	br := bufio.NewReaderSize(p.stdout, 64<<10)
	for {
		line, err := readLine(br, max)
		if err != nil {
			// End of stream is the closed channel. Only a real fault is a message.
			if errors.Is(err, errLineTooLong) {
				select {
				case p.lines <- lineMsg{err: err}:
				case <-p.quit:
				}
			}
			break
		}
		select {
		case p.lines <- lineMsg{line: line}:
		case <-p.quit:
			p.finish()
			return
		}
	}
	close(p.lines)
	p.finish()
}

func (p *proc) finish() {
	p.exit = p.cmd.Wait()
	close(p.done)
}

var errLineTooLong = errors.New("line longer than the limit")

// readLine reads up to the next newline, failing as soon as more than max bytes have
// been seen, so an endless line costs max bytes of memory.
func readLine(br *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	for {
		frag, err := br.ReadSlice('\n')
		if len(buf)+len(frag) > max+1 { // +1: the newline itself
			return nil, errLineTooLong
		}
		buf = append(buf, frag...)
		switch {
		case err == nil:
			return bytes.TrimRight(buf, "\r\n"), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			if len(buf) > 0 && errors.Is(err, io.EOF) {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
}

// kill ends the process group and waits for the process to be reaped.
func (p *proc) kill() {
	p.once.Do(func() {
		close(p.quit)
		killGroup(p.cmd)
		_ = p.stdout.Close() // unblocks the reader even if a grandchild escaped the group
	})
	<-p.done
}

// stop asks politely (stdin closed) and kills after shutdownGrace.
func (p *proc) stop() {
	_ = p.stdin.Close()
	select {
	case <-p.done:
	case <-time.After(shutdownGrace):
		p.kill()
	}
	// A plugin that exited on its own may have left children behind; the group is gone
	// with the leader unless they stayed, so this is a no-op in the normal case.
	p.once.Do(func() { close(p.quit); killGroup(p.cmd) })
}

// exitText describes how the process ended, for an error message.
func (p *proc) exitText() string {
	select {
	case <-p.done:
	case <-time.After(500 * time.Millisecond):
		return "process still running"
	}
	if p.exit == nil {
		return "exited 0"
	}
	return "exited: " + scrub(p.exit.Error())
}

func (h *Host) wrap(p *proc, format string, a ...any) error {
	msg := fmt.Sprintf(format, a...)
	if p != nil {
		// Every caller is about to fail the call and kill the child. Doing it first makes
		// the stderr tail complete (Wait returns after stderr is drained) and the message
		// deterministic.
		p.kill()
		if t := scrub(p.stderr.String()); t != "" {
			msg += "; stderr: " + t
		}
	}
	return fmt.Errorf("%w: plugin %s: %s", ErrPlugin, h.entry.Name, msg)
}

// await waits for the next stdout line, bounded by the deadline and ctx.
func (h *Host) await(ctx context.Context, p *proc, what string, timer *time.Timer, werr <-chan error) ([]byte, error) {
	for {
		select {
		case m, ok := <-p.lines:
			switch {
			case !ok:
				return nil, h.wrap(p, "%s: stdout closed (%s)", what, p.exitText())
			case m.err != nil && errors.Is(m.err, errLineTooLong):
				return nil, h.wrap(p, "%s: output larger than %d bytes", what, h.lim.MaxResponseBytes)
			case m.err != nil:
				return nil, h.wrap(p, "%s: %v (%s)", what, m.err, p.exitText())
			}
			return m.line, nil
		case err := <-werr:
			if err != nil {
				return nil, h.wrap(p, "%s: writing the request: %v", what, err)
			}
			werr = nil
		case <-timer.C:
			return nil, h.wrap(p, "%s: no answer within %s", what, h.lim.Deadline)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (h *Host) handshake(ctx context.Context, p *proc) error {
	timer := time.NewTimer(h.lim.Deadline)
	defer timer.Stop()
	line, err := h.await(ctx, p, "handshake", timer, nil)
	if err != nil {
		return err
	}
	if len(line) > maxManifestBytes {
		return h.wrap(p, "handshake: manifest larger than %d bytes", maxManifestBytes)
	}
	var m Manifest
	if err := json.Unmarshal(line, &m); err != nil {
		return h.wrap(p, "handshake: the first line is not a JSON manifest")
	}
	switch {
	case m.V != ProtocolVersion:
		return h.wrap(p, "handshake: protocol version %d, this jb speaks %d", m.V, ProtocolVersion)
	case m.Role != RoleMapper:
		return h.wrap(p, "handshake: role %q, this host runs %q", scrub(m.Role), RoleMapper)
	case m.Name == "" || len(m.Name) > 64:
		return h.wrap(p, "handshake: manifest name is empty or longer than 64 bytes")
	}
	m.Name, m.Version = scrub(m.Name), scrub(m.Version)
	h.manifest = m
	return nil
}

type rawEvent struct {
	TS     string          `json:"ts"`
	Fields json.RawMessage `json:"fields"`
}

type response struct {
	ID         *int64            `json:"id"`
	Events     []json.RawMessage `json:"events"`
	Unparsable []int             `json:"unparsable"`
	Error      string            `json:"error"`
}

// MapBatch sends docs to the plugin, in requests of at most MaxDocs documents, and
// returns exactly one result per document. Any failure kills the child, counts toward
// the breaker and is returned: the caller must fail the source. There is no partial
// answer and no retry.
func (h *Host) MapBatch(ctx context.Context, docs []map[string]any) ([]core.MapResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, fmt.Errorf("%w: plugin %s: host is closed", ErrPlugin, h.entry.Name)
	}
	if h.breaks >= h.lim.MaxBreaks {
		return nil, fmt.Errorf("%w: plugin %s: %d consecutive failures: %w", ErrPlugin, h.entry.Name, h.breaks, ErrBreakerOpen)
	}
	out := make([]core.MapResult, 0, len(docs))
	for i := 0; i < len(docs); {
		enc, n, err := h.encodeChunk(docs[i:])
		if err != nil {
			return nil, err
		}
		res, err := h.call(ctx, enc, n)
		if err != nil {
			return nil, err
		}
		out = append(out, res...)
		i += n
	}
	if len(out) != len(docs) {
		return nil, h.fail(nil, fmt.Errorf("%w: plugin %s: internal: %d results for %d documents", ErrPlugin, h.entry.Name, len(out), len(docs)))
	}
	return out, nil
}

// encodeChunk marshals as many leading documents as fit in one request. A single
// document that cannot fit is an error, not a skip: dropping it would be a quiet pass.
func (h *Host) encodeChunk(docs []map[string]any) (encoded [][]byte, n int, err error) {
	budget := h.lim.MaxRequestBytes - len(h.config) - 64
	for n < len(docs) && n < h.lim.MaxDocs {
		b, merr := json.Marshal(docs[n])
		if merr != nil {
			return nil, 0, fmt.Errorf("%w: plugin %s: document is not JSON: %v", ErrPlugin, h.entry.Name, merr)
		}
		if len(b)+1 > budget {
			if n == 0 {
				return nil, 0, fmt.Errorf("%w: plugin %s: one document is %d bytes, over the %d-byte request limit", ErrPlugin, h.entry.Name, len(b), h.lim.MaxRequestBytes)
			}
			break
		}
		budget -= len(b) + 1
		encoded = append(encoded, b)
		n++
	}
	return encoded, n, nil
}

func (h *Host) call(ctx context.Context, enc [][]byte, n int) ([]core.MapResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h.p == nil {
		p, err := h.start()
		if err != nil {
			return nil, h.fail(nil, err)
		}
		h.p = p
		if err := h.handshake(ctx, p); err != nil {
			return nil, h.fail(p, err)
		}
	}
	p := h.p
	h.nextID++
	id := h.nextID
	var req bytes.Buffer
	fmt.Fprintf(&req, `{"v":%d,"id":%d,"config":`, ProtocolVersion, id)
	req.Write(h.config)
	req.WriteString(`,"docs":[`)
	for i, d := range enc {
		if i > 0 {
			req.WriteByte(',')
		}
		req.Write(d)
	}
	req.WriteString("]}\n")

	werr := make(chan error, 1)
	go func() { _, err := p.stdin.Write(req.Bytes()); werr <- err }()
	timer := time.NewTimer(h.lim.Deadline)
	defer timer.Stop()
	line, err := h.await(ctx, p, "request", timer, werr)
	if err != nil {
		return nil, h.fail(p, err)
	}
	res, err := h.decode(p, line, id, n)
	if err != nil {
		return nil, h.fail(p, err)
	}
	h.breaks = 0
	return res, nil
}

// fail kills the child. A cancelled context is not the plugin's fault and does not
// count toward the breaker; everything else does.
func (h *Host) fail(p *proc, err error) error {
	if p == nil {
		p = h.p
	}
	if p != nil {
		p.kill()
	}
	h.p = nil
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	h.breaks++
	return err
}

func (h *Host) decode(p *proc, line []byte, id int64, n int) ([]core.MapResult, error) {
	var r response
	if err := json.Unmarshal(line, &r); err != nil {
		return nil, h.wrap(p, "response is not valid JSON")
	}
	if r.ID == nil || *r.ID != id {
		return nil, h.wrap(p, "response id does not match request id %d", id)
	}
	if r.Error != "" {
		return nil, h.wrap(p, "reported an error: %s", scrub(r.Error))
	}
	if len(r.Events) != n {
		return nil, h.wrap(p, "returned %d result slots for %d documents", len(r.Events), n)
	}
	unp := make(map[int]bool, len(r.Unparsable))
	for _, i := range r.Unparsable {
		if i < 0 || i >= n || unp[i] {
			return nil, h.wrap(p, "unparsable list has an out-of-range or repeated index")
		}
		unp[i] = true
	}
	out := make([]core.MapResult, n)
	for i, raw := range r.Events {
		isNull := bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
		switch {
		case isNull && unp[i]:
			out[i] = core.MapResult{Unparsable: true}
		case isNull:
			return nil, h.wrap(p, "slot %d is null but not listed as unparsable (a skipped document)", i)
		case unp[i]:
			return nil, h.wrap(p, "slot %d has an event and is also listed as unparsable", i)
		default:
			ev, err := decodeEvent(raw)
			if err != nil {
				return nil, h.wrap(p, "slot %d: %v", i, err)
			}
			out[i] = core.MapResult{Event: ev}
		}
	}
	return out, nil
}

func decodeEvent(raw json.RawMessage) (core.Event, error) {
	var e rawEvent
	if err := json.Unmarshal(raw, &e); err != nil {
		return core.Event{}, errors.New("event is not an object with ts and fields")
	}
	t, err := time.Parse(time.RFC3339Nano, e.TS)
	if err != nil {
		return core.Event{}, errors.New("event ts is missing or not RFC 3339")
	}
	if len(bytes.TrimSpace(e.Fields)) == 0 || bytes.Equal(bytes.TrimSpace(e.Fields), []byte("null")) {
		return core.Event{}, errors.New("event has no fields object")
	}
	dec := json.NewDecoder(bytes.NewReader(e.Fields))
	dec.UseNumber()
	var f map[string]any
	if err := dec.Decode(&f); err != nil {
		return core.Event{}, errors.New("event fields is not an object")
	}
	for k, v := range f {
		f[k] = normalise(v)
	}
	return core.Event{Time: t, Fields: f}, nil
}

// normalise turns json.Number into int when it is a whole number that fits, else
// float64, so a plugin's "status": 401 equals the int a built-in mapper emits.
func normalise(v any) any {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return int(i)
		}
		if f, err := x.Float64(); err == nil && !math.IsInf(f, 0) {
			return f
		}
		return x.String()
	case map[string]any:
		for k, e := range x {
			x[k] = normalise(e)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = normalise(e)
		}
		return x
	}
	return v
}

// Close shuts the child down (stdin closed, then the group killed after a grace
// period) and refuses further requests. It is safe to call more than once.
func (h *Host) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	if h.p != nil {
		h.p.stop()
		h.p = nil
	}
	return nil
}
