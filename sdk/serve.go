// Package sdk is the plugin side of json-bourne: write a [Mapper], hand it to [Serve],
// and the stdio loop that speaks the plugin protocol is done for you. It also holds a
// bounded line reader and the field mapping and type coercion the example plugins are
// configured with.
//
// It imports the standard library only and none of jb's host code, so a plugin author
// links nothing of the host. The protocol is documented in docs/PLUGINS.md; this
// package is one implementation of it, not the definition. The API is v0 and may
// change between minor versions.
//
// This is the plugin side of json-bourne's own mapper protocol and nothing else. It is
// not an implementation of another project's plugin protocol, and a plugin built with
// it will not run under another host. See docs/adr/0001-relationship-to-other-plugin-specifications.md.
package sdk

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// ProtocolVersion is the protocol version these plugins speak.
const ProtocolVersion = 1

// MaxRequestLine bounds one request line a plugin will read. The host's own default
// request limit is 8 MiB; this is deliberately above it.
const MaxRequestLine = 16 << 20

// ErrUnparsable marks a document that is not in the format the mapper reads. The
// protocol reports it per document and the host counts it; it does not stop the run.
var ErrUnparsable = errors.New("unparsable document")

// Event is what a mapper produces for one document.
type Event struct {
	Time   time.Time
	Fields map[string]any
}

// Mapper turns one decoded document into an event. Return an error wrapping
// ErrUnparsable for a document that does not match; any other error fails the whole
// request (the source then fails the run), so use it only for a fault in the document
// set or the configuration, never for one odd line.
type Mapper interface {
	Map(doc map[string]any, raw int) (Event, error)
}

// Plugin describes a mapper plugin to Serve.
type Plugin struct {
	Name         string
	Version      string
	ConfigSchema string // one human-readable sentence or two, shown by tooling
	// New builds a Mapper from the request's config (the operator's mapper_config).
	// An error fails the request with that message.
	New func(config json.RawMessage) (Mapper, error)
}

type request struct {
	V      int               `json:"v"`
	ID     int64             `json:"id"`
	Config json.RawMessage   `json:"config"`
	Docs   []json.RawMessage `json:"docs"`
}

type response struct {
	ID         int64  `json:"id"`
	Events     []any  `json:"events,omitempty"`
	Unparsable []int  `json:"unparsable,omitempty"`
	Error      string `json:"error,omitempty"`
}

type wireEvent struct {
	TS     string         `json:"ts"`
	Fields map[string]any `json:"fields"`
}

// Serve prints the manifest and then answers one response per request line until in
// ends. It returns nil on a clean end of input.
func Serve(in io.Reader, out io.Writer, p Plugin) error {
	bw := bufio.NewWriter(out)
	man := map[string]any{"v": ProtocolVersion, "role": "mapper", "name": p.Name, "version": p.Version}
	if p.ConfigSchema != "" {
		man["config_schema"] = p.ConfigSchema
	}
	if err := writeJSON(bw, man); err != nil {
		return err
	}
	br := bufio.NewReaderSize(in, 64<<10)
	var (
		cfgKey []byte
		mapper Mapper
	)
	for {
		line, err := ReadLine(br, MaxRequestLine)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading request: %w", err)
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			return fmt.Errorf("request is not JSON: %w", err)
		}
		if req.V != ProtocolVersion {
			if err := writeJSON(bw, response{ID: req.ID, Error: fmt.Sprintf("protocol version %d not supported", req.V)}); err != nil {
				return err
			}
			continue
		}
		if mapper == nil || !bytes.Equal(cfgKey, req.Config) {
			m, merr := build(p, req.Config)
			if merr != nil {
				if err := writeJSON(bw, response{ID: req.ID, Error: "config: " + merr.Error()}); err != nil {
					return err
				}
				continue
			}
			mapper, cfgKey = m, append(cfgKey[:0], req.Config...)
		}
		if err := writeJSON(bw, handle(mapper, req)); err != nil {
			return err
		}
	}
}

// build calls p.New. A panic there is a bug in the plugin, reported like a panic in Map:
// a response error without the panic value, and the cached mapper is left as it was.
func build(p Plugin, cfg json.RawMessage) (m Mapper, err error) {
	defer func() {
		if r := recover(); r != nil {
			m, err = nil, errors.New("internal error while building the mapper")
		}
	}()
	return p.New(cfg)
}

func handle(m Mapper, req request) (resp response) {
	resp = response{ID: req.ID, Events: make([]any, len(req.Docs))}
	defer func() {
		// A panic is a bug in the mapper. It is reported loudly, without the document,
		// instead of being counted as an odd line.
		if r := recover(); r != nil {
			resp = response{ID: req.ID, Error: "internal error while mapping a document"}
		}
	}()
	for i, raw := range req.Docs {
		var doc map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil || doc == nil {
			resp.Unparsable = append(resp.Unparsable, i)
			continue
		}
		ev, err := m.Map(doc, len(raw))
		switch {
		case errors.Is(err, ErrUnparsable):
			resp.Unparsable = append(resp.Unparsable, i)
		case err != nil:
			return response{ID: req.ID, Error: err.Error()}
		default:
			resp.Events[i] = wireEvent{TS: ev.Time.UTC().Format(time.RFC3339Nano), Fields: ev.Fields}
		}
	}
	return resp
}

func writeJSON(w *bufio.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	w.Write(b)
	w.WriteByte('\n')
	return w.Flush()
}

// ReadLine reads one newline-terminated line of at most max bytes. A longer line is an
// error as soon as it is known to be too long, so an endless line costs max bytes.
func ReadLine(br *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	for {
		frag, err := br.ReadSlice('\n')
		if len(buf)+len(frag) > max+1 {
			return nil, errors.New("line longer than the limit")
		}
		buf = append(buf, frag...)
		switch {
		case err == nil:
			return bytes.TrimRight(buf, "\r\n"), nil
		case errors.Is(err, bufio.ErrBufferFull):
		case errors.Is(err, io.EOF) && len(buf) == 0:
			return nil, io.EOF
		default:
			return nil, err
		}
	}
}
