// Package web is the read-only HTML dashboard behind `jb serve`.
//
// It is a serving adapter: it listens (the caller hands it a listener) and it never
// calls out. It depends on core and the standard library only. It reaches the
// evidence through narrow read ports (core.DashboardStore and friends), so it has no
// SQL, no file access and no way to write. An archtest rule keeps net/http client
// symbols out of this package; see internal/archtest.
//
// Everything that comes from the evidence is untrusted text: log lines carry
// attacker-controlled strings (paths, user agents, host names). It is rendered only
// through html/template's contextual escaping, never as template.HTML, and capped in
// length first. The page has no script, loads nothing from another origin and is
// served with a Content-Security-Policy that would block both anyway.
//
// There is no authentication. The default is to bind loopback and to refuse a
// request whose Host header is not a loopback name (DNS rebinding); a non-loopback
// bind is an explicit, loudly warned decision of the caller (CheckAddr).
package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/style.css
var styleCSS []byte

// Row limits. Every query the dashboard makes is bounded by one of these.
const (
	runsLimit     = 100
	topLimit      = 15
	eventsLimit   = 50
	findingsLimit = 200
	repLimit      = 200
	logTailLines  = 100
	tableCap      = 200 // estate rows drawn per table
	graphNodes    = 40  // nodes drawn in the SVG
	requestBudget = 20 * time.Second
)

// Deps are the read ports the dashboard is built on. Open is called once per request
// and the handle is closed when the request ends, so a writer (`jb watch`) can open
// the database between requests. Log, State and Estate may be nil: the panel then says
// it is not available.
type Deps struct {
	Open   func(ctx context.Context) (core.DashboardStore, error)
	Estate core.EstateReader
	Log    core.LogTailer
	State  core.WatchStatePeeker
	Fields core.DashboardFields
	Now    func() time.Time
}

// Options are the serving decisions the composition root takes.
type Options struct {
	// Loopback is true when the server is bound to a loopback address. The Host
	// header must then be a loopback name, which stops a web page in the operator's
	// browser reaching the dashboard through DNS rebinding.
	Loopback bool
}

const csp = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

type server struct {
	d     Deps
	o     Options
	pages map[string]*template.Template
}

// New returns the dashboard handler.
func New(d Deps, o Options) http.Handler {
	if d.Now == nil {
		d.Now = time.Now
	}
	s := &server{d: d, o: o, pages: map[string]*template.Template{}}
	for _, name := range []string{"overview", "run", "findings", "reputation", "watch", "estate", "node", "edge", "notfound"} {
		s.pages[name] = template.Must(template.New("layout").Funcs(template.FuncMap{
			"sev": core.SeverityName,
		}).ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html"))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", s.overview)
	mux.HandleFunc("/run", s.run)
	mux.HandleFunc("/findings", s.findings)
	mux.HandleFunc("/reputation", s.reputation)
	mux.HandleFunc("/watch", s.watch)
	mux.HandleFunc("/estate", s.estate)
	mux.HandleFunc("/estate/node", s.estateNode)
	mux.HandleFunc("/estate/edge", s.estateEdge)
	mux.HandleFunc("/static/style.css", s.style)
	mux.HandleFunc("/", s.notFound)
	inner := http.TimeoutHandler(mux, requestBudget, "the request took too long and was stopped")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			http.Error(w, "read-only dashboard: GET and HEAD only", http.StatusMethodNotAllowed)
			return
		}
		if o.Loopback && !loopbackHost(r.Host) {
			http.Error(w, "unexpected Host header: this dashboard answers on loopback names only", http.StatusMisdirectedRequest)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// loopbackHost reports whether a Host header names this machine's loopback.
func loopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// CheckAddr validates the listen address. A loopback address is returned as is
// ("localhost" becomes 127.0.0.1, so no name lookup decides where we bind). Anything
// else, including ":8090" and "0.0.0.0:8090", which listen on every interface, is
// refused unless allowRemote is set; remote is then true and the caller must warn.
func CheckAddr(addr string, allowRemote bool) (listen string, remote bool, err error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", false, fmt.Errorf("--addr %q: want HOST:PORT: %w", addr, err)
	}
	if n, perr := strconv.Atoi(port); perr != nil || n < 0 || n > 65535 {
		return "", false, fmt.Errorf("--addr %q: port %q is not 0-65535", addr, port)
	}
	if strings.EqualFold(host, "localhost") {
		return net.JoinHostPort("127.0.0.1", port), false, nil
	}
	if a, perr := netip.ParseAddr(host); perr == nil && a.IsLoopback() {
		return addr, false, nil
	}
	if !allowRemote {
		return "", false, fmt.Errorf("--addr %q is not a loopback address: the dashboard has no authentication and shows evidence; use 127.0.0.1, or pass --allow-remote to accept that risk", addr)
	}
	return addr, true, nil
}

// NewServer wraps h in an http.Server with bounded timeouts and header size.
func NewServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      requestBudget + 10*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// Serve serves on ln until ctx ends, then shuts down gracefully. It returns nil on a
// clean stop.
func Serve(ctx context.Context, srv *http.Server, ln net.Listener) error {
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			_ = srv.Close()
			return err
		}
		<-errc
		return nil
	}
}

func (s *server) style(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(styleCSS)
}

func (s *server) render(w http.ResponseWriter, status int, page string, data any) {
	var b strings.Builder
	if err := s.pages[page].ExecuteTemplate(&b, "layout", data); err != nil {
		http.Error(w, "the page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(b.String()))
}

func (s *server) notFound(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusNotFound, "notfound", struct{ Nav, Title, Message string }{"", "Not found", "no such page"})
}

func (s *server) missing(w http.ResponseWriter, what string) {
	s.render(w, http.StatusNotFound, "notfound", struct{ Nav, Title, Message string }{"", "Not found", what})
}
