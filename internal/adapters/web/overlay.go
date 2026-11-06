package web

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// The overlays of an ip node: what the evidence store knows about the address. They are
// read when a person opens the node's record, never when the map loads, and each is plain
// text with its source and time. There is no verdict colour: a colour would be a judgement
// this tool does not make.
const (
	// overlayWindow is how far back the last-seen question looks.
	overlayWindow = 30 * 24 * time.Hour
	// overlayRepLimit bounds the reputation rows read for one address (one per source).
	overlayRepLimit = 50
)

// overlayBudget is the time limit of the store questions of one overlay. A query that
// takes longer is stopped and reads as "could not read the store", never as "none".
// It is a variable so a test can shorten it.
var overlayBudget = 3 * time.Second

// The four texts of an overlay line. They are distinct on purpose: an empty answer is
// not a clean one, and a failure is not an empty answer.
const (
	overlayNever     = "never looked up"
	overlayNone      = "none in the last 30 days"
	overlayCouldNot  = "could not read the store"
	overlayNoKeyText = "no key field is configured"
)

// overlayNotice is printed with every overlay. It names no verdict.
const overlayNotice = "Read from the evidence store when this record was opened. This is context, not attribution, and an empty line is not a clean result."

type overlayPage struct {
	Nav, Title string
	Label      string
	Lines      []string
}

// estateOverlay answers GET /estate/overlay?g=MAP&id=NODE for an ip node of a loaded
// estate map. The node is looked up in the loaded file and its id must parse as an
// address: only that canonical address reaches the store, as a bound parameter.
func (s *server) estateOverlay(w http.ResponseWriter, r *http.Request) {
	gs, n, _ := s.loadEstates(s.ctx(r))
	g, ok := findGraph(gs, r.URL.Query().Get("g"))
	if !ok || n.Bad() {
		s.missing(w, r, "no such estate map")
		return
	}
	id := r.URL.Query().Get("id")
	var node *core.EstateNode
	for i := range g.Nodes {
		if g.Nodes[i].ID == id && g.Nodes[i].Kind == "ip" {
			node = &g.Nodes[i]
			break
		}
	}
	addr, perr := netip.ParseAddr(strings.TrimPrefix(id, "ip:"))
	if node == nil || !strings.HasPrefix(id, "ip:") || perr != nil {
		s.missing(w, r, "no such address node in that estate map")
		return
	}
	p := overlayPage{Nav: "estate", Title: "Overlay " + c(node.Label), Label: c(node.Label)}

	ctx, cancel := context.WithTimeout(s.ctx(r), overlayBudget)
	defer cancel()
	st, err := s.d.Open(ctx)
	if err != nil {
		p.Lines = []string{"reputation: " + overlayCouldNot, "last seen in logs: " + overlayCouldNot}
		s.sendOverlay(w, r, p)
		return
	}
	defer st.Close()
	p.Lines = append(p.Lines, s.reputationLines(ctx, st, addr)...)
	p.Lines = append(p.Lines, s.lastSeenLine(ctx, st, addr))
	s.sendOverlay(w, r, p)
}

// reputationLines is the latest stored reputation row of each source for the address.
func (s *server) reputationLines(ctx context.Context, st core.DashboardStore, addr netip.Addr) []string {
	rows, err := st.Reputation(ctx, core.ReputationFilter{Indicators: []string{addr.String()}, Latest: true, Limit: overlayRepLimit})
	if err != nil || ctx.Err() != nil {
		return []string{"reputation: " + overlayCouldNot}
	}
	if len(rows) == 0 {
		return []string{"reputation: " + overlayNever}
	}
	out := make([]string, 0, len(rows))
	for _, x := range rows {
		out = append(out, "reputation: "+c(x.Verdict)+" ("+c(x.Source)+", observed "+day(x.Observed)+")")
	}
	return out
}

// lastSeenLine is the last time a stored event carried the address in the key field that
// `jb serve` takes, looking back overlayWindow from now.
func (s *server) lastSeenLine(ctx context.Context, st core.DashboardStore, addr netip.Addr) string {
	const label = "last seen in logs: "
	if s.d.Fields.Key == "" {
		return label + overlayNoKeyText
	}
	at, found, err := st.LastSeen(ctx, s.d.Fields.Key, addr.String(), s.d.Now().Add(-overlayWindow))
	if err != nil || ctx.Err() != nil {
		return label + overlayCouldNot
	}
	if !found {
		return label + overlayNone
	}
	return label + day(at)
}

// day prints a time as its UTC date, the precision of an overlay line.
func day(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02")
}

func (s *server) sendOverlay(w http.ResponseWriter, r *http.Request, p overlayPage) {
	if isHX(r) {
		s.send(w, r, http.StatusOK, overlayFragment(p))
		return
	}
	s.send(w, r, http.StatusOK, overlayView(p))
}
