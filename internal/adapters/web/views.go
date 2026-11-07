package web

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/estategraph"
)

// textCap is how many characters of one stored string a page shows.
const textCap = 300

// clip makes stored text safe to put in a page: control characters are dropped and
// the length is capped. It does not escape; html/template does that, at the point of
// use and in the right context. clip never returns template.HTML.
func clip(s string, n int) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if r < 0x20 && r != '\t' || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 {
			r = '�'
		}
		if count == n {
			b.WriteString("…(cut)")
			return b.String()
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

func c(s string) string { return clip(s, textCap) }

func tm(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// note is the state of a panel that has nothing to show: the reason it is empty
// (Absent, an answer) or why asking failed (Err, a banner). A panel with either set
// never renders a table, so a failure cannot look like a clean result.
type note struct{ Err, Absent string }

func (n note) Bad() bool { return n.Err != "" || n.Absent != "" }

func noteOf(err error) note {
	if err == nil {
		return note{}
	}
	if errors.Is(err, core.ErrAbsent) {
		return note{Absent: c(err.Error())}
	}
	return note{Err: "query failed: " + c(err.Error())}
}

type count struct {
	Label string
	N     int64
}

func counts(cs []core.Count) []count {
	out := make([]count, len(cs))
	for i, x := range cs {
		out[i] = count{c(x.Label), x.N}
	}
	return out
}

type runRow struct {
	ID               string
	Created          string
	EventRuns        int
	Events, Findings int64
	Incomplete       bool
}

func runRowOf(g core.RunGroup) runRow {
	return runRow{ID: c(g.ID), Created: tm(g.Created), EventRuns: g.EventRuns, Events: g.Events, Findings: g.Findings, Incomplete: g.Incomplete()}
}

type findingRow struct {
	Run, Severity, SevClass, Detector, Tag, Summary, Window string
}

func findingRows(fs []core.StoredFinding) []findingRow {
	out := make([]findingRow, len(fs))
	for i, f := range fs {
		class := ""
		switch {
		case f.Severity >= core.SevHigh:
			class = "bad"
		case f.Severity >= core.SevActivity:
			class = "warn"
		}
		w := ""
		if !f.Window.From.IsZero() {
			w = tm(f.Window.From) + " to " + tm(f.Window.To)
		}
		out[i] = findingRow{c(f.Run), core.SeverityName(f.Severity), class, c(f.Detector), c(f.Tag), c(f.Summary), w}
	}
	return out
}

func (s *server) ctx(r *http.Request) context.Context { return r.Context() }

// open opens the store for this request. The returned note is non-empty when it
// could not be opened; the caller must then not render a store panel as empty.
func (s *server) open(ctx context.Context) (core.DashboardStore, note) {
	st, err := s.d.Open(ctx)
	if err != nil {
		return nil, noteOf(err)
	}
	return st, note{}
}

type overviewPage struct {
	Nav, Title string
	Store      note
	Stats      *core.StoreStats
	First      string
	Last       string
	RunsNote   note
	Runs       []runRow
	RunsLimit  int
}

func (s *server) overview(w http.ResponseWriter, r *http.Request) {
	p := overviewPage{Nav: "runs", Title: "Runs", RunsLimit: runsLimit}
	st, n := s.open(s.ctx(r))
	p.Store = n
	if st != nil {
		defer st.Close()
		if stats, err := st.Stats(s.ctx(r)); err != nil {
			p.Store = noteOf(err)
		} else {
			p.Stats, p.First, p.Last = &stats, tm(stats.FirstSeen), tm(stats.LastSeen)
		}
		runs, err := st.Runs(s.ctx(r), runsLimit)
		p.RunsNote = noteOf(err)
		for _, g := range runs {
			p.Runs = append(p.Runs, runRowOf(g))
		}
	}
	s.send(w, r, http.StatusOK, overviewView(p))
}

type runPage struct {
	Nav, Title   string
	ID           string
	Store        note
	Run          *runRow
	SummaryNote  note
	Summary      *core.EventSummary
	BySource     []count
	ByKind       []count
	ByStatus     []count
	TopPaths     []count
	TopKeys      []count
	Fields       core.DashboardFields
	FindingsNote note
	Findings     []findingRow
	EventsNote   note
	Events       []eventRow
	EventsLimit  int
	FindLimit    int
}

type eventRow struct{ Time, Run, Source, Kind, Fields string }

func eventRows(es []core.StoredEvent) []eventRow {
	out := make([]eventRow, len(es))
	for i, e := range es {
		keys := make([]string, 0, len(e.Fields))
		for k := range e.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "%s=%s ", clip(k, 40), clip(fmt.Sprint(e.Fields[k]), 120))
		}
		out[i] = eventRow{tm(e.Time), c(e.Run), c(e.Source), c(e.Kind), clip(strings.TrimSpace(b.String()), textCap)}
	}
	return out
}

func (s *server) run(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" || len(id) > 200 {
		s.missing(w, r, "no run id given, or it is too long")
		return
	}
	p := runPage{Nav: "runs", Title: "Run " + c(id), ID: c(id), Fields: s.d.Fields, EventsLimit: eventsLimit, FindLimit: findingsLimit}
	st, n := s.open(s.ctx(r))
	p.Store = n
	if st != nil {
		defer st.Close()
		g, err := st.Run(s.ctx(r), id)
		switch {
		case errors.Is(err, core.ErrNotFound):
			s.missing(w, r, "no run with that id")
			return
		case err != nil:
			p.Store = noteOf(err)
		default:
			row := runRowOf(g)
			p.Run = &row
		}
	}
	if p.Run != nil {
		sum, err := st.EventSummary(s.ctx(r), id, s.d.Fields, topLimit)
		p.SummaryNote = noteOf(err)
		if err == nil {
			p.Summary = &sum
			p.BySource, p.ByKind, p.ByStatus = counts(sum.BySource), counts(sum.ByKind), counts(sum.ByStatus)
			p.TopPaths, p.TopKeys = counts(sum.TopPaths), counts(sum.TopKeys)
		}
		fs, err := st.RunFindings(s.ctx(r), id, findingsLimit)
		p.FindingsNote, p.Findings = noteOf(err), findingRows(fs)
		es, err := st.RecentEvents(s.ctx(r), id, eventsLimit)
		p.EventsNote, p.Events = noteOf(err), eventRows(es)
	}
	s.send(w, r, http.StatusOK, runView(p))
}

type findingsPage struct {
	Nav, Title string
	Store      note
	Rows       []findingRow // after the filter
	Total      int          // stored rows before the filter
	Cut        bool
	Limit      int
	Q, Sev     string // the filter, as the form shows it
	Filtered   bool
}

// Note is the sentence above the table: how the rows are ordered and what was cut or
// filtered away, so a shorter list is never mistaken for the whole.
func (p findingsPage) Note() string {
	n := "Newest runs first, most severe first within a run"
	if p.Cut {
		n += "; showing the first " + strconv.Itoa(p.Limit) + ", more may exist"
	}
	if p.Filtered {
		n += "; " + strconv.Itoa(len(p.Rows)) + " of " + strconv.Itoa(p.Total) + " match the filter"
	}
	return n + "."
}

// sevOptions are the severity names the filter offers; "" is any.
var sevOptions = []string{"", "info", "check", "activity", "high", "critical"}

func sevLabel(o string) string {
	if o == "" {
		return "any"
	}
	return o
}

func validSev(v string) bool {
	for _, o := range sevOptions {
		if o == v {
			return true
		}
	}
	return false
}

// cut keeps at most n runes of s.
func cut(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

func (s *server) findings(w http.ResponseWriter, r *http.Request) {
	p := findingsPage{Nav: "findings", Title: "Findings", Limit: findingsLimit}
	p.Q = cut(strings.TrimSpace(r.URL.Query().Get("q")), 100)
	if sev := r.URL.Query().Get("sev"); validSev(sev) {
		p.Sev = sev
	}
	p.Filtered = p.Q != "" || p.Sev != ""
	st, n := s.open(s.ctx(r))
	p.Store = n
	if st != nil {
		defer st.Close()
		fs, err := st.LatestFindings(s.ctx(r), findingsLimit)
		p.Store = noteOf(err)
		if len(fs) > findingsLimit {
			fs, p.Cut = fs[:findingsLimit], true
		}
		all := findingRows(fs)
		p.Total = len(all)
		p.Cut = p.Cut || len(fs) == findingsLimit
		needle := strings.ToLower(p.Q)
		for _, f := range all {
			if p.Sev != "" && f.Severity != p.Sev {
				continue
			}
			if needle != "" && !strings.Contains(strings.ToLower(f.Detector+" "+f.Tag+" "+f.Summary+" "+f.Run), needle) {
				continue
			}
			p.Rows = append(p.Rows, f)
		}
	}
	if isHX(r) {
		s.send(w, r, http.StatusOK, findingsResults(p))
		return
	}
	s.send(w, r, http.StatusOK, findingsView(p))
}

type repRow struct{ Indicator, Verdict, Source, Observed string }

type reputationPage struct {
	Nav, Title string
	Store      note
	Rows       []repRow
	Limit      int
}

func (s *server) reputation(w http.ResponseWriter, r *http.Request) {
	p := reputationPage{Nav: "reputation", Title: "Reputation snapshots", Limit: repLimit}
	st, n := s.open(s.ctx(r))
	p.Store = n
	if st != nil {
		defer st.Close()
		rs, err := st.LatestReputation(s.ctx(r), repLimit)
		p.Store = noteOf(err)
		for _, x := range rs {
			p.Rows = append(p.Rows, repRow{c(x.Indicator), c(x.Verdict), c(x.Source), tm(x.Observed)})
		}
	}
	s.send(w, r, http.StatusOK, reputationView(p))
}

var cycleRE = regexp.MustCompile(`CYCLE (QUIET|FINDINGS|INCOMPLETE|FAILED)\b`)

type seenRow struct{ Tag, Severity, At string }
type outageRow struct{ Component, At string }

type watchPage struct {
	Nav, Title string
	LogNote    note
	LogEmpty   bool
	Lines      []string
	Cycle      string // last cycle verdict word, "" when none was found
	CycleLine  string
	CycleAge   string
	Healthy    bool
	NoCycle    bool
	StateNote  note
	HasState   bool
	Seen       []seenRow
	Outages    []outageRow
	TailLines  int
}

func (s *server) watch(w http.ResponseWriter, r *http.Request) {
	p := watchPage{Nav: "watch", Title: "Watch", TailLines: logTailLines}
	if s.d.Log == nil {
		p.LogNote = note{Absent: "the watch log is not available (no evidence directory is known)"}
	} else {
		lines, err := s.d.Log.Tail(s.ctx(r), logTailLines)
		p.LogNote = noteOf(err)
		if err == nil && len(lines) == 0 {
			p.LogEmpty = true
		}
		for _, l := range lines {
			p.Lines = append(p.Lines, clip(l, 400))
		}
		for i := len(lines) - 1; i >= 0 && err == nil; i-- {
			if m := cycleRE.FindStringSubmatch(lines[i]); m != nil {
				p.Cycle, p.CycleLine = m[1], clip(lines[i], 400)
				p.Healthy = m[1] == "QUIET" || m[1] == "FINDINGS"
				if at, perr := time.Parse(time.RFC3339, strings.Fields(lines[i])[0]); perr == nil {
					p.CycleAge = s.d.Now().Sub(at).Round(time.Second).String() + " ago"
				}
				break
			}
		}
		p.NoCycle = err == nil && !p.LogEmpty && p.Cycle == ""
	}
	if s.d.State == nil {
		p.StateNote = note{Absent: "the watch state is not available (no evidence directory is known)"}
	} else {
		st, err := s.d.State.Peek(s.ctx(r))
		switch {
		case errors.Is(err, core.ErrStateCorrupt):
			p.StateNote = note{Err: "watch state is corrupt: " + c(err.Error())}
		default:
			p.StateNote = noteOf(err)
		}
		if err == nil {
			p.HasState = true
			for tag, v := range st.Seen {
				p.Seen = append(p.Seen, seenRow{c(tag), core.SeverityName(v.Severity), tm(v.At)})
			}
			sort.Slice(p.Seen, func(i, j int) bool {
				return p.Seen[i].At > p.Seen[j].At || p.Seen[i].At == p.Seen[j].At && p.Seen[i].Tag < p.Seen[j].Tag
			})
			if len(p.Seen) > findingsLimit {
				p.Seen = p.Seen[:findingsLimit]
			}
			for comp, h := range st.Health {
				p.Outages = append(p.Outages, outageRow{c(comp), tm(h.At)})
			}
			sort.Slice(p.Outages, func(i, j int) bool { return p.Outages[i].Component < p.Outages[j].Component })
		}
	}
	if isHX(r) {
		s.send(w, r, http.StatusOK, watchPanel(p))
		return
	}
	s.send(w, r, http.StatusOK, watchView(p))
}

// ---- estate ----

type nodeRow struct {
	G, ID, Kind, Label, Source, Method, Observed string
	NFacts                                       int
}

type factRow struct{ Key, Value, Source, Method, Observed string }

// factGroup is every fact of one key. Values are listed in value order, so a key with
// several values (two open ports, say) shows each one under the key once.
type factGroup struct {
	Key   string
	Facts []factRow
}

// groupFacts groups facts by key, any key. Groups are in key order and the facts of a
// group in value order, then source, method and time, so the same file always renders
// the same page.
func groupFacts(fs []core.EstateFact) []factGroup {
	rows := make([]factRow, 0, len(fs))
	for _, f := range fs {
		rows = append(rows, factRowOf(f))
	}
	slices.SortStableFunc(rows, func(a, b factRow) int {
		return cmp.Or(cmp.Compare(a.Key, b.Key), cmp.Compare(a.Value, b.Value), cmp.Compare(a.Source, b.Source),
			cmp.Compare(a.Method, b.Method), cmp.Compare(a.Observed, b.Observed))
	})
	var out []factGroup
	for _, r := range rows {
		if n := len(out); n == 0 || out[n-1].Key != r.Key {
			out = append(out, factGroup{Key: r.Key})
		}
		out[len(out)-1].Facts = append(out[len(out)-1].Facts, r)
	}
	return out
}

// assessRow is one assessment as shown. It is opinion: the page prints assessmentNotice
// with every list of them, whatever the file's caveat says.
type assessRow struct{ ID, Subject, Label, By, Decided, Basis, Note string }

// assessmentNotice is the fixed text printed with every assessment section. It is not
// taken from the file.
const assessmentNotice = "An assessment is the opinion of its author and not an observation. It rests on the basis it lists; check that before relying on it."

func factRowOf(f core.EstateFact) factRow {
	return factRow{c(f.Key), c(f.Value), c(f.Source), c(f.Method), c(f.Observed)}
}

func assessRowOf(a core.EstateAssessment) assessRow {
	basis := make([]string, 0, len(a.Basis))
	for _, b := range a.Basis {
		basis = append(basis, c(b))
	}
	return assessRow{c(a.ID), c(a.Subject), c(a.Label), c(a.By), c(a.Decided), strings.Join(basis, ", "), c(a.Note)}
}

// assessmentsOf returns the rows of the assessments about one node ("" means all of
// them), at most tableCap.
func assessmentsOf(g core.EstateGraph, subject string) []assessRow {
	var out []assessRow
	for _, a := range g.Assessments {
		if (subject == "" || a.Subject == subject) && len(out) < tableCap {
			out = append(out, assessRowOf(a))
		}
	}
	return out
}

// citingOf returns the assessments about other nodes that cite this node in their basis,
// at most tableCap. A basis entry cites a node when it is the node's id or the id followed
// by "#" and a fact key; an entry that only starts with the same characters does not.
func citingOf(g core.EstateGraph, id string) []assessRow {
	var out []assessRow
	for _, a := range g.Assessments {
		if a.Subject == id || len(out) >= tableCap {
			continue
		}
		for _, b := range a.Basis {
			if b == id || strings.HasPrefix(b, id+"#") {
				out = append(out, assessRowOf(a))
				break
			}
		}
	}
	return out
}

type edgeRow struct {
	G                                  string
	I                                  int
	From, To, Relation, Source, Method string
	Observed, Confidence, InferredFrom string
}
type absenceRow struct{ Subject, Source, Method, Observed, Answer string }

type svgNode struct {
	X, Y, LX int
	Label    string
	G, ID    string
}
type svgEdge struct {
	X1, Y1, X2, Y2 int
	Stale          bool
}

type graphView struct {
	ID, Caveat           string
	Src                  string // where the browser fetches the graph data
	Filtered             bool
	ConfFiltered         bool // an edge confidence filter is on
	Legend               []relCount
	LegendCut            bool
	NodeShown, EdgeShown int
	Nodes                []nodeRow
	Edges                []edgeRow
	Absences             []absenceRow
	Assessments          []assessRow
	AssessmentTotal      int
	NodeTotal, EdgeTotal int
	SVGNodes             []svgNode
	SVGEdges             []svgEdge
	SVGW, SVGH           int
	SVG                  bool
	SVGCut               bool
}

func nodeRowOf(g string, n core.EstateNode) nodeRow {
	return nodeRow{c(g), c(n.ID), c(n.Kind), c(n.Label), c(n.Source), c(n.Method), c(n.Observed), len(n.Facts)}
}
func edgeRowOf(g string, i int, e core.EstateEdge) edgeRow {
	return edgeRow{c(g), i, c(e.From), c(e.To), c(e.Relation), c(e.Source), c(e.Method), c(e.Observed), c(e.Confidence), c(e.InferredFrom)}
}

// relCount is how many drawn edges carry one relation.
type relCount struct {
	Relation string
	N        int
}

// legendOf counts the edges of the interactive drawing by relation, in relation order.
// It builds the layout the graph data route builds, so a count is the number of lines of
// that relation the person sees. cut says the drawing holds only the most connected nodes.
func legendOf(g core.EstateGraph, kinds, confs []string, now time.Time) ([]relCount, bool) {
	l := estategraph.Build(g, estategraph.Options{Limit: graphJSONNodes, Now: now, Kinds: kinds, Confidences: confs})
	n := map[string]int{}
	for _, e := range l.Edges {
		n[c(e.Relation)]++
	}
	out := make([]relCount, 0, len(n))
	for r, k := range n {
		out = append(out, relCount{r, k})
	}
	slices.SortFunc(out, func(a, b relCount) int { return cmp.Compare(a.Relation, b.Relation) })
	return out, l.Cut
}

func buildGraph(g core.EstateGraph, kinds, confs []string, now time.Time) graphView {
	v := graphView{ID: c(g.ID), Caveat: c(g.Caveat), NodeTotal: len(g.Nodes), EdgeTotal: len(g.Edges),
		Assessments: assessmentsOf(g, ""), AssessmentTotal: len(g.Assessments), Filtered: len(kinds) > 0, ConfFiltered: len(confs) > 0}
	v.Src = graphHref(v.ID, kinds, confs)
	wantConf := kindSet(confs)
	chosen := kindSet(kinds)
	shown := map[string]bool{} // node ids that pass the filter
	for _, n := range g.Nodes {
		if !v.Filtered || chosen[n.Kind] {
			shown[n.ID] = true
			v.NodeShown++
			if len(v.Nodes) < tableCap {
				v.Nodes = append(v.Nodes, nodeRowOf(g.ID, n))
			}
		}
	}
	for i, e := range g.Edges {
		if (!v.Filtered || shown[e.From] && shown[e.To]) && (!v.ConfFiltered || wantConf[e.Confidence]) {
			v.EdgeShown++
			if len(v.Edges) < tableCap {
				v.Edges = append(v.Edges, edgeRowOf(g.ID, i, e))
			}
		}
	}
	for i, a := range g.Absences {
		if i == tableCap {
			break
		}
		v.Absences = append(v.Absences, absenceRow{c(a.Subject), c(a.Source), c(a.Method), c(a.Observed), c(a.Answer)})
	}
	// The drawing that needs no script: the most connected nodes in columns by kind.
	l := estategraph.Build(g, estategraph.Options{Limit: graphNodes, Now: now, Kinds: kinds, Confidences: confs})
	v.Legend, v.LegendCut = legendOf(g, kinds, confs, now)
	if len(l.Nodes) > 0 {
		v.SVG, v.SVGCut, v.SVGW, v.SVGH = true, l.Cut, l.Width, l.Height
		for _, n := range l.Nodes {
			v.SVGNodes = append(v.SVGNodes, svgNode{X: n.X, Y: n.Y, LX: n.X + 8, Label: clip(n.Label, 22), G: c(g.ID), ID: c(n.ID)})
		}
		xy := map[string][2]int{}
		for _, n := range l.Nodes {
			xy[n.ID] = [2]int{n.X, n.Y}
		}
		for _, e := range l.Edges {
			a, b := xy[e.From], xy[e.To]
			v.SVGEdges = append(v.SVGEdges, svgEdge{a[0], a[1], b[0], b[1], e.Stale})
		}
	}
	return v
}

// The three layers of the estate page, in this order. The heading text is fixed here and
// never taken from a file: a subject the viewer does not know falls under Unclassified
// and is not printed (the loader accepts only operated and adversary, RFC 0015).
const (
	headingOperated     = "Operated"
	headingAdversary    = "Adversary and third-party"
	headingUnclassified = "Unclassified"
)

type graphLayer struct {
	Heading string
	Graphs  []graphView
}

// layersOf groups the graphs by subject. A graph is never merged with another: each keeps
// its own nodes, edges and corroboration. A layer with no graph is left out.
func layersOf(gs []core.EstateGraph, kinds, confs []string, now time.Time) []graphLayer {
	layers := []graphLayer{{Heading: headingOperated}, {Heading: headingAdversary}, {Heading: headingUnclassified}}
	for _, g := range gs {
		i := 2
		switch g.Subject {
		case "operated":
			i = 0
		case "adversary":
			i = 1
		}
		layers[i].Graphs = append(layers[i].Graphs, buildGraph(g, kinds, confs, now))
	}
	out := layers[:0]
	for _, l := range layers {
		if len(l.Graphs) > 0 {
			out = append(out, l)
		}
	}
	return out
}

type estatePage struct {
	Nav, Title string
	Note       note
	NotWired   bool
	Layers     []graphLayer
	Cap        int
	Kinds      []string // the kinds the filter keeps; empty means all
	Confs      []string // the edge confidences the filter keeps; empty means all
}

// kindOptions are the node kinds the filter offers, each with whether it is chosen.
type kindOption struct {
	Kind    string
	Checked bool
}

func (p estatePage) KindOptions() []kindOption {
	chosen := kindSet(p.Kinds)
	out := make([]kindOption, 0, len(estategraph.Kinds))
	for _, k := range estategraph.Kinds {
		out = append(out, kindOption{k, chosen[k]})
	}
	return out
}

func kindSet(kinds []string) map[string]bool {
	m := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		m[k] = true
	}
	return m
}

// kindsOf reads the repeatable kind parameter. A value that is not a known node kind is
// dropped, never reflected and never an error, as an unknown severity is for the
// findings filter. The result is in the filter's own order, without repeats.
func kindsOf(r *http.Request) []string {
	asked := map[string]bool{}
	for _, k := range r.URL.Query()["kind"] {
		asked[k] = true
	}
	var out []string
	for _, k := range estategraph.Kinds {
		if asked[k] {
			out = append(out, k)
		}
	}
	return out
}

// confOption is an edge confidence the filter offers, with whether it is chosen.
type confOption struct {
	Confidence string
	Checked    bool
}

func (p estatePage) ConfOptions() []confOption {
	chosen := kindSet(p.Confs)
	out := make([]confOption, 0, len(estategraph.Confidences))
	for _, k := range estategraph.Confidences {
		out = append(out, confOption{k, chosen[k]})
	}
	return out
}

// confidencesOf reads the repeatable confidence parameter the way kindsOf reads kind:
// an unknown value is dropped, never reflected, never an error.
func confidencesOf(r *http.Request) []string {
	asked := map[string]bool{}
	for _, k := range r.URL.Query()["confidence"] {
		asked[k] = true
	}
	var out []string
	for _, k := range estategraph.Confidences {
		if asked[k] {
			out = append(out, k)
		}
	}
	return out
}

func (s *server) loadEstates(ctx context.Context) ([]core.EstateGraph, note, bool) {
	if s.d.Estate == nil {
		return nil, note{}, true
	}
	gs, err := s.d.Estate.Estates(ctx)
	return gs, noteOf(err), false
}

func (s *server) estate(w http.ResponseWriter, r *http.Request) {
	p := estatePage{Nav: "estate", Title: "Estate", Cap: tableCap}
	gs, n, notWired := s.loadEstates(s.ctx(r))
	p.Note, p.NotWired = n, notWired
	if !n.Bad() && !notWired && len(gs) == 0 {
		p.Note = note{Absent: "estate dir absent or empty: no estate file has been collected for this case (see `jb estate`)"}
	}
	p.Kinds = kindsOf(r)
	p.Confs = confidencesOf(r)
	p.Layers = layersOf(gs, p.Kinds, p.Confs, s.d.Now())
	if isHX(r) {
		s.send(w, r, http.StatusOK, estateGraphs(p))
		return
	}
	s.send(w, r, http.StatusOK, estateView(p))
}

func findGraph(gs []core.EstateGraph, id string) (core.EstateGraph, bool) {
	for _, g := range gs {
		if g.ID == id {
			return g, true
		}
	}
	return core.EstateGraph{}, false
}

type nodePage struct {
	Nav, Title string
	Caveat     string
	GraphID    string
	Node       nodeRow
	Out, In    []edgeRow
	Absences   []absenceRow
	Facts      []factGroup
	Assess     []assessRow
	Citing     []assessRow // assessments about other nodes that cite this one in their basis
	// OverlayHref is set for an ip node: where its reputation and last-seen overlay is read.
	OverlayHref string
}

func (s *server) estateNode(w http.ResponseWriter, r *http.Request) {
	gs, n, _ := s.loadEstates(s.ctx(r))
	g, ok := findGraph(gs, r.URL.Query().Get("g"))
	if !ok || n.Bad() {
		s.missing(w, r, "no such estate map")
		return
	}
	id := r.URL.Query().Get("id")
	for _, x := range g.Nodes {
		if x.ID != id {
			continue
		}
		p := nodePage{Nav: "estate", Title: "Node " + c(x.Label), Caveat: c(g.Caveat), GraphID: c(g.ID), Node: nodeRowOf(g.ID, x), Assess: assessmentsOf(g, id), Citing: citingOf(g, id)}
		if x.Kind == "ip" {
			p.OverlayHref = overlayHref(g.ID, x.ID)
		}
		p.Facts = groupFacts(x.Facts)
		for i, e := range g.Edges {
			if e.From == id && len(p.Out) < tableCap {
				p.Out = append(p.Out, edgeRowOf(g.ID, i, e))
			}
			if e.To == id && len(p.In) < tableCap {
				p.In = append(p.In, edgeRowOf(g.ID, i, e))
			}
		}
		for _, a := range g.Absences {
			if a.Subject == id && len(p.Absences) < tableCap {
				p.Absences = append(p.Absences, absenceRow{c(a.Subject), c(a.Source), c(a.Method), c(a.Observed), c(a.Answer)})
			}
		}
		s.sendNode(w, r, p)
		return
	}
	s.missing(w, r, "no such node in that estate map")
}

type edgePage struct {
	Nav, Title string
	Caveat     string
	GraphID    string
	Edge       edgeRow
	From, To   *nodeRow
	Corr       corroboration
}

// corroboration is what the file counts about an edge: how many distinct sources claim it
// and how recent the newest claim is. Sources is the list as text.
type corroboration struct {
	Count   int
	Sources string
	Newest  string
	Stale   bool
}

func (c corroboration) Plural() string {
	if c.Count == 1 {
		return "1 distinct source"
	}
	return str(c.Count) + " distinct sources"
}

func (s *server) estateEdge(w http.ResponseWriter, r *http.Request) {
	gs, n, _ := s.loadEstates(s.ctx(r))
	g, ok := findGraph(gs, r.URL.Query().Get("g"))
	if !ok || n.Bad() {
		s.missing(w, r, "no such estate map")
		return
	}
	i, err := strconv.Atoi(r.URL.Query().Get("i"))
	if err != nil || i < 0 || i >= len(g.Edges) {
		s.missing(w, r, "no such edge in that estate map")
		return
	}
	e := g.Edges[i]
	p := edgePage{Nav: "estate", Title: "Edge " + c(e.Relation), Caveat: c(g.Caveat), GraphID: c(g.ID), Edge: edgeRowOf(g.ID, i, e)}
	wt := estategraph.Weigh(g, s.d.Now())[i]
	srcs := make([]string, 0, len(wt.Sources))
	for _, x := range wt.Sources {
		srcs = append(srcs, c(x))
	}
	p.Corr = corroboration{Count: len(wt.Sources), Sources: strings.Join(srcs, ", "), Newest: tm(wt.Newest), Stale: wt.Stale}
	if wt.Newest.IsZero() {
		p.Corr.Newest = "unknown"
	}
	for _, x := range g.Nodes {
		row := nodeRowOf(g.ID, x)
		if x.ID == e.From {
			p.From = &row
		}
		if x.ID == e.To {
			p2 := row
			p.To = &p2
		}
	}
	s.sendEdge(w, r, p)
}

type notFoundPage struct{ Nav, Title, Message string }

// isHX reports whether htmx asked for this page: it then wants the fragment, not the page.
func isHX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// send renders a component into a buffer first, so a render error is a clean 500 and
// never half a page, and then writes it. Every page varies on HX-Request.
func (s *server) send(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	var b strings.Builder
	if err := c.Render(r.Context(), &b); err != nil {
		http.Error(w, "the page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Add("Vary", "HX-Request")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(b.String()))
}

func (s *server) sendNode(w http.ResponseWriter, r *http.Request, p nodePage) {
	if isHX(r) {
		s.send(w, r, http.StatusOK, nodeRecord(p, true))
		return
	}
	s.send(w, r, http.StatusOK, nodeView(p))
}

func (s *server) sendEdge(w http.ResponseWriter, r *http.Request, p edgePage) {
	if isHX(r) {
		s.send(w, r, http.StatusOK, edgeRecord(p, true))
		return
	}
	s.send(w, r, http.StatusOK, edgeView(p))
}

// ---- the data of the interactive graph ----

// graphJSONNodes bounds what the browser is asked to lay out.
const graphJSONNodes = 300

type jsonNode struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	Degree    int    `json:"degree"`
	Component int    `json:"component"`
	Href      string `json:"href"`
}

type jsonEdge struct {
	Source     string `json:"source"`
	Target     string `json:"target"`
	Relation   string `json:"relation"`
	SourceName string `json:"sourceName"`
	Confidence string `json:"confidence"`
	Href       string `json:"href"`
	// Weight is 1 to 3 from the distinct sources that claim the edge; Stale is true when
	// the newest claim is older than 90 days; Newest is that claim's time (RFC 3339, or
	// empty when it cannot be read). The file stores none of them.
	Weight  int      `json:"weight"`
	Stale   bool     `json:"stale"`
	Newest  string   `json:"newest"`
	Sources []string `json:"sources"`
}

type jsonGraph struct {
	ID         string     `json:"id"`
	NodeTotal  int        `json:"nodeTotal"`
	EdgeTotal  int        `json:"edgeTotal"`
	Components int        `json:"components"`
	Cut        bool       `json:"cut"`
	Filtered   bool       `json:"filtered"`
	Nodes      []jsonNode `json:"nodes"`
	Edges      []jsonEdge `json:"edges"`
}

// estateGraphJSON serves one estate map as JSON for the browser to draw. Every string is
// cleaned like the page's text, and encoding/json escapes <, > and & so the document is
// inert even if it were ever served as HTML. The links are built here, never taken from
// the file.
func (s *server) estateGraphJSON(w http.ResponseWriter, r *http.Request) {
	gs, n, _ := s.loadEstates(s.ctx(r))
	g, ok := findGraph(gs, r.URL.Query().Get("g"))
	if !ok || n.Bad() {
		http.Error(w, "no such estate map", http.StatusNotFound)
		return
	}
	l := estategraph.Build(g, estategraph.Options{Limit: graphJSONNodes, Now: s.d.Now(), Kinds: kindsOf(r), Confidences: confidencesOf(r)})
	out := jsonGraph{ID: c(g.ID), NodeTotal: l.NodeTotal, EdgeTotal: len(g.Edges), Components: l.Components, Cut: l.Cut, Filtered: l.Filtered,
		Nodes: []jsonNode{}, Edges: []jsonEdge{}}
	for _, x := range l.Nodes {
		out.Nodes = append(out.Nodes, jsonNode{ID: c(x.ID), Kind: c(x.Kind), Label: c(x.Label), Degree: x.Degree, Component: x.Component, Href: nodeHref(g.ID, x.ID)})
	}
	for _, e := range l.Edges {
		je := jsonEdge{Source: c(e.From), Target: c(e.To), Relation: c(e.Relation), SourceName: c(e.Source), Confidence: c(e.Confidence), Href: edgeHref(g.ID, e.Index),
			Weight: e.Weight, Stale: e.Stale, Sources: []string{}}
		for _, x := range e.Sources {
			je.Sources = append(je.Sources, c(x))
		}
		if !e.Newest.IsZero() {
			je.Newest = tm(e.Newest)
		}
		out.Edges = append(out.Edges, je)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(out)
}
