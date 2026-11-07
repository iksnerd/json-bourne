package web

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// The timeline (RFC 0019): findings from the store and the cycles of every watcher, read
// from their logs, on one time axis. Every bound is a constant here, and a cut is always
// said before the table.
const (
	timelineFindingsLimit = 500 // findings rows asked of the store
	timelineWatchers      = 16  // watchers drawn
	timelineCycleRows     = 500 // cycle rows (and ticks) kept per watcher, newest first
	tlLaneLeft            = 150 // SVG: plot area x range, lane height and top margin
	tlLaneRight           = 990
	tlLaneH               = 44
	tlTop                 = 24
	tlWidth               = 1000
)

// timelineBudget is the time limit of the store question. A variable so a test can
// shorten it, as overlayBudget is.
var timelineBudget = 3 * time.Second

type tlWindow struct {
	Key string
	D   time.Duration
}

// timelineWindows are the windows the page offers, ending now; the last is the maximum.
var timelineWindows = []tlWindow{{"1h", time.Hour}, {"6h", 6 * time.Hour}, {"24h", 24 * time.Hour}, {"7d", 7 * 24 * time.Hour}}

const timelineDefaultWindow = "24h"

func windowOf(key string) tlWindow {
	for _, w := range timelineWindows {
		if w.Key == key {
			return w
		}
	}
	for _, w := range timelineWindows {
		if w.Key == timelineDefaultWindow {
			return w
		}
	}
	return timelineWindows[0]
}

// unnamedParam is the watcher parameter value of the unnamed watcher. It cannot be a
// real name: a name starts with a letter.
const unnamedParam = "_"

// runStampRE reads which watcher a run id belongs to: watch-<stamp> or
// watch-<name>-<stamp>, the shape app.WatchRunPrefixFor and the run clock make.
var runStampRE = regexp.MustCompile(`^watch-(?:([a-z][a-z0-9_-]{0,31})-)?\d{8}T\d{6}Z$`)

// watcherOfRun is the label of the watcher that made a run, or "(hunt)" for any other run.
func watcherOfRun(run string) string {
	m := runStampRE.FindStringSubmatch(run)
	switch {
	case m == nil:
		return "(hunt)"
	case m[1] == "":
		return "(unnamed)"
	}
	return m[1]
}

func watcherLabel(name string) string {
	if name == "" {
		return "(unnamed)"
	}
	return name
}

func logName(name string) string {
	if name == "" {
		return "watch.log"
	}
	return "watch." + name + ".log"
}

type tlOption struct {
	Value, Label string
	Checked      bool
}

type tlRow struct {
	Time, Kind, Watcher, Detail, Run, RunHref string
}

type tlMark struct {
	X, Y, Y2, W, H, R int
	Letter            string
	Filled            bool // a square rather than a ring
	Title, Href       string
}

type tlLane struct {
	Name         string
	Y            int
	Ticks, Dots  []tlMark
	Spans        []tlMark
	LabelX, Base int
}

type timelinePage struct {
	Nav, Title string
	Window     string
	Windows    []tlOption
	Watchers   []tlOption
	Sevs       []tlOption
	From, To   string
	Notices    []string // every cut, absence and unknown, before the results
	Horizons   []string // the retention horizon of each watcher
	Cut        bool     // a notice about a cut is active
	Rows       []tlRow
	Lanes      []tlLane
	SVGH       int
	AxisL      string
	AxisR      string
	LaneLeft   int
	LaneRight  int
	SVGW       int
	FindNote   string // empty when findings were read; else why none are shown
}

type tlSortRow struct {
	t      time.Time
	rank   int
	watch  string
	run    string
	sevKey int
	text   string
	row    tlRow
}

func (s *server) timeline(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	win := windowOf(q.Get("w"))
	now := s.d.Now().UTC().Truncate(time.Minute)
	from := now.Add(-win.D)
	p := timelinePage{Nav: "timeline", Title: "Timeline", Window: win.Key, From: tm(from), To: tm(now),
		SVGW: tlWidth, LaneLeft: tlLaneLeft, LaneRight: tlLaneRight}

	// Severity filter: closed set, unknown values dropped. In the filter's own order.
	askedSev := map[string]bool{}
	for _, v := range q["sev"] {
		askedSev[v] = true
	}
	var sevs []core.Severity
	for _, o := range sevOptions[1:] {
		sv, _ := core.ParseSeverity(o)
		if askedSev[o] {
			sevs = append(sevs, sv)
		}
		p.Sevs = append(p.Sevs, tlOption{Value: o, Label: o, Checked: askedSev[o]})
	}
	for _, o := range timelineWindows {
		p.Windows = append(p.Windows, tlOption{Value: o.Key, Label: o.Key, Checked: o.Key == win.Key})
	}

	// Watchers: those the history reader found; a requested name that was not found is ignored.
	var found []string
	histNote := ""
	if s.d.History == nil {
		histNote = "watch history is not available (no evidence directory is known): no cycle is shown and no gap is judged."
	} else {
		var err error
		found, err = s.d.History.Watchers(s.ctx(r))
		switch {
		case err != nil:
			histNote = "could not list the watchers: " + c(err.Error()) + ". No cycle is shown and no gap is judged."
		case len(found) == 0:
			histNote = "no watch log or status record was found in the evidence directory: no cycle is shown and no gap is judged."
		}
	}
	slices.Sort(found)
	askedW := map[string]bool{}
	for _, v := range q["watcher"] {
		askedW[v] = true
	}
	var chosen []string
	for _, n := range found {
		v := n
		if n == "" {
			v = unnamedParam
		}
		if askedW[v] {
			chosen = append(chosen, n)
		}
		p.Watchers = append(p.Watchers, tlOption{Value: v, Label: watcherLabel(n), Checked: askedW[v]})
	}
	filtered := len(chosen) > 0
	shown := found
	if filtered {
		shown = chosen
	}
	if histNote != "" {
		p.Notices = append(p.Notices, histNote)
	}
	if len(shown) > timelineWatchers {
		var rest []string
		for _, n := range shown[timelineWatchers:] {
			rest = append(rest, c(watcherLabel(n)))
		}
		p.Cut = true
		p.Notices = append(p.Notices, "INCOMPLETE: "+strconv.Itoa(len(rest))+" more watcher(s) found and not drawn: "+strings.Join(rest, ", ")+".")
		shown = shown[:timelineWatchers]
	}

	var rows []tlSortRow
	drawn := map[string]bool{} // lane labels of watchers that were read
	var laneOrder []string
	type tick struct {
		t       time.Time
		verdict string
		run     string
	}
	laneTicks := map[string][]tick{}
	laneSpans := map[string][]core.WatchNoCycle{}
	laneEvery := map[string]time.Duration{}
	runKnown := map[string]bool{}

	for _, n := range shown {
		label := watcherLabel(n)
		file := logName(n)
		h, err := s.d.History.Read(s.ctx(r), n, now)
		if err != nil {
			if errors.Is(err, core.ErrAbsent) {
				p.Notices = append(p.Notices, "watcher "+c(label)+": there is no "+file+" in the evidence directory, so no cycle is shown for it.")
			} else {
				p.Notices = append(p.Notices, "watcher "+c(label)+": could not read "+file+": "+c(err.Error())+".")
			}
			continue
		}
		drawn[label] = true
		laneOrder = append(laneOrder, label)
		laneEvery[label] = h.Every
		if h.Cut {
			p.Cut = true
			if len(h.Cycles) > 0 {
				p.Notices = append(p.Notices, "INCOMPLETE: "+file+" read from "+tm(h.Cycles[0].At)+" only; earlier cycles are not shown.")
			} else {
				p.Notices = append(p.Notices, "INCOMPLETE: "+file+" is larger than the read bound and holds no cycle line in the part read.")
			}
		}
		if h.Unparsed > 0 {
			p.Notices = append(p.Notices, strconv.Itoa(h.Unparsed)+" line(s) of "+file+" were read and not understood.")
		}
		switch {
		case h.Every <= 0:
			p.Notices = append(p.Notices, "watcher "+c(label)+": interval unknown (no readable watch-status record): no gap is judged for this watcher.")
		case len(h.Cycles) == 0:
			p.Notices = append(p.Notices, "watcher "+c(label)+": no cycle line in the log. No span is drawn, because the start is unknown.")
		}
		if h.Keep > 0 {
			p.Horizons = append(p.Horizons, c(label)+": findings of its runs older than "+h.Keep.String()+" (before "+tm(now.Add(-h.Keep))+") are removed by retention, so an empty finding column before then is not a result.")
		} else {
			p.Horizons = append(p.Horizons, c(label)+": retention horizon unknown (no readable watch-status record).")
		}

		// The reader returns cycles oldest first; the page does not rely on it.
		slices.SortStableFunc(h.Cycles, func(a, b core.WatchCycleLine) int { return cmp.Or(a.At.Compare(b.At), cmp.Compare(a.Run, b.Run)) })
		slices.SortStableFunc(h.Gaps, func(a, b core.WatchNoCycle) int { return cmp.Or(a.From.Compare(b.From), a.To.Compare(b.To)) })
		// Cycles in the window, oldest first; the newest are kept if there are too many.
		var cyc []core.WatchCycleLine
		for _, cl := range h.Cycles {
			if !cl.At.Before(from) && !cl.At.After(now) {
				cyc = append(cyc, cl)
			}
		}
		newest := ""
		if len(h.Cycles) > 0 {
			newest = h.Cycles[len(h.Cycles)-1].Run
		}
		if len(cyc) > timelineCycleRows {
			p.Cut = true
			p.Notices = append(p.Notices, "INCOMPLETE: the newest "+strconv.Itoa(timelineCycleRows)+" cycles of "+c(label)+" in this window are shown; older ones in the window are not.")
			cyc = cyc[len(cyc)-timelineCycleRows:]
		}
		for i, cl := range cyc {
			dur := "not recorded"
			if i == len(cyc)-1 && cl.Run == newest && h.Last != nil && h.Last.Run == cl.Run && !h.Last.Ended.Before(cl.At) {
				dur = h.Last.Ended.Sub(cl.At).Round(time.Second).String()
			}
			detail := "CYCLE " + c(cl.Verdict)
			if cl.Verdict == "INCOMPLETE" || cl.Verdict == "FAILED" {
				detail += " (not a quiet result)"
			}
			if cl.GapReported {
				if cl.GapFrom.IsZero() {
					detail += "; gap reported, span not read"
				} else {
					detail += "; gap reported: events " + tm(cl.GapFrom) + " to " + tm(cl.GapTo) + " were never examined"
				}
			}
			detail += "; duration " + dur
			rows = append(rows, tlSortRow{t: cl.At, rank: 1, watch: label, run: cl.Run, text: detail,
				row: tlRow{Time: tm(cl.At), Kind: "cycle", Watcher: c(label), Detail: detail, Run: c(cl.Run)}})
			laneTicks[label] = append(laneTicks[label], tick{cl.At, cl.Verdict, cl.Run})
		}
		for _, g := range h.Gaps {
			end := now
			if !g.To.IsZero() {
				end = g.To
			}
			if end.Before(from) {
				continue
			}
			span := end.Sub(g.From).Round(time.Second)
			every := h.Every.Round(time.Second)
			var text string
			if g.To.IsZero() {
				text = "No cycle line in " + file + " since " + tm(g.From) + " (" + span.String() + " until " + tm(now) + ")."
			} else {
				text = "No cycle line in " + file + " from " + tm(g.From) + " to " + tm(g.To) + " (" + span.String() + ")."
			}
			text += " This watcher's interval is " + every.String() + ", so this is more than " + strconv.Itoa(h.GapFactor) + " intervals. The log shows no cycle in this span. The cause is not known: the watcher may not have run, or its log may not have been written."
			rows = append(rows, tlSortRow{t: g.From, rank: 2, watch: label, text: text,
				row: tlRow{Time: tm(g.From), Kind: "no cycle recorded", Watcher: c(label), Detail: text, Run: "-"}})
			laneSpans[label] = append(laneSpans[label], g)
		}
	}

	// Findings.
	var fpage core.FindingsPage
	findingsRead := false
	if st, n := s.open(s.ctx(r)); st != nil {
		defer st.Close()
		ctx, cancel := context.WithTimeout(s.ctx(r), timelineBudget)
		defer cancel()
		fq := core.FindingsQuery{From: from, To: now, Severities: sevs, Limit: timelineFindingsLimit}
		if filtered {
			for _, n := range chosen {
				if n == "" {
					fq.RunPrefixes = append(fq.RunPrefixes, "watch-")
				} else {
					fq.RunPrefixes = append(fq.RunPrefixes, "watch-"+n+"-")
				}
			}
		}
		page, err := st.FindingsBetween(ctx, fq)
		switch {
		case err == nil:
			fpage, findingsRead = page, true
		case errors.Is(err, core.ErrAbsent):
			p.FindNote = "store not available: " + c(err.Error())
		default:
			p.FindNote = "could not read the store: " + c(err.Error()) + ". The cycles below are not affected."
		}
		if runs, rerr := st.Runs(ctx, runsLimit); rerr == nil {
			for _, g := range runs {
				runKnown[g.ID] = true
			}
		}
	} else {
		if n.Absent != "" {
			p.FindNote = "store not available: " + n.Absent
		} else {
			p.FindNote = "could not read the store: " + n.Err + ". The cycles below are not affected."
		}
	}
	type dot struct {
		t    time.Time
		sev  core.Severity
		run  string
		text string
	}
	laneDots := map[string][]dot{}
	if findingsRead {
		if fpage.More {
			p.Cut = true
			p.Notices = append(p.Notices, "INCOMPLETE: the newest "+strconv.Itoa(timelineFindingsLimit)+" findings of this window are shown; older ones in the window are not.")
		}
		if len(fpage.Rows) == 0 {
			p.FindNote = "no findings in this window. This says nothing about whether a hunt was complete."
			for _, hz := range p.Horizons {
				if !strings.Contains(hz, "unknown") {
					p.FindNote += " Findings of watch runs older than the retention horizon are removed (see below)."
					break
				}
			}
		}
	}
	for _, f := range fpage.Rows {
		wl := watcherOfRun(f.Run)
		sev := core.SeverityName(f.Severity)
		detail := "severity " + sev + ", detector " + c(f.Detector) + ", tag " + clip(f.Tag, 120)
		if !f.Window.From.IsZero() {
			span := f.Window.To.Sub(f.Window.From)
			if d := f.Created.Sub(f.Window.To); d > span || -d > span {
				detail += "; events " + tm(f.Window.From) + " to " + tm(f.Window.To) + " (the run was saved at " + tm(f.Created) + ")"
			}
		}
		rows = append(rows, tlSortRow{t: f.Created, rank: 0, watch: wl, run: f.Run, sevKey: -int(f.Severity), text: f.Detector + "\x00" + f.Tag + "\x00" + f.Summary,
			row: tlRow{Time: tm(f.Created), Kind: "finding", Watcher: c(wl), Detail: detail, Run: c(f.Run), RunHref: runHref(f.Run)}})
		laneDots[wl] = append(laneDots[wl], dot{f.Created, f.Severity, f.Run, detail})
	}

	// A total order: time newest first, then kind, watcher, run, severity, text. Two
	// loads of the same data, in whatever order a source listed them, give the same bytes.
	slices.SortFunc(rows, func(a, b tlSortRow) int {
		return cmp.Or(b.t.Compare(a.t), cmp.Compare(a.rank, b.rank), cmp.Compare(a.watch, b.watch), cmp.Compare(a.run, b.run),
			cmp.Compare(a.sevKey, b.sevKey), cmp.Compare(a.text, b.text), cmp.Compare(a.row.Detail, b.row.Detail))
	})
	for _, x := range rows {
		if x.row.Kind == "cycle" && runKnown[x.run] {
			x.row.RunHref = runHref(x.run)
		}
		p.Rows = append(p.Rows, x.row)
	}

	// Lanes: every watcher read, then any other label that has a finding.
	labels := slices.Clone(laneOrder)
	var extra []string
	for l := range laneDots {
		if !drawn[l] {
			extra = append(extra, l)
		}
	}
	slices.Sort(extra)
	labels = append(labels, extra...)
	total := now.Sub(from).Nanoseconds()
	xOf := func(t time.Time) int {
		off := t.Sub(from).Nanoseconds()
		off = max(0, min(off, total))
		return tlLaneLeft + int(off*int64(tlLaneRight-tlLaneLeft)/total)
	}
	for i, l := range labels {
		y := tlTop + i*tlLaneH
		lane := tlLane{Name: c(l), Y: y, LabelX: 4, Base: y + 30}
		ticks := laneTicks[l]
		slices.SortFunc(ticks, func(a, b tick) int { return cmp.Or(a.t.Compare(b.t), cmp.Compare(a.run, b.run)) })
		for _, t := range ticks {
			h, letter := 8, ""
			switch t.verdict {
			case "FINDINGS":
				h, letter = 14, "F"
			case "INCOMPLETE":
				h, letter = 22, "I"
			case "FAILED":
				h, letter = 22, "X"
			}
			x := xOf(t.t)
			m := tlMark{X: x, Y: y + 30 - h, Y2: y + 30, Letter: letter, Title: "cycle " + c(t.verdict) + " at " + tm(t.t)}
			if runKnown[t.run] {
				m.Href = runHref(t.run)
			}
			lane.Ticks = append(lane.Ticks, m)
		}
		dots := laneDots[l]
		slices.SortFunc(dots, func(a, b dot) int {
			return cmp.Or(a.t.Compare(b.t), cmp.Compare(a.run, b.run), cmp.Compare(int(a.sev), int(b.sev)), cmp.Compare(a.text, b.text))
		})
		for _, d := range dots {
			lane.Dots = append(lane.Dots, tlMark{X: xOf(d.t), Y: y + 38, R: 3, Filled: d.sev >= core.SevHigh, Title: "finding: " + d.text, Href: runHref(d.run)})
		}
		for _, g := range laneSpans[l] {
			end := now
			if !g.To.IsZero() {
				end = g.To
			}
			x1, x2 := xOf(g.From), xOf(end)
			lane.Spans = append(lane.Spans, tlMark{X: x1, Y: y + 2, W: max(x2-x1, 2), H: 26,
				Title: "no cycle line from " + tm(g.From) + " to " + map[bool]string{true: "now", false: tm(g.To)}[g.To.IsZero()]})
		}
		p.Lanes = append(p.Lanes, lane)
	}
	p.SVGH = tlTop + len(labels)*tlLaneH + 4
	p.AxisL, p.AxisR = tm(from), tm(now)
	if isHX(r) {
		s.send(w, r, http.StatusOK, timelineResults(p))
		return
	}
	s.send(w, r, http.StatusOK, timelineView(p))
}
