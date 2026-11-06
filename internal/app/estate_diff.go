package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/core"
)

// The estate drift check compares two states of the operator's own estate. It is the
// passive counterpart of an active "did anything change" scan: it reads two files and
// sends nothing.
//
// The rule that makes a comparison honest: an observation is only comparable with
// another made by the SAME source and the SAME method. A claim's method is the exact
// question (the query, and the resolver or service it went to). Asking the same name of
// another resolver, or through another service, is a different question and its answer
// differing is not a change of the world. Such questions are listed as not comparable,
// never counted as drift and never dropped from the output.

// ErrIncompleteSnapshot means one side of a comparison is a snapshot whose run did not
// finish. Its absences of data would read as removals, so it is refused.
var ErrIncompleteSnapshot = errors.New("snapshot is incomplete")

// Change kinds and item types.
const (
	ChangeAdded   = "added"
	ChangeRemoved = "removed"
	ChangeChanged = "changed"

	ItemNode    = "node"
	ItemEdge    = "edge"
	ItemAbsence = "absence"
	ItemFact    = "fact"
)

// DriftSide describes one side of a comparison, so the output says exactly what was
// compared.
type DriftSide struct {
	Ref      string `json:"ref"`
	Path     string `json:"path"`
	Snapshot string `json:"snapshot,omitempty"` // snapshot id, when it is one
	Taken    string `json:"taken,omitempty"`
	Observed string `json:"latest_observed"` // the latest claim time in the file
	Nodes    int    `json:"nodes"`
	Edges    int    `json:"edges"`
	Absences int    `json:"absences"`
	Facts    int    `json:"facts"`
}

// EstateChange is one difference between two observations of the same question.
type EstateChange struct {
	Kind         string `json:"kind"`
	Type         string `json:"type"`
	Subject      string `json:"subject"`
	From         string `json:"from,omitempty"`
	To           string `json:"to,omitempty"`
	Relation     string `json:"relation,omitempty"`
	Source       string `json:"source"`
	Method       string `json:"method"`
	FromObserved string `json:"from_observed"`
	ToObserved   string `json:"to_observed"`
	Detail       string `json:"detail,omitempty"`
	// Value is the fact value that appeared or disappeared (type fact only). Subject is
	// then "<node id>#<fact key>".
	Value string `json:"value,omitempty"`
}

// NotComparable is a question that exists on one side only, or a node recorded under a
// different source or method on each side. It is listed so the reader knows what the
// comparison could not say.
type NotComparable struct {
	Source   string `json:"source"`
	Method   string `json:"method"`
	Side     string `json:"side"` // "from only" or "to only"
	Claims   int    `json:"claims"`
	Observed string `json:"observed"`
	Reason   string `json:"reason"`
	// Subject is "<node id>#<fact key>" for a group of facts that exists on one side only.
	Subject string `json:"subject,omitempty"`
}

// EstateDiff is the result of comparing two estate states.
type EstateDiff struct {
	From          DriftSide       `json:"from"`
	To            DriftSide       `json:"to"`
	Compared      int             `json:"questions_compared"`
	Changes       []EstateChange  `json:"changes"`
	NotComparable []NotComparable `json:"not_comparable"`
	// NodesNotCompared counts nodes present on both sides but recorded by a different
	// source or method on each, whose labels therefore were not compared.
	NodesNotCompared int `json:"nodes_not_compared"`
}

// Count returns how many changes have this kind and type ("" matches any).
func (d EstateDiff) Count(kind, typ string) int {
	n := 0
	for _, c := range d.Changes {
		if (kind == "" || c.Kind == kind) && (typ == "" || c.Type == typ) {
			n++
		}
	}
	return n
}

type qkey struct{ source, method string }

type qgroup struct {
	nodes    map[string]casefile.Node
	edges    map[string]casefile.Edge
	absences map[string]casefile.Absence
	observed string
}

func (g *qgroup) seen(at string) {
	if at > g.observed { // RFC 3339 in UTC compares as text; see normTime
		g.observed = at
	}
}

func (g *qgroup) claims() int { return len(g.nodes) + len(g.edges) + len(g.absences) }

// normTime renders an RFC 3339 time in UTC so that two times compare as text. An
// unparsable value (the loader refuses one) is returned unchanged.
func normTime(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}

func edgeIdentity(e casefile.Edge) string { return e.From + "\x00" + e.To + "\x00" + e.Relation }

func groupEstate(e *casefile.Estate) (map[qkey]*qgroup, string) {
	groups := map[qkey]*qgroup{}
	latest := ""
	get := func(s, m string) *qgroup {
		k := qkey{s, m}
		g := groups[k]
		if g == nil {
			g = &qgroup{nodes: map[string]casefile.Node{}, edges: map[string]casefile.Edge{}, absences: map[string]casefile.Absence{}}
			groups[k] = g
		}
		return g
	}
	for _, n := range e.Nodes {
		g := get(n.Source, n.Method)
		g.nodes[n.ID] = n
		at := normTime(n.Observed)
		g.seen(at)
		latest = max(latest, at)
	}
	for _, ed := range e.Edges {
		g := get(ed.Source, ed.Method)
		g.edges[edgeIdentity(ed)] = ed
		at := normTime(ed.Observed)
		g.seen(at)
		latest = max(latest, at)
	}
	for _, a := range e.Absences {
		g := get(a.Source, a.Method)
		g.absences[a.Subject] = a
		at := normTime(a.Observed)
		g.seen(at)
		latest = max(latest, at)
	}
	return groups, latest
}

func subjectName(s string) string {
	if s == "" {
		return "unclassified"
	}
	return s
}

func driftSide(s *casefile.EstateState, latest string) DriftSide {
	d := DriftSide{Ref: s.Ref, Path: s.Path, Observed: latest, Nodes: len(s.Estate.Nodes), Edges: len(s.Estate.Edges), Absences: len(s.Estate.Absences)}
	for _, n := range s.Estate.Nodes {
		d.Facts += len(n.Facts)
	}
	if s.Snapshot != nil {
		d.Snapshot, d.Taken = s.Snapshot.ID, s.Snapshot.Taken
	}
	return d
}

// DiffEstates compares two loaded states. An incomplete snapshot on either side is an
// error (ErrIncompleteSnapshot): comparing against it would report every question it
// failed to ask as a removal.
func DiffEstates(from, to *casefile.EstateState) (EstateDiff, error) {
	for _, s := range []*casefile.EstateState{from, to} {
		if s.Snapshot != nil && !s.Snapshot.Complete {
			return EstateDiff{}, fmt.Errorf("%w: %s did not finish (%d lookup(s) got no full answer); it is not a state of the estate and is never compared", ErrIncompleteSnapshot, s.Ref, len(s.Snapshot.Failures))
		}
	}
	if from.Estate.Subject != to.Estate.Subject {
		return EstateDiff{}, core.Usagef("cannot compare %s (subject %s) with %s (subject %s): an estate diff compares two files of the same subject", from.Ref, subjectName(from.Estate.Subject), to.Ref, subjectName(to.Estate.Subject))
	}
	gf, latestF := groupEstate(from.Estate)
	gt, latestT := groupEstate(to.Estate)
	out := EstateDiff{From: driftSide(from, latestF), To: driftSide(to, latestT), Changes: []EstateChange{}, NotComparable: []NotComparable{}}

	keys := map[qkey]bool{}
	for k := range gf {
		keys[k] = true
	}
	for k := range gt {
		keys[k] = true
	}
	sorted := make([]qkey, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].source != sorted[j].source {
			return sorted[i].source < sorted[j].source
		}
		return sorted[i].method < sorted[j].method
	})

	comparable := map[qkey]bool{}
	for _, k := range sorted {
		f, t := gf[k], gt[k]
		switch {
		case f != nil && t != nil:
			comparable[k] = true
			out.Compared++
			out.Changes = append(out.Changes, diffGroup(k, f, t)...)
		case f != nil:
			out.NotComparable = append(out.NotComparable, NotComparable{Source: k.source, Method: k.method, Side: "from only", Claims: f.claims(), Observed: f.observed,
				Reason: "this exact question (source and method) was not asked on the other side; a different method or resolver is not a change of the world"})
		default:
			out.NotComparable = append(out.NotComparable, NotComparable{Source: k.source, Method: k.method, Side: "to only", Claims: t.claims(), Observed: t.observed,
				Reason: "this exact question (source and method) was not asked on the other side; a different method or resolver is not a change of the world"})
		}
	}

	// Nodes are unique by id within a file, so a node carries the source and method of
	// the question that first named it. It is compared only when both sides name it
	// through the same question, and counted as added or removed only when the question
	// itself is comparable.
	nf, nt := map[string]casefile.Node{}, map[string]casefile.Node{}
	for _, n := range from.Estate.Nodes {
		nf[n.ID] = n
	}
	for _, n := range to.Estate.Nodes {
		nt[n.ID] = n
	}
	for _, n := range to.Estate.Nodes {
		fn, ok := nf[n.ID]
		switch {
		case !ok:
			if comparable[qkey{n.Source, n.Method}] {
				out.Changes = append(out.Changes, EstateChange{Kind: ChangeAdded, Type: ItemNode, Subject: n.ID, Source: n.Source, Method: n.Method,
					FromObserved: gf[qkey{n.Source, n.Method}].observed, ToObserved: normTime(n.Observed)})
			}
		case fn.Source != n.Source || fn.Method != n.Method:
			out.NodesNotCompared++
		case fn.Kind != n.Kind || fn.Label != n.Label:
			out.Changes = append(out.Changes, EstateChange{Kind: ChangeChanged, Type: ItemNode, Subject: n.ID, Source: n.Source, Method: n.Method,
				FromObserved: normTime(fn.Observed), ToObserved: normTime(n.Observed),
				Detail: fmt.Sprintf("kind %s, label %q -> kind %s, label %q", fn.Kind, fn.Label, n.Kind, n.Label)})
		}
	}
	for _, n := range from.Estate.Nodes {
		if _, ok := nt[n.ID]; !ok && comparable[qkey{n.Source, n.Method}] {
			out.Changes = append(out.Changes, EstateChange{Kind: ChangeRemoved, Type: ItemNode, Subject: n.ID, Source: n.Source, Method: n.Method,
				FromObserved: normTime(n.Observed), ToObserved: gt[qkey{n.Source, n.Method}].observed})
		}
	}
	if out.NodesNotCompared > 0 {
		out.NotComparable = append(out.NotComparable, NotComparable{Side: "both", Claims: out.NodesNotCompared,
			Reason: "node(s) present on both sides but recorded by a different source or method on each; labels were not compared"})
	}
	diffFacts(from.Estate, to.Estate, &out)
	sort.SliceStable(out.Changes, func(i, j int) bool { return changeKey(out.Changes[i]) < changeKey(out.Changes[j]) })
	return out, nil
}

// factGroup is the values one source and method recorded for one key of one node, as a
// set: a port list that gains an entry has gained one value, not replaced a list.
type factGroup struct {
	node, key, source, method string
	values                    map[string]casefile.Fact
	observed                  string // the latest time any fact of the group was observed
}

type factKey struct{ node, key, source, method string }

func groupFacts(e *casefile.Estate) map[factKey]*factGroup {
	out := map[factKey]*factGroup{}
	for _, n := range e.Nodes {
		for _, f := range n.Facts {
			k := factKey{n.ID, f.Key, f.Source, f.Method}
			g := out[k]
			if g == nil {
				g = &factGroup{node: n.ID, key: f.Key, source: f.Source, method: f.Method, values: map[string]casefile.Fact{}}
				out[k] = g
			}
			g.values[f.Value] = f
			if at := normTime(f.Observed); at > g.observed {
				g.observed = at
			}
		}
	}
	return out
}

// diffFacts compares facts as a set per node, key, source and method. A value that
// appears or disappears is a change with both observation times. A group that exists on
// one side only is listed as not comparable and is never drift, as for any claim.
// Assessments are opinion and are not compared.
func diffFacts(from, to *casefile.Estate, out *EstateDiff) {
	gf, gt := groupFacts(from), groupFacts(to)
	keys := make([]factKey, 0, len(gf)+len(gt))
	for k := range gf {
		keys = append(keys, k)
	}
	for k := range gt {
		if _, both := gf[k]; !both {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		return strings.Join([]string{a.node, a.key, a.source, a.method}, "\x00") < strings.Join([]string{b.node, b.key, b.source, b.method}, "\x00")
	})
	const reason = "this exact group of facts (node, key, source and method) was not recorded on the other side; a different source note or method is not a change of the world"
	for _, k := range keys {
		f, t := gf[k], gt[k]
		subject := k.node + "#" + k.key
		switch {
		case f != nil && t != nil:
			out.Compared++
			for v, tf := range t.values {
				if _, ok := f.values[v]; !ok {
					out.Changes = append(out.Changes, EstateChange{Kind: ChangeAdded, Type: ItemFact, Subject: subject, Value: v, Source: k.source, Method: k.method,
						FromObserved: f.observed, ToObserved: normTime(tf.Observed)})
				}
			}
			for v, ff := range f.values {
				if _, ok := t.values[v]; !ok {
					out.Changes = append(out.Changes, EstateChange{Kind: ChangeRemoved, Type: ItemFact, Subject: subject, Value: v, Source: k.source, Method: k.method,
						FromObserved: normTime(ff.Observed), ToObserved: t.observed})
				}
			}
		case f != nil:
			out.NotComparable = append(out.NotComparable, NotComparable{Source: k.source, Method: k.method, Side: "from only", Claims: len(f.values), Observed: f.observed, Subject: subject, Reason: reason})
		default:
			out.NotComparable = append(out.NotComparable, NotComparable{Source: k.source, Method: k.method, Side: "to only", Claims: len(t.values), Observed: t.observed, Subject: subject, Reason: reason})
		}
	}
}

var typeOrder = map[string]string{ItemEdge: "1", ItemAbsence: "2", ItemNode: "3", ItemFact: "4"}
var kindOrder = map[string]string{ChangeAdded: "1", ChangeRemoved: "2", ChangeChanged: "3"}

func changeKey(c EstateChange) string {
	return strings.Join([]string{typeOrder[c.Type], c.Source, c.Method, kindOrder[c.Kind], c.Subject, c.From, c.To, c.Relation, c.Value}, "\x00")
}

func diffGroup(k qkey, f, t *qgroup) []EstateChange {
	var out []EstateChange
	edgeSubject := func(e casefile.Edge) string { return e.From + " -[" + e.Relation + "]-> " + e.To }
	for id, te := range t.edges {
		fe, ok := f.edges[id]
		switch {
		case !ok:
			out = append(out, EstateChange{Kind: ChangeAdded, Type: ItemEdge, Subject: edgeSubject(te), From: te.From, To: te.To, Relation: te.Relation,
				Source: k.source, Method: k.method, FromObserved: f.observed, ToObserved: normTime(te.Observed)})
		case fe.Confidence != te.Confidence || fe.InferredFrom != te.InferredFrom:
			out = append(out, EstateChange{Kind: ChangeChanged, Type: ItemEdge, Subject: edgeSubject(te), From: te.From, To: te.To, Relation: te.Relation,
				Source: k.source, Method: k.method, FromObserved: normTime(fe.Observed), ToObserved: normTime(te.Observed),
				Detail: fmt.Sprintf("confidence %q -> %q", fe.Confidence, te.Confidence)})
		}
	}
	for id, fe := range f.edges {
		if _, ok := t.edges[id]; !ok {
			out = append(out, EstateChange{Kind: ChangeRemoved, Type: ItemEdge, Subject: edgeSubject(fe), From: fe.From, To: fe.To, Relation: fe.Relation,
				Source: k.source, Method: k.method, FromObserved: normTime(fe.Observed), ToObserved: t.observed})
		}
	}
	// An absence is an answer. "Was present, now absent" and the reverse are changes.
	for s, fa := range f.absences {
		if _, still := t.absences[s]; !still {
			out = append(out, EstateChange{Kind: ChangeChanged, Type: ItemAbsence, Subject: s, Source: k.source, Method: k.method,
				FromObserved: normTime(fa.Observed), ToObserved: t.observed, Detail: "was absent (not found), now present"})
		}
	}
	for s, ta := range t.absences {
		if _, was := f.absences[s]; !was {
			out = append(out, EstateChange{Kind: ChangeChanged, Type: ItemAbsence, Subject: s, Source: k.source, Method: k.method,
				FromObserved: f.observed, ToObserved: normTime(ta.Observed), Detail: "was present, now absent (not found)"})
		}
	}
	return out
}

// ---- findings ----

// DriftDetector is the detector name on every drift finding.
const DriftDetector = "estate_drift"

type driftClass struct {
	name      string
	sev       core.Severity
	what      string
	addedOnly bool
}

// driftClasses maps an edge relation to the finding it can raise. A relation not listed
// here appears in the diff and raises no finding.
var driftClasses = map[string]driftClass{
	"ns":            {name: "ns", sev: core.SevHigh, what: "NS records"},
	"mx":            {name: "mx", sev: core.SevHigh, what: "MX records"},
	"originated_by": {name: "origin", sev: core.SevHigh, what: "origin AS"},
	"resolves_to":   {name: "address", sev: core.SevActivity, what: "addresses"},
	"ct_candidate":  {name: "ct", sev: core.SevCheck, what: "certificate-transparency candidate names", addedOnly: true},
}

// DriftFindings turns the edge changes of a diff into findings. The tag is the detector,
// the class, the subject and a short digest of the changed edges, so the same drift
// carries the same tag on every run until it is accepted (promoted), and a further
// change of the same subject gets a new tag instead of being muted. The summary holds
// the subject and counts only; values are in the diff.
func DriftFindings(d EstateDiff) []core.Finding {
	type agg struct {
		cls            driftClass
		subject        string
		added, removed int
		ids            []string
		from, to       string
	}
	byTag := map[string]*agg{}
	for _, c := range d.Changes {
		if c.Type != ItemEdge || (c.Kind != ChangeAdded && c.Kind != ChangeRemoved) {
			continue
		}
		cls, ok := driftClasses[c.Relation]
		if !ok || (cls.addedOnly && c.Kind != ChangeAdded) {
			continue
		}
		k := cls.name + "\x00" + c.From
		a := byTag[k]
		if a == nil {
			a = &agg{cls: cls, subject: c.From}
			byTag[k] = a
		}
		if c.Kind == ChangeAdded {
			a.added++
		} else {
			a.removed++
		}
		a.ids = append(a.ids, c.Kind+"\x00"+c.From+"\x00"+c.To+"\x00"+c.Relation+"\x00"+c.Source+"\x00"+c.Method)
		a.from, a.to = max(a.from, c.FromObserved), max(a.to, c.ToObserved)
	}
	var out []core.Finding
	for _, a := range byTag {
		sort.Strings(a.ids)
		sum := sha256.Sum256([]byte(strings.Join(a.ids, "\n")))
		tag := fmt.Sprintf("%s:%s:%s:%s", DriftDetector, a.cls.name, a.subject, hex.EncodeToString(sum[:4]))
		var summary string
		if a.cls.name == "ct" {
			summary = fmt.Sprintf("estate drift: %d new candidate name(s) on certificates for %s (candidates, not live hosts)", a.added, a.subject)
		} else {
			summary = fmt.Sprintf("estate drift: %s of %s changed (+%d added, -%d removed)", a.cls.what, a.subject, a.added, a.removed)
		}
		detail := map[string]any{
			"class": a.cls.name, "subject": a.subject, "added": a.added, "removed": a.removed,
			"from": d.From.Ref, "to": d.To.Ref, "from_observed": a.from, "to_observed": a.to,
			"note": "an estate map shows infrastructure, not who typed the commands",
		}
		if a.cls.name == "address" || a.cls.name == "origin" {
			detail["note"] = "an address or origin AS belonging to a CDN, proxy or shared host says nothing about who runs the site; a change is not a change of ownership"
		}
		f := core.Finding{Detector: DriftDetector, Tag: tag, Severity: a.cls.sev, Summary: summary, Detail: detail}
		if ft, e1 := time.Parse(time.RFC3339, d.From.Observed); e1 == nil {
			if tt, e2 := time.Parse(time.RFC3339, d.To.Observed); e2 == nil && tt.After(ft) {
				f.Window = core.Window{From: ft, To: tt}
			}
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].Tag < out[j].Tag
	})
	return out
}

// ---- delivery with dedupe ----

// DriftDelivery counts what DeliverDrift did.
type DriftDelivery struct {
	New        int
	Suppressed int
	// OptionalFailed counts alerts the required sink took but an optional one (a
	// webhook) did not.
	OptionalFailed int
}

// DeliverDrift sends findings that are new to the alert sink, using the same rule as the
// watch loop: a tag alerted within ttl is held back unless its severity rose. Nothing is
// recorded as seen until it was delivered. It does not look at the network.
func DeliverDrift(ctx context.Context, state core.WatchStateStore, sink core.AlertSink, now time.Time, ttl time.Duration, run string, findings []core.Finding) (DriftDelivery, error) {
	var res DriftDelivery
	st, err := state.Load(ctx)
	if err != nil {
		return res, err
	}
	if st.Seen == nil {
		st.Seen = map[string]core.SeenTag{}
	}
	var errs []error
	at := now.UTC().Format(time.RFC3339)
	for _, f := range findings {
		if prev, ok := st.Seen[f.Tag]; ok && inTTL(prev.At, now, ttl) && f.Severity <= prev.Severity {
			res.Suppressed++
			continue
		}
		a := core.Alert{Kind: core.AlertFinding, Tag: f.Tag, Severity: core.SeverityName(f.Severity), Detector: f.Detector, Text: f.Summary, Run: run, At: at}
		if err := sink.Deliver(ctx, a); err != nil {
			errs = append(errs, fmt.Errorf("deliver alert %q: %w", a.Tag, err))
			var oe *core.OptionalDeliveryError
			if !errors.As(err, &oe) {
				continue // not delivered: offered again next run
			}
			res.OptionalFailed++
		}
		res.New++
		st.Seen[f.Tag] = core.SeenTag{At: now, Severity: f.Severity}
	}
	for tag, s := range st.Seen {
		if !inTTL(s.At, now, ttl) {
			delete(st.Seen, tag)
		}
	}
	if err := state.Save(ctx, st); err != nil {
		errs = append(errs, fmt.Errorf("drift state could not be saved (%v); the next run will repeat findings", err))
	}
	return res, errors.Join(errs...)
}
