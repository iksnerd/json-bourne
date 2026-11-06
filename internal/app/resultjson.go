package app

import (
	"encoding/json"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// The JSON documents of `jb hunt --output json` and `jb activity --output json`. They are
// the encoding of the result itself, so the command line, the Go API and the MCP tools
// print one document. A key is a contract with scripts: do not rename or drop one.

// jsonComponent is one source or detector row of a hunt, and one source row of an activity check.
type jsonComponent struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Events *int64 `json:"events,omitempty"`
	// Outcome, IndexAlive and IndexDocuments are set on a source of a hunt. IndexDocuments
	// is the count of the unfiltered liveness probe, present only with IndexAlive.
	Outcome        string `json:"outcome,omitempty"`
	IndexAlive     *bool  `json:"index_alive,omitempty"`
	IndexDocuments *int64 `json:"index_documents,omitempty"`
	// Unparsable and UnparsableShare are set only when a source reported unparsable documents.
	// Duplicates is set when documents were dropped because another source of the run
	// returned them first; they are not in Events.
	Duplicates      *int64   `json:"duplicates,omitempty"`
	Unparsable      *int     `json:"unparsable,omitempty"`
	UnparsableShare *float64 `json:"unparsable_share,omitempty"`
	HighUnparsable  bool     `json:"high_unparsable,omitempty"`
	Findings        *int     `json:"findings,omitempty"`
	Error           string   `json:"error,omitempty"`
}

type jsonFinding struct {
	Detector string         `json:"detector"`
	Tag      string         `json:"tag"`
	Severity string         `json:"severity"`
	Summary  string         `json:"summary"`
	Window   [2]time.Time   `json:"window"`
	Baseline [2]time.Time   `json:"baseline"`
	Detail   map[string]any `json:"detail,omitempty"`
}

// jsonSearch is present only for a run with a search.
type jsonSearch struct {
	Terms  []string `json:"terms"`
	Absent bool     `json:"absent"` // matched nothing, and every index was shown alive
}

// jsonDisabled names one source or detector the config switched off.
type jsonDisabled struct {
	Kind string `json:"kind"` // source or detector
	Name string `json:"name"`
}

func jsonDisabledOf(ds []Disabled) []jsonDisabled {
	var out []jsonDisabled
	for _, d := range ds {
		out = append(out, jsonDisabled{Kind: d.Kind, Name: d.Name})
	}
	return out
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// utcPtr is nil for the zero time, else the time in UTC.
func utcPtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// sourceComponent is the row of a source; hunt adds the outcome and the liveness probe.
func sourceComponent(s SourceResult, hunt bool) jsonComponent {
	n := s.Events
	c := jsonComponent{Name: s.Name, Status: string(s.Status), Events: &n, Error: errText(s.Err)}
	if hunt {
		c.Outcome = s.Outcome()
		if s.IndexAlive {
			alive, docs := true, s.IndexDocs
			c.IndexAlive, c.IndexDocuments = &alive, &docs
		}
	}
	if s.Duplicates > 0 {
		dup := s.Duplicates
		c.Duplicates = &dup
	}
	if s.Unparsable > 0 {
		u, share := s.Unparsable, s.UnparsableShare()
		c.Unparsable, c.UnparsableShare, c.HighUnparsable = &u, &share, s.HighUnparsable()
	}
	return c
}

// MarshalJSON prints what `jb hunt --output json` prints. A search that matched nothing
// in every live index is an answer, so complete is true for it (see SearchAbsent).
func (r Result) MarshalJSON() ([]byte, error) {
	absent := r.SearchAbsent()
	out := struct {
		Search    *jsonSearch     `json:"search,omitempty"`
		Run       string          `json:"run"`
		Until     *time.Time      `json:"until,omitempty"` // set only for a historical window
		Window    [2]time.Time    `json:"window"`
		Baseline  [2]time.Time    `json:"baseline"`
		Complete  bool            `json:"complete"`
		Stored    bool            `json:"stored"` // false: the run went to a temporary store
		Sources   []jsonComponent `json:"sources"`
		Detectors []jsonComponent `json:"detectors"`
		Findings  []jsonFinding   `json:"findings"`
		// Disabled lists what the config switched off (neither read nor run); present only
		// when something is, so the output of a config without enabled: false is unchanged.
		Disabled []jsonDisabled `json:"disabled,omitempty"`
	}{
		Run: r.Run, Window: [2]time.Time{r.Window.From, r.Window.To},
		Baseline: [2]time.Time{r.Baseline.From, r.Baseline.To}, Complete: r.Complete() || absent, Stored: r.Stored,
		Sources: []jsonComponent{}, Detectors: []jsonComponent{}, Findings: []jsonFinding{},
		Until: utcPtr(r.Until), Disabled: jsonDisabledOf(r.Disabled),
	}
	if len(r.Search) > 0 {
		out.Search = &jsonSearch{Terms: r.Search, Absent: absent}
	}
	for _, s := range r.Sources {
		out.Sources = append(out.Sources, sourceComponent(s, true))
	}
	for _, d := range r.Detectors {
		n := d.Findings
		out.Detectors = append(out.Detectors, jsonComponent{Name: d.Name, Status: string(d.Status), Findings: &n, Error: errText(d.Err)})
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, jsonFinding{
			Detector: f.Detector, Tag: f.Tag, Severity: core.SeverityName(f.Severity), Summary: f.Summary,
			Window:   [2]time.Time{f.Window.From, f.Window.To},
			Baseline: [2]time.Time{f.Baseline.From, f.Baseline.To}, Detail: f.Detail,
		})
	}
	return json.Marshal(out)
}

type jsonSubject struct {
	Subject     string     `json:"subject"`
	Kind        string     `json:"kind"`
	Active      bool       `json:"active"`
	Window      int        `json:"window_events"`
	Preceding   int        `json:"preceding_events"`
	Last        *time.Time `json:"last_genuine,omitempty"`
	LastEarlier *time.Time `json:"last_genuine_preceding,omitempty"`
	Noise       int        `json:"noise,omitempty"`
	Ignored     int        `json:"ignored,omitempty"`
	Note        string     `json:"note,omitempty"`
}

type jsonActivityDetector struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	// Findings is set when a detector that did not finish returned findings first.
	Findings   int           `json:"findings_before_stop,omitempty"`
	Seen       int           `json:"events_read"`
	Unparsable int           `json:"unparsable"`
	Subjects   []jsonSubject `json:"subjects"`
	Notes      []string      `json:"notes,omitempty"`
}

// MarshalJSON prints what `jb activity --output json` prints.
func (r ActivityResult) MarshalJSON() ([]byte, error) {
	out := struct {
		Run       string                 `json:"run"`
		Until     *time.Time             `json:"until,omitempty"` // set only for a historical window
		Verdict   string                 `json:"verdict"`
		Complete  bool                   `json:"complete"`
		Stored    bool                   `json:"stored"` // false: the run went to a temporary store
		Reasons   []string               `json:"reasons"`
		Window    [2]time.Time           `json:"window"`
		Baseline  [2]time.Time           `json:"baseline"`
		Sources   []jsonComponent        `json:"sources"`
		Detectors []jsonActivityDetector `json:"detectors"`
		// Current and Previous count actor and rare-action events; CommonCurrent and
		// CommonPrevious count routine common-action traffic, which is not activity by volume.
		Current        int            `json:"genuine_events_window"`
		Previous       int            `json:"genuine_events_preceding"`
		CommonCurrent  int            `json:"common_action_events_window"`
		CommonPrevious int            `json:"common_action_events_preceding"`
		Flagged        []string       `json:"common_actions_flagged"`
		Disabled       []jsonDisabled `json:"disabled,omitempty"`
	}{
		Run: r.Run, Verdict: string(r.Verdict), Complete: r.Complete(), Stored: r.Stored, Reasons: append([]string{}, r.Reasons...),
		Until:    utcPtr(r.Until),
		Window:   [2]time.Time{r.Window.From, r.Window.To},
		Baseline: [2]time.Time{r.Baseline.From, r.Baseline.To},
		Sources:  []jsonComponent{}, Detectors: []jsonActivityDetector{},
		Current: r.Current, Previous: r.Previous,
		CommonCurrent: r.CommonCurrent, CommonPrevious: r.CommonPrevious,
		Flagged:  append([]string{}, r.Flagged...),
		Disabled: jsonDisabledOf(r.Disabled),
	}
	for _, s := range r.Sources {
		out.Sources = append(out.Sources, sourceComponent(s, false))
	}
	for _, d := range r.Detectors {
		jd := jsonActivityDetector{Name: d.Name, Status: string(d.Status), Error: errText(d.Err), Findings: d.Findings,
			Seen: d.Report.Seen, Unparsable: d.Report.Unparsable, Subjects: []jsonSubject{}, Notes: d.Report.Notes}
		for _, s := range d.Report.Subjects {
			jd.Subjects = append(jd.Subjects, jsonSubject{
				Subject: s.Subject, Kind: s.Kind, Active: s.Active, Window: s.Current, Preceding: s.Previous,
				Last: utcPtr(s.Last), LastEarlier: utcPtr(s.LastEarlier), Noise: s.Noise, Ignored: s.Ignored, Note: s.Note,
			})
		}
		out.Detectors = append(out.Detectors, jd)
	}
	return json.Marshal(out)
}
