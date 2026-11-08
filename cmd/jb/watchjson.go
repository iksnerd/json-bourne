package main

import (
	"io"
	"time"

	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/core"
)

// jsonCycle is the JSON form of one watch cycle (`jb watch --once --output json`). The
// field names are part of the output contract; docs/config/watch.md lists them.
type jsonCycle struct {
	Run            string       `json:"run"`
	Watcher        string       `json:"watcher,omitempty"` // --name; absent for the unnamed watcher
	Window         [2]time.Time `json:"window"`            // [from, to)
	Status         string       `json:"status"`            // quiet, findings, incomplete or failed
	Healthy        bool         `json:"healthy"`           // true only for quiet and findings
	Failed         []string     `json:"failed"`            // sources and detectors that did not finish
	New            int          `json:"new"`               // finding alerts delivered
	Suppressed     int          `json:"suppressed"`        // findings held back by --ttl
	Repeated       int          `json:"repeated"`          // outage alerts held back by --repeat
	Recovered      int          `json:"recovered"`         // recovery alerts delivered
	OptionalFailed int          `json:"optional_failed"`   // alerts the log took and a webhook did not
	Gap            string       `json:"gap,omitempty"`     // set when time went unexamined before this cycle
	Error          string       `json:"error,omitempty"`   // the first thing that broke the cycle
	Alerts         []core.Alert `json:"alerts"`            // everything delivered this cycle, health alerts first
	Pruned         *jsonPruned  `json:"pruned"`            // null when retention did not run or failed
}

type jsonPruned struct {
	Runs     int64 `json:"runs"`
	Events   int64 `json:"events"`
	Findings int64 `json:"findings"`
}

func cycleJSONOf(name string, r app.CycleReport) jsonCycle {
	out := jsonCycle{
		Run: r.Run, Watcher: name, Window: [2]time.Time{r.Window.From, r.Window.To},
		Status: string(r.Status), Healthy: r.Status.Healthy(),
		Failed: append([]string{}, r.Failed...), New: r.New, Suppressed: r.Suppressed,
		Repeated: r.Repeated, Recovered: r.Recovered, OptionalFailed: r.OptionalFailed,
		Gap: r.Gap, Error: errText(r.Err), Alerts: append([]core.Alert{}, r.Surfaced...),
	}
	if r.Pruned != nil {
		out.Pruned = &jsonPruned{Runs: r.Pruned.Runs, Events: r.Pruned.Events, Findings: r.Pruned.Findings}
	}
	return out
}

func writeCycleJSON(w io.Writer, name string, r app.CycleReport) error {
	return writeIndentedJSON(w, cycleJSONOf(name, r))
}
