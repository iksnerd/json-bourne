// Package severityfloor is the one place that parses, validates and applies a
// detector's min_severity and note. A floor can only raise a finding: the
// severity becomes the greater of the computed one and the floor. behaviour and
// newkey share it so their rules cannot drift (RFC 0011).
//
// The package imports the standard library and internal/core only.
package severityfloor

import (
	"errors"
	"fmt"
	"strings"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Floor is a parsed min_severity and note. The zero value is no floor.
type Floor struct {
	Sev  core.Severity // 0 (SevInfo) means no floor
	Note string
}

// Parse validates min_severity and note. allowed lists the severities a floor
// may take, lowest first; it is named in the error. noteNeedsFloor makes a note
// without min_severity an error. Errors carry no prefix: the caller adds its own.
func Parse(minSeverity, note string, allowed []core.Severity, noteNeedsFloor bool) (Floor, error) {
	f := Floor{Note: strings.TrimSpace(note)}
	minSeverity = strings.TrimSpace(minSeverity)
	if minSeverity == "" {
		if noteNeedsFloor && f.Note != "" {
			return Floor{}, errors.New("note needs min_severity: a note is carried only with a floor")
		}
		return f, nil
	}
	sev, ok := core.ParseSeverity(minSeverity)
	if ok {
		ok = false
		for _, a := range allowed {
			if a == sev {
				ok = true
			}
		}
	}
	if !ok {
		names := make([]string, len(allowed))
		for i, a := range allowed {
			names[i] = core.SeverityName(a)
		}
		return Floor{}, fmt.Errorf("min_severity %q must be one of %s: a floor below them can never raise a finding", minSeverity, strings.Join(names, ", "))
	}
	if sev == core.SevCritical && f.Note == "" {
		return Floor{}, errors.New("min_severity critical needs a note: say why this is critical")
	}
	f.Sev = sev
	return f, nil
}

// Apply returns the greater of sev and the floor. It sets detail["min_severity"]
// only when the floor raised the result, and detail["note"] whenever a note is set.
func (f Floor) Apply(sev core.Severity, detail map[string]any) core.Severity {
	if f.Sev > sev {
		sev = f.Sev
		detail["min_severity"] = core.SeverityName(f.Sev)
	}
	if f.Note != "" {
		detail["note"] = f.Note
	}
	return sev
}
