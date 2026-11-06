package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/iksnerd/json-bourne/internal/core"
)

// overlapLimit bounds how many label pairs one warning looks for and names.
const overlapLimit = 5

// SourceOverlaps asks the store whether the same documents sit under two source labels
// inside w. The answer is advice only: callers print it and never let it change a
// verdict or an exit code, so an error here is returned for them to note, not to act on.
func SourceOverlaps(ctx context.Context, r core.SourceOverlapReader, w core.Window) ([]core.SourceOverlap, error) {
	if r == nil {
		return nil, nil
	}
	return r.SourceOverlaps(ctx, w, overlapLimit)
}

// SourceOverlapWarning words the overlaps as one WARNING with the exact command that
// fixes it. scope is the command-line part that names the config (`--case DIR`,
// `--config FILE`), already quoted for a shell. It returns "" when there is nothing to
// say.
//
// The suggested direction relabels the default label (kibana:<index>), which a config
// that names its source no longer produces, into the other one. When neither or both
// look like defaults the first label is renamed into the second, and the warning says
// to swap them if that is backwards. The command is a dry run until --apply is added.
func SourceOverlapWarning(ov []core.SourceOverlap, scope string) string {
	if len(ov) == 0 {
		return ""
	}
	if scope == "" {
		scope = "--config FILE"
	}
	var b strings.Builder
	for _, o := range ov {
		oldL, newL := o.A, o.B
		ambiguous := false
		switch aDef, bDef := strings.HasPrefix(o.A, "kibana:"), strings.HasPrefix(o.B, "kibana:"); {
		case bDef && !aDef:
			oldL, newL = o.B, o.A
		case aDef && !bDef:
		default:
			ambiguous = true
		}
		fmt.Fprintf(&b, "WARNING: the store holds the same %d document(s) under two source labels, %s and %s, in the window being read, so a detector that reads both counts them twice. "+
			"Fix: jb db rename-source %s %s %s --merge   (a dry run; add --apply to change the store)",
			o.Docs, quote(oldL), quote(newL), scope, shellQuote(oldL), shellQuote(newL))
		if ambiguous {
			fmt.Fprintf(&b, "; swap the two labels if %s is the one your config still uses", quote(oldL))
		}
		b.WriteString("\n")
	}
	if len(ov) >= overlapLimit {
		b.WriteString("WARNING: the search stops at " + fmt.Sprint(overlapLimit) + " label pairs; there may be more.\n")
	}
	return b.String()
}

func quote(s string) string { return fmt.Sprintf("%q", s) }

// shellQuote single-quotes s unless it is made only of characters a shell leaves alone.
// A default label such as kibana:logs-* holds a glob character.
func shellQuote(s string) string {
	safe := s != ""
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.:-/=+@%", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ShellQuote is shellQuote for callers that build the scope argument.
func ShellQuote(s string) string { return shellQuote(s) }

// OverlapAdvice is the advice of a run about one set of documents stored under two source
// labels: the WARNING with its fix, or a note that the check did not run, or "" when there
// is nothing to say. Advice only: it never fails the caller, who prints it and keeps the
// verdict. It ends with a newline when it is not empty.
func OverlapAdvice(ctx context.Context, r core.SourceOverlapReader, win core.Window, scope string) string {
	ov, err := SourceOverlaps(ctx, r, win)
	if err != nil {
		if ctx.Err() == nil {
			return fmt.Sprintf("note: the check for one set of documents stored under two source labels did not run: %v\n", err)
		}
		return ""
	}
	return SourceOverlapWarning(ov, scope)
}

// RenameScope is the part of a `jb db rename-source` command line that names the config,
// as the caller was given it, quoted for a shell.
func RenameScope(caseDir, cfgPath string) string {
	var parts []string
	if caseDir != "" {
		parts = append(parts, "--case "+ShellQuote(caseDir))
	}
	if cfgPath != "" {
		parts = append(parts, "--config "+ShellQuote(cfgPath))
	}
	return strings.Join(parts, " ")
}
