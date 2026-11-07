package casefile

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// A case file holds environment-variable names, never values. These patterns are a
// backstop for a pasted value, not a scanner: they favour refusing a doubtful string
// (the author can reword it) over letting a key through. The error names the field
// and never the value.
var (
	knownTokenRE = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY|\bAKIA[0-9A-Z]{16}\b|\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bsk-[A-Za-z0-9_-]{20,}|\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.|(?i:\bbearer\s+[A-Za-z0-9._~+/=-]{16,})|://[^/\s:@]+:[^/\s@]+@`)
	hexRE        = regexp.MustCompile(`\b[0-9a-fA-F]{40,}\b`)
	runRE        = regexp.MustCompile(`[A-Za-z0-9+/=]{32,}`)
)

func looksLikeCredential(s string) bool {
	if knownTokenRE.MatchString(s) || hexRE.MatchString(s) {
		return true
	}
	for _, run := range runRE.FindAllString(s, -1) {
		if strings.ContainsAny(run, "abcdefghijklmnopqrstuvwxyz") &&
			strings.ContainsAny(run, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") &&
			strings.ContainsAny(run, "0123456789") && entropy(run) >= 3.5 {
			return true
		}
	}
	return false
}

func entropy(s string) float64 {
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	n, h := float64(len(s)), 0.0
	for _, c := range counts {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// Limits on the credential walk. A case-family file is a few hundred nodes and a few
// levels deep; these are far above any real file and far below what hurts. They stop a
// self-referencing alias (a stack overflow Go cannot recover from), absurd nesting, and
// an alias expansion bomb (nested aliases that multiply) before the strict decode runs.
const (
	maxScanDepth = 64
	maxScanNodes = 100000
)

// scanner is one credential walk. Its node budget is shared by every call made on it, so
// a file walked in pieces (an actor file) has one budget, not one per piece.
type scanner struct {
	nodes    int
	visiting map[*yaml.Node]bool // alias targets on the current path
}

func newScanner() *scanner { return &scanner{visiting: map[*yaml.Node]bool{}} }

// scanCredentials walks every scalar value in the document.
func scanCredentials(n *yaml.Node) error { return newScanner().walk(n, "", 0) }

func (s *scanner) walk(n *yaml.Node, path string, depth int) error {
	if depth > maxScanDepth {
		return fmt.Errorf("document nests deeper than %d levels; refused", maxScanDepth)
	}
	if s.nodes++; s.nodes > maxScanNodes {
		return fmt.Errorf("document expands to more than %d nodes (nested aliases?); refused", maxScanNodes)
	}
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			if err := s.walk(c, path, depth+1); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			p := n.Content[i].Value
			if path != "" {
				p = path + "." + p
			}
			if err := s.walk(n.Content[i+1], p, depth+1); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			if err := s.walk(c, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if looksLikeCredential(n.Value) {
			return fmt.Errorf("%s (line %d) holds a credential-shaped value; a case file names an environment variable and never holds the value", path, n.Line)
		}
	case yaml.AliasNode:
		if n.Alias == nil {
			return nil
		}
		if s.visiting[n.Alias] {
			return fmt.Errorf("%s (line %d) is an alias that contains itself; refused", path, n.Line)
		}
		s.visiting[n.Alias] = true
		err := s.walk(n.Alias, path, depth+1)
		delete(s.visiting, n.Alias)
		return err
	}
	return nil
}
