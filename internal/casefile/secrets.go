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

// scanCredentials walks every scalar value in the document.
func scanCredentials(n *yaml.Node) error { return scan(n, "") }

func scan(n *yaml.Node, path string) error {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			if err := scan(c, path); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			p := n.Content[i].Value
			if path != "" {
				p = path + "." + p
			}
			if err := scan(n.Content[i+1], p); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			if err := scan(c, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if looksLikeCredential(n.Value) {
			return fmt.Errorf("%s (line %d) holds a credential-shaped value; a case file names an environment variable and never holds the value", path, n.Line)
		}
	case yaml.AliasNode:
		return scan(n.Alias, path)
	}
	return nil
}
