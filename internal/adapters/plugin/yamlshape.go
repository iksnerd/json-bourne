package plugin

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// maxMappingKeys is the most keys one YAML mapping may hold in the allowlist. yaml.v3
// decodes a mapping in time quadratic in its key count (tens of seconds at the 1 MiB file
// cap). It is a local copy of casefile.MaxMappingKeys because archtest forbids this
// package from importing internal/casefile; TestMaxMappingKeysMatchesCasefile keeps the
// two equal.
const maxMappingKeys = 1000

// checkYAMLShape refuses a document with a mapping of more than maxMappingKeys keys. It
// parses into yaml.Node (linear) and walks the tree once, so it runs before the
// quadratic decode. A document that does not parse is left to the real decoder to report.
func checkYAMLShape(data []byte) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil
	}
	return checkShape(&root)
}

func checkShape(n *yaml.Node) error {
	if n.Kind == yaml.MappingNode && len(n.Content)/2 > maxMappingKeys {
		return fmt.Errorf("a mapping at line %d has %d keys; the limit is %d keys per mapping (the YAML decoder is quadratic in the key count)", n.Line, len(n.Content)/2, maxMappingKeys)
	}
	for _, c := range n.Content {
		if err := checkShape(c); err != nil {
			return err
		}
	}
	return nil
}
