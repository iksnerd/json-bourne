package casefile

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// MaxMappingKeys is the most keys one YAML mapping may hold in any operator-supplied
// file (case, actor, estate, snapshot, config). yaml.v3 decodes a mapping in time
// quadratic in its key count (about 0.6 s for 16,000 keys, tens of seconds at the 1 MiB
// file cap), so a hostile or generated file could stall `jb case check`, `jb serve` and
// `jb watch` start-up. The largest legitimate mappings are the per-case `windows`,
// `return_codes` and the behaviour detector's `fields`, which hold a handful to a few
// hundred keys; lists (estate nodes, edges, facts) are sequences and do not count.
const MaxMappingKeys = 1000

// CheckYAMLShape refuses a document with a mapping of more than MaxMappingKeys keys. It
// parses into yaml.Node, which is linear, and walks the tree once without following
// aliases, so it is cheap and runs before any quadratic decode. kind names the file in
// the error ("case file", "config", ...). A document that does not parse is left to the
// real decoder to report, so its error text is unchanged.
func CheckYAMLShape(kind string, data []byte) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil
	}
	return checkShape(kind, &root)
}

func checkShape(kind string, n *yaml.Node) error {
	if n.Kind == yaml.MappingNode && len(n.Content)/2 > MaxMappingKeys {
		return fmt.Errorf("%s: a mapping at line %d has %d keys; the limit is %d keys per mapping (the YAML decoder is quadratic in the key count)", kind, n.Line, len(n.Content)/2, MaxMappingKeys)
	}
	for _, c := range n.Content {
		if err := checkShape(kind, c); err != nil {
			return err
		}
	}
	return nil
}
