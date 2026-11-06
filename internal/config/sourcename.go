package config

import "strings"

// ValidSourceName reports whether s is acceptable as the name of a source: the rule a
// config's `name:` is held to. `jb db rename-source` applies it to the new label.
func ValidSourceName(s string) bool { return sourceName.MatchString(s) }

// ValidStoredLabel reports whether s can be a label already in the store. That is any
// valid source name, plus the default label a kibana source reports when it has no
// name (kibana:<index>), whose index may hold a wildcard or capitals that a name may
// not. No space and no control character is accepted, and the length is bounded.
func ValidStoredLabel(s string) bool {
	if sourceName.MatchString(s) {
		return true
	}
	if !strings.HasPrefix(s, "kibana:") || len(s) == len("kibana:") || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f || r > 0x7e {
			return false
		}
	}
	return true
}
