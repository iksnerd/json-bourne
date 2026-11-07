package casefile

import (
	"strings"
	"testing"
	"time"
)

// invalidInputs are inputs no loader may crash on or hang over: malformed and truncated
// YAML and JSON, huge numbers, control bytes and deep or wide structures. Each loader
// must return an error or a valid value. The test has no recover: a panic fails it.
func invalidInputs() map[string]string {
	deepJSON := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	deepObj := strings.Repeat(`{"a":`, 5000) + "1" + strings.Repeat("}", 5000)
	return map[string]string{
		"empty":                "",
		"whitespace":           " \n\t\n",
		"null":                 "null",
		"scalar":               "42",
		"tab indent":           "a:\n\tb: 1\n",
		"unclosed flow":        "a: [1, 2",
		"unclosed quote":       "a: \"unterminated",
		"bad utf8":             "a: \xff\xfe\xfd\n",
		"nul bytes":            "a: b\x00c\n",
		"control bytes":        "\x01\x02\x03\x1b[31m",
		"duplicate keys":       "a: 1\na: 2\n",
		"merge key bomb":       "a: &a {x: 1}\nb: {<<: *a, <<: *a}\n",
		"huge int":             "a: 99999999999999999999999999999999999999999999\n",
		"huge float":           "a: 1e99999999\n",
		"huge exp json":        `{"a": 1e999999999999}`,
		"huge int json":        `{"a": ` + strings.Repeat("9", 5000) + `}`,
		"negative zero":        "a: -0\n",
		"nan":                  "a: .nan\n",
		"deep yaml":            "a: " + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + "\n",
		"deep yaml map":        strings.Repeat("a: {", 3000) + "1" + strings.Repeat("}", 3000) + "\n",
		"self alias":           "loop: &x [*x]\n",
		"alias cycle":          "a: &a [*b]\nb: &b [*a]\n",
		"undefined alias":      "a: *nope\n",
		"alias fan-out":        "a: &a [1,1,1,1,1,1,1,1,1,1]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]\n",
		"long scalar":          "a: " + strings.Repeat("x", 1<<16) + "\n",
		"many keys":            strings.Repeat("k: 1\n", 1) + manyKeys(1000),
		"truncated json":       `{"apiVersion":"jb.estate-facts/v1","method":"m","facts":[{"node":"ip:192.0.2.1"`,
		"json garbage":         `}{`,
		"json deep array":      deepJSON,
		"json deep object":     deepObj,
		"json two values":      `{"a":1}{"a":2}`,
		"json lines garbage":   "{}\n{\"node\":}\n\xff\n",
		"json huge string key": `{"` + strings.Repeat("k", 1<<16) + `":1}`,
		"yaml document marker": "---\n---\n---\n",
		"yaml directive":       "%YAML 9.9\n---\na: 1\n",
		"yaml tag":             "a: !!python/object:os.system x\n",
		"yaml binary":          "a: !!binary |\n  ////////\n",
		"yaml anchor only":     "&a\n",
		"yaml key is map":      "? {a: 1}\n: 2\n",
		"yaml complex key":     "? [a, b]\n: c\n",
	}
}

func manyKeys(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("k")
		b.WriteString(strings.Repeat("0", i%7))
		b.WriteString(": 1\n")
	}
	return b.String()
}

// withHeaders prefixes the input with each format's apiVersion, so the input reaches the
// walk behind the version check as well as failing at it.
func withHeaders(in string) []string {
	return []string{
		in,
		"apiVersion: jb.case/v1\n" + in,
		"apiVersion: jb.actor/v1\n" + in,
		"apiVersion: jb.estate/v2\n" + in,
		"apiVersion: jb.estate-snapshot/v2\ncomplete: true\n" + in,
	}
}

// returnsWithin runs f and fails the test if it takes longer than the bound. A hang is a bug
// in the loader, not in the test: the goroutine is left to finish after the failure.
func returnsWithin(t *testing.T, name string, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return returnsWithin %v", name, d)
	}
}

// Invariant: invalid input returns an error and never crashes. Every parser the package
// exposes takes every input; one that accepts it must hand back a value that re-validates.
func TestInvariantInvalidInputIsRefusedNotCrashed(t *testing.T) {
	for name, in := range invalidInputs() {
		for _, doc := range withHeaders(in) {
			data := []byte(doc)
			returnsWithin(t, name, 20*time.Second, func() {
				if c, err := Parse(data); err == nil && c == nil {
					t.Errorf("%s: Parse returned neither value nor error", name)
				}
				if a, err := ParseActor(data); err == nil && a == nil {
					t.Errorf("%s: ParseActor returned neither value nor error", name)
				}
				if e, err := ParseEstate(data); err == nil {
					if e == nil {
						t.Errorf("%s: ParseEstate returned neither value nor error", name)
					} else if out, merr := MarshalEstate(e); merr != nil {
						t.Errorf("%s: accepted estate does not marshal: %v", name, merr)
					} else if _, perr := ParseEstate(out); perr != nil {
						t.Errorf("%s: accepted estate does not re-parse: %v", name, perr)
					}
				}
				if s, err := ParseEstateSnapshot(data); err == nil && s == nil {
					t.Errorf("%s: ParseEstateSnapshot returned neither value nor error", name)
				}
				if f, err := ParseFactsImport(data); err == nil {
					if f == nil {
						t.Errorf("%s: ParseFactsImport returned neither value nor error", name)
					} else if f.validate() != nil {
						t.Errorf("%s: accepted import does not re-validate", name)
					}
				}
			})
		}
	}
}
