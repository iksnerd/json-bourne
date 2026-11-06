package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/adapters/kibana"
)

func withKibanaLines(lines string) string {
	return strings.Replace(valid, "    index: logs-auth-*\n", "    index: logs-auth-*\n"+lines, 1)
}

func TestKibanaFilterAcceptedAndSentAsAnANDedQuery(t *testing.T) {
	f, err := Parse([]byte(withKibanaLines(`    filter:
      - match_phrase: {field: message, value: "Chrome/126.0.0.0"}
      - term: {field: status, value: "200"}
`)))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	src := rt.Sources[0].(*kibana.Source)
	got, _ := json.Marshal(src.Query)
	want := `{"bool":{"filter":[{"match_phrase":{"message":"Chrome/126.0.0.0"}},{"term":{"status":"200"}}]}}`
	if string(got) != want {
		t.Fatalf("query = %s\nwant    %s", got, want)
	}
}

func TestKibanaWithoutFilterHasNoQuery(t *testing.T) {
	f, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	if q := rt.Sources[0].(*kibana.Source).Query; q != nil {
		t.Fatalf("Query = %v, want nil so an unfiltered source keeps the old behaviour", q)
	}
}

func TestKibanaFilterRejectedAtLoad(t *testing.T) {
	many := "    filter:\n" + strings.Repeat("      - term: {field: a, value: b}\n", 9)
	for name, bad := range map[string]string{
		"both kinds in one clause": "    filter:\n      - match_phrase: {field: message, value: x}\n        term: {field: status, value: \"1\"}\n",
		"neither kind":             "    filter:\n      - {}\n",
		"empty list":               "    filter: []\n",
		"empty value":              "    filter:\n      - term: {field: status, value: \"\"}\n",
		"empty field":              "    filter:\n      - term: {field: \"\", value: x}\n",
		"field with a space":       "    filter:\n      - term: {field: \"a b\", value: x}\n",
		"field that is a path":     "    filter:\n      - term: {field: \"a/b\", value: x}\n",
		"unknown clause kind":      "    filter:\n      - regexp: {field: message, value: x}\n",
		"unknown key in clause":    "    filter:\n      - term: {field: a, value: b, boost: 9}\n",
		"too many clauses":         many,
		"value too long":           "    filter:\n      - term: {field: a, value: \"" + strings.Repeat("x", 513) + "\"}\n",
		"not a list":               "    filter: {term: {field: a, value: b}}\n",
	} {
		if _, err := Parse([]byte(withKibanaLines(bad))); err == nil {
			t.Errorf("%s: accepted at load", name)
		}
	}
}

const quietDetector = `
detectors:
  - type: fingerprint
    actors: [a.yaml]
    empty_is_quiet: true
`

// "No matching event" may only read as quiet when every source has shown, by a filter and
// its liveness probe, that it is alive. On an unfiltered source an empty result means a
// broken source, and the option must not be able to hide that.
func TestEmptyIsQuietNeedsEveryKibanaSourceFiltered(t *testing.T) {
	head := "sources:\n  - type: kibana\n    url: https://kibana.example.com\n    api_key_env: JB_KIBANA_API_KEY\n    index: logs-*\n"
	filter := "    filter:\n      - match_phrase: {field: message, value: x}\n"

	if _, err := Parse([]byte(head + filter + quietDetector)); err != nil {
		t.Fatalf("filtered source + empty_is_quiet rejected: %v", err)
	}
	_, err := Parse([]byte(head + quietDetector))
	if err == nil || !strings.Contains(err.Error(), "empty_is_quiet") || !strings.Contains(err.Error(), "filter") {
		t.Fatalf("unfiltered source + empty_is_quiet should be refused, naming both: %v", err)
	}
	two := head + filter + head[len("sources:\n"):] // second source, unfiltered
	if _, err := Parse([]byte(two + quietDetector)); err == nil {
		t.Fatal("one unfiltered source among two was accepted")
	}
	// Without the option nothing changes.
	if _, err := Parse([]byte(head + "detectors:\n  - type: fingerprint\n    actors: [a.yaml]\n")); err != nil {
		t.Fatalf("plain fingerprint on an unfiltered source rejected: %v", err)
	}
}
