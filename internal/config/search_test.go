package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/adapters/kibana"
)

func buildSearched(t *testing.T, yaml string, terms []string, field string) (*kibana.Source, error) {
	t.Helper()
	f, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.WithSearch(terms, field); err != nil {
		return nil, err
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	return rt.Sources[0].(*kibana.Source), nil
}

func queryJSON(t *testing.T, s *kibana.Source) string {
	t.Helper()
	b, err := json.Marshal(s.Query)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSearchIsANDedOntoTheConfiguredFilter(t *testing.T) {
	yaml := withKibanaLines("    filter:\n      - term: {field: status, value: \"200\"}\n")
	src, err := buildSearched(t, yaml, []string{"203.0.113.9", "Example/1.0"}, "")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"bool":{"filter":[{"match_phrase":{"message":"203.0.113.9"}},{"match_phrase":{"message":"Example/1.0"}},{"term":{"status":"200"}}]}}`
	if got := queryJSON(t, src); got != want {
		t.Fatalf("query = %s\nwant    %s", got, want)
	}
}

func TestSearchWithoutAConfiguredFilterStillFilters(t *testing.T) {
	src, err := buildSearched(t, valid, []string{"needle"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if src.Query == nil {
		t.Fatal("Query is nil: the term was not sent to the server and the source would download the window")
	}
}

func TestSearchFieldComesFromTheOverrideThenTheSourceThenMessage(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml, flag, want string
	}{
		"default":        {valid, "", `"message":"x"`},
		"source setting": {withKibanaLines("    search_field: request.line\n"), "", `"request.line":"x"`},
		"run override":   {withKibanaLines("    search_field: request.line\n"), "log.original", `"log.original":"x"`},
		"override alone": {valid, "log.original", `"log.original":"x"`},
	} {
		t.Run(name, func(t *testing.T) {
			src, err := buildSearched(t, tc.yaml, []string{"x"}, tc.flag)
			if err != nil {
				t.Fatal(err)
			}
			if got := queryJSON(t, src); !strings.Contains(got, tc.want) {
				t.Fatalf("query = %s, want it to contain %s", got, tc.want)
			}
		})
	}
}

// A term is data in a JSON string. However it is built, it must come out as exactly one
// extra clause carrying the term verbatim, never as structure.
func TestSearchTermIsNeverQueryStructure(t *testing.T) {
	for _, term := range []string{
		`x"}}, {"match_all": {}}, {"match_phrase": {"message": "y`,
		`* OR _exists_:password`,
		`{{template}} ${jndi:ldap://example.com/a}`,
		`'; DROP TABLE events; --`,
		`a\u0000b`,
	} {
		src, err := buildSearched(t, valid, []string{term}, "")
		if err != nil {
			t.Fatalf("%q: %v", term, err)
		}
		var q struct {
			Bool struct {
				Filter []map[string]map[string]string `json:"filter"`
			} `json:"bool"`
		}
		if err := json.Unmarshal([]byte(queryJSON(t, src)), &q); err != nil {
			t.Fatalf("%q: %v", term, err)
		}
		if len(q.Bool.Filter) != 1 || q.Bool.Filter[0]["match_phrase"]["message"] != term {
			t.Fatalf("%q came out as %+v: the term leaked into the structure", term, q.Bool.Filter)
		}
	}
}

func TestValidateSearchRefusals(t *testing.T) {
	long := strings.Repeat("a", MaxSearchBytes+1)
	for name, tc := range map[string]struct {
		terms []string
		want  string
	}{
		"no terms":           {nil, "no term"},
		"empty":              {[]string{""}, "empty"},
		"blank":              {[]string{"   "}, "blank"},
		"newline":            {[]string{"a\nb"}, "control"},
		"nul":                {[]string{"a\x00b"}, "control"},
		"tab":                {[]string{"a\tb"}, "control"},
		"ansi escape":        {[]string{"\x1b[31mred"}, "control"},
		"del":                {[]string{"a\x7fb"}, "control"},
		"bidi override":      {[]string{"a‮b"}, "control or format"},
		"zero width space":   {[]string{"a​b"}, "control or format"},
		"invalid utf-8":      {[]string{"a\xffb"}, "UTF-8"},
		"too long":           {[]string{long}, "at most"},
		"leading space":      {[]string{" a"}, "starts with whitespace"},
		"trailing space":     {[]string{"a "}, "ends with whitespace"},
		"too many terms":     {[]string{"a", "b", "c", "d", "e"}, "at most"},
		"second term is bad": {[]string{"ok", "a\nb"}, "term 2"},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateSearch(tc.terms)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one containing %q", err, tc.want)
			}
			for _, term := range tc.terms {
				if len(term) > 3 && strings.Contains(err.Error(), term) {
					t.Fatalf("the error echoes the term: %v", err)
				}
			}
		})
	}
	max := strings.Repeat("é", MaxSearchBytes/2) // exactly the cap in bytes
	if err := ValidateSearch([]string{max, "203.0.113.9", "a b", "Example/1.0 (X11; Linux)"}); err != nil {
		t.Fatalf("a term at the cap, an address, a phrase: %v", err)
	}
}

func TestWithSearchRefusesWhatCannotBeSentSafely(t *testing.T) {
	f, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.WithSearch([]string{"a\nb"}, ""); err == nil {
		t.Fatal("a control character was accepted")
	}
	if err := f.WithSearch([]string{"ok"}, "bad field"); err == nil {
		t.Fatal("a field with a space was accepted")
	}
	many := "    filter:\n" + strings.Repeat("      - term: {field: a, value: b}\n", 7)
	f, err = Parse([]byte(withKibanaLines(many)))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.WithSearch([]string{"x", "y"}, ""); err == nil || !strings.Contains(err.Error(), "clause") {
		t.Fatalf("7 filter clauses and 2 terms passed the clause limit: %v", err)
	}
}

func TestSearchFieldInTheConfigIsValidatedAtLoad(t *testing.T) {
	if _, err := Parse([]byte(withKibanaLines("    search_field: \"a b\"\n"))); err == nil {
		t.Fatal("search_field with a space loaded")
	}
}
