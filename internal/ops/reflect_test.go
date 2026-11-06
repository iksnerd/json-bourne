package ops

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

type goodOptions struct {
	Window string   `jb:"window" default:"1h" desc:"Size of the window, e.g. 1h"`
	Mode   string   `jb:"mode" enum:"a,b" default:"a"`
	Days   int      `jb:"days" min:"1" max:"31" default:"7"`
	Big    int64    `jb:"big_count"`
	Apply  bool     `jb:"apply" default:"false"`
	IPs    []string `jb:"ips" desc:"Addresses, a, b"`
	Case   string   `jb:"case" required:"true"`
	Out    string   `jb:"out" cli:"only"`

	Env   func(string) (string, bool) `jb:"-"`
	Ports map[string]int              `jb:"-"`
	Now   func() time.Time            `jb:"-"`
	note  string
}

func codes(ps []Problem) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Code)
	}
	return out
}

func hasCode(ps []Problem, code, ref string) bool {
	for _, p := range ps {
		if p.Code == code && (ref == "" || strings.Contains(p.Ref, ref)) {
			return true
		}
	}
	return false
}

func TestReflectMapsTheFourShapes(t *testing.T) {
	s, only, ps := Reflect(goodOptions{})
	if len(ps) != 0 {
		t.Fatalf("problems: %v", ps)
	}
	b, _ := json.Marshal(s)
	want := `{"type":"object","additionalProperties":false,"properties":{` +
		`"apply":{"type":"boolean","default":false},` +
		`"big_count":{"type":"integer"},` +
		`"case":{"type":"string"},` +
		`"days":{"type":"integer","default":7,"minimum":1,"maximum":31},` +
		`"ips":{"type":"array","description":"Addresses, a, b","items":{"type":"string"}},` +
		`"mode":{"type":"string","default":"a","enum":["a","b"]},` +
		`"out":{"type":"string"},` +
		`"window":{"type":"string","description":"Size of the window, e.g. 1h","default":"1h"}},` +
		`"required":["case"]}`
	if string(b) != want {
		t.Fatalf("schema:\n got %s\nwant %s", b, want)
	}
	if !reflect.DeepEqual(only, []string{"out"}) {
		t.Fatalf("cli only = %v", only)
	}
}

func TestReflectAcceptsAPointerAndFlattensAnEmbeddedStruct(t *testing.T) {
	type outer struct {
		Case string `jb:"case" required:"true"`
		Inner
	}
	s, _, ps := Reflect(&outer{})
	if len(ps) != 0 {
		t.Fatalf("problems: %v", ps)
	}
	if _, ok := s.Properties["config"]; !ok || len(s.Properties) != 2 {
		t.Fatalf("properties = %v", s.Properties)
	}
}

// Inner is exported so that embedding it is visible to reflection.
type Inner struct {
	Config string `jb:"config"`
}

func TestReflectRefusals(t *testing.T) {
	cases := []struct {
		name string
		v    any
		code string
	}{
		{"not a struct", 5, "type-not-struct"},
		{"float", struct {
			X float64 `jb:"x"`
		}{}, "field-type"},
		{"int32", struct {
			X int32 `jb:"x"`
		}{}, "field-type"},
		{"duration", struct {
			X time.Duration `jb:"x"`
		}{}, "field-type"},
		{"map", struct {
			X map[string]string `jb:"x"`
		}{}, "field-type"},
		{"slice of int", struct {
			X []int `jb:"x"`
		}{}, "field-type"},
		{"func", struct {
			X func() `jb:"x"`
		}{}, "field-type"},
		{"untagged", struct{ X string }{}, "field-untagged"},
		{"upper case name", struct {
			X string `jb:"Window"`
		}{}, "name-invalid"},
		{"hyphen name", struct {
			X string `jb:"a-b"`
		}{}, "name-invalid"},
		{"double underscore", struct {
			X string `jb:"a__b"`
		}{}, "name-invalid"},
		{"no_ prefix", struct {
			X bool `jb:"no_store"`
		}{}, "name-invalid"},
		{"help", struct {
			X bool `jb:"help"`
		}{}, "name-invalid"},
		{"empty name", struct {
			X string `jb:""`
		}{}, "name-invalid"},
		{"duplicate", struct {
			X string `jb:"a"`
			Y string `jb:"a"`
		}{}, "name-duplicate"},
		{"enum on int", struct {
			X int `jb:"x" enum:"1,2"`
		}{}, "tag-invalid"},
		{"min on string", struct {
			X string `jb:"x" min:"1"`
		}{}, "tag-invalid"},
		{"min not a number", struct {
			X int `jb:"x" min:"one"`
		}{}, "tag-invalid"},
		{"range reversed", struct {
			X int `jb:"x" min:"5" max:"2"`
		}{}, "range-invalid"},
		{"duplicate enum", struct {
			X string `jb:"x" enum:"a,a"`
		}{}, "enum-duplicate"},
		{"empty enum entry", struct {
			X string `jb:"x" enum:"a,"`
		}{}, "tag-invalid"},
		{"default not an int", struct {
			X int `jb:"x" default:"soon"`
		}{}, "default-invalid"},
		{"default not a bool", struct {
			X bool `jb:"x" default:"maybe"`
		}{}, "default-invalid"},
		{"default outside enum", struct {
			X string `jb:"x" enum:"a,b" default:"c"`
		}{}, "default-invalid"},
		{"default outside range", struct {
			X int `jb:"x" max:"3" default:"4"`
		}{}, "default-invalid"},
		{"bad required", struct {
			X string `jb:"x" required:"yes"`
		}{}, "tag-invalid"},
		{"bad cli", struct {
			X string `jb:"x" cli:"both"`
		}{}, "tag-invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, ps := Reflect(c.v)
			if !hasCode(ps, c.code, "") {
				t.Fatalf("want %s, got %v", c.code, codes(ps))
			}
			for _, p := range ps {
				if p.Ref == "" || p.Message == "" {
					t.Fatalf("problem without reference or message: %+v", p)
				}
			}
		})
	}
}

func TestReflectReturnsEveryProblem(t *testing.T) {
	_, _, ps := Reflect(struct {
		A float64 `jb:"a"`
		B string
		C string `jb:"no_c"`
	}{})
	if len(ps) != 3 {
		t.Fatalf("want 3 problems, got %v", ps)
	}
}

func TestReflectRefsNameTheGoField(t *testing.T) {
	type opts struct {
		Bad float64 `jb:"bad"`
	}
	_, _, ps := Reflect(opts{})
	if len(ps) != 1 || ps[0].Ref != "opts.Bad" {
		t.Fatalf("ref = %v", ps)
	}
}
