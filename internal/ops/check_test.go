package ops

import (
	"encoding/json"
	"strings"
	"testing"
)

func testSchema(t *testing.T) Schema {
	t.Helper()
	s, _, ps := Reflect(goodOptions{})
	if len(ps) != 0 {
		t.Fatal(ps)
	}
	return s
}

func decodeJSON(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCheckAccepts(t *testing.T) {
	s := testSchema(t)
	for _, in := range []string{
		`{"case":"x"}`,
		`{"case":"x","days":31,"mode":"b","apply":true,"ips":["a","b"],"window":"2h","big_count":9007199254740993}`,
		`{"case":"x","days":1.0}`,
		`{"case":"x","ips":[]}`,
	} {
		if ps := Check(s, decodeJSON(t, in)); len(ps) != 0 {
			t.Errorf("%s: %v", in, ps)
		}
	}
	if ps := Check(s, map[string]any{"case": "x", "days": 3}); len(ps) != 0 {
		t.Errorf("Go int: %v", ps)
	}
}

func TestCheckRefusals(t *testing.T) {
	s := testSchema(t)
	cases := []struct {
		name, in, code, ref string
	}{
		{"not an object", `[1]`, "arguments-type", ""},
		{"a string", `"x"`, "arguments-type", ""},
		{"null", `null`, "argument-missing", "case"}, // absent arguments are an empty object
		{"unknown", `{"case":"x","zzz":1}`, "argument-unknown", "zzz"},
		{"case-only property is still known to the check", `{"case":"x","out":5}`, "argument-type", "out"},
		{"missing", `{}`, "argument-missing", "case"},
		{"string for int", `{"case":"x","days":"3"}`, "argument-type", "days"},
		{"fraction", `{"case":"x","days":2.5}`, "argument-type", "days"},
		{"bool for int", `{"case":"x","days":true}`, "argument-type", "days"},
		{"int for bool", `{"case":"x","apply":1}`, "argument-type", "apply"},
		{"int for string", `{"case":3}`, "argument-type", "case"},
		{"null value", `{"case":"x","days":null}`, "argument-type", "days"},
		{"string for array", `{"case":"x","ips":"a"}`, "argument-type", "ips"},
		{"number in array", `{"case":"x","ips":["a",1]}`, "argument-type", "ips[1]"},
		{"enum", `{"case":"x","mode":"c"}`, "argument-enum", "mode"},
		{"below minimum", `{"case":"x","days":0}`, "argument-range", "days"},
		{"above maximum", `{"case":"x","days":32}`, "argument-range", "days"},
		{"too large for int64", `{"case":"x","big_count":1e30}`, "argument-type", "big_count"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ps := Check(s, decodeJSON(t, c.in))
			if !hasCode(ps, c.code, c.ref) {
				t.Fatalf("want %s on %q, got %v", c.code, c.ref, ps)
			}
		})
	}
}

func TestCheckListsEveryProblemInOrderAndNeverFillsDefaults(t *testing.T) {
	s := testSchema(t)
	ps := Check(s, decodeJSON(t, `{"zzz":1,"days":99,"apply":"x"}`))
	got := []string{}
	for _, p := range ps {
		got = append(got, p.Code+":"+p.Ref)
	}
	want := []string{"argument-type:apply", "argument-missing:case", "argument-range:days", "argument-unknown:zzz"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
	args := map[string]any{"case": "x"}
	if ps := Check(s, args); len(ps) != 0 || len(args) != 1 {
		t.Fatalf("check changed the arguments or failed: %v %v", ps, args)
	}
}

func TestCheckAcceptsJSONNumber(t *testing.T) {
	s := testSchema(t)
	dec := json.NewDecoder(strings.NewReader(`{"case":"x","days":3,"big_count":4.0}`))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	if ps := Check(s, v); len(ps) != 0 {
		t.Fatal(ps)
	}
	dec = json.NewDecoder(strings.NewReader(`{"case":"x","days":3.5}`))
	dec.UseNumber()
	_ = dec.Decode(&v)
	if ps := Check(s, v); !hasCode(ps, "argument-type", "days") {
		t.Fatal(ps)
	}
}

func TestDecodePopulatesAStruct(t *testing.T) {
	args := decodeJSON(t, `{"case":"c","window":"2h","days":5,"big_count":7,"apply":true,"ips":["a","b"],"mode":"b"}`).(map[string]any)
	var o goodOptions
	if err := Decode(args, &o); err != nil {
		t.Fatal(err)
	}
	if o.Case != "c" || o.Window != "2h" || o.Days != 5 || o.Big != 7 || !o.Apply || len(o.IPs) != 2 || o.Mode != "b" {
		t.Fatalf("decoded %+v", o)
	}
}

func TestDecodeLeavesAbsentFieldsAloneAndFlattensEmbedded(t *testing.T) {
	type in struct {
		Case string `jb:"case"`
		Inner
	}
	o := in{Inner: Inner{Config: "keep"}}
	if err := Decode(map[string]any{"case": "c"}, &o); err != nil {
		t.Fatal(err)
	}
	if o.Case != "c" || o.Config != "keep" {
		t.Fatalf("%+v", o)
	}
	if err := Decode(map[string]any{"config": "k2"}, &o); err != nil || o.Config != "k2" {
		t.Fatalf("%v %+v", err, o)
	}
}

func TestDecodeRefusesWhatTheCheckWouldHave(t *testing.T) {
	var o goodOptions
	if err := Decode(map[string]any{"days": "x"}, &o); err == nil {
		t.Fatal("string into int accepted")
	}
	if err := Decode(map[string]any{"nope": 1}, &o); err == nil {
		t.Fatal("unknown key accepted")
	}
	if err := Decode(map[string]any{}, o); err == nil {
		t.Fatal("non-pointer accepted")
	}
}
