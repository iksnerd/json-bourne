package httpstatus

import (
	"encoding/json"
	"math"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want int
		ok   bool
	}{
		{"int", 404, 404, true},
		{"int32", int32(200), 200, true},
		{"int64", int64(503), 503, true},
		{"float whole", float64(401), 401, true},
		{"float fractional", 401.5, 0, false},
		{"float nan", math.NaN(), 0, false},
		{"float inf", math.Inf(1), 0, false},
		{"json number", json.Number("302"), 302, true},
		{"string", " 429 ", 429, true},
		{"string junk", "ok", 0, false},
		{"low bound", 100, 100, true},
		{"high bound", 599, 599, true},
		{"below", 99, 0, false},
		{"above", 600, 0, false},
		{"int64 out", int64(1000), 0, false},
		{"nil", nil, 0, false},
		{"bool", true, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Parse(tc.in)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("Parse(%v) = %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}
