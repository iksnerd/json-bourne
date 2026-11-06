package main

import (
	"testing"
	"time"
)

func TestParseWindow(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"7d", 7 * 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"30m", 30 * time.Minute, false}, // minutes are minutes, never hours
		{"90m", 90 * time.Minute, false},
		{"0d", 0, true},
		{"d", 0, true},
		{"1.5d", 0, true},
		{"-2d", 0, true},
		{"", 0, true},
		{"7x", 0, true},
		{"7", 0, true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := parseWindow(c.in)
			if (err != nil) != c.wantErr {
				t.Fatalf("parseWindow(%q) error = %v, wantErr %v", c.in, err, c.wantErr)
			}
			if !c.wantErr && got != c.want {
				t.Fatalf("parseWindow(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestWindowFlagAcceptsDays(t *testing.T) {
	var d time.Duration
	v := (*windowValue)(&d)
	if err := v.Set("7d"); err != nil || d != 168*time.Hour {
		t.Fatalf("Set(7d): d=%v err=%v", d, err)
	}
	if err := v.Set("bogus"); err == nil {
		t.Fatal("Set(bogus) should fail")
	}
}
