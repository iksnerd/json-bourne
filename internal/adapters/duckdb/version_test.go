package duckdb

import (
	"strings"
	"testing"
)

func TestEngineVersionStartsAnEngineWithoutAFile(t *testing.T) {
	v, err := EngineVersion()
	if err != nil || !strings.HasPrefix(v, "v") {
		t.Fatalf("%q %v", v, err)
	}
}

func TestDriverVersionIsReportedNotInvented(t *testing.T) {
	v := DriverVersion()
	if v == "" {
		t.Fatal("empty")
	}
	t.Logf("driver %s", v)
}
