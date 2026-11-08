package jb

import (
	"reflect"
	"testing"
)

// RFC 0017, step 6: Config is opaque. A field or method here would hand a library caller
// the internal config type (and, through Build, the ports) again. The surface golden
// (api_surface_test.go) also fails if EstatePorts or an exported seam reappears.
func TestConfigIsOpaque(t *testing.T) {
	typ := reflect.TypeFor[Config]()
	for i := range typ.NumField() {
		if f := typ.Field(i); f.IsExported() {
			t.Errorf("Config has exported field %s", f.Name)
		}
	}
	if n := reflect.TypeFor[*Config]().NumMethod(); n != 0 {
		t.Errorf("Config has %d exported methods, want 0", n)
	}
}
