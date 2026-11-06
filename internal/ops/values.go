package ops

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
)

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// asInt accepts a Go integer, a float with a zero fraction (what encoding/json decodes
// a JSON number to) and a json.Number. It never accepts a bool.
func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		return uintToInt(uint64(n))
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return uintToInt(n)
	case float32:
		return floatToInt(float64(n))
	case float64:
		return floatToInt(n)
	case json.Number:
		if i, err := strconv.ParseInt(string(n), 10, 64); err == nil {
			return i, true
		}
		f, err := strconv.ParseFloat(string(n), 64)
		if err != nil {
			return 0, false
		}
		return floatToInt(f)
	}
	return 0, false
}

func uintToInt(u uint64) (int64, bool) {
	if u > math.MaxInt64 {
		return 0, false
	}
	return int64(u), true
}

func floatToInt(f float64) (int64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) {
		return 0, false
	}
	if f < -9.223372036854775808e18 || f >= 9.223372036854775808e18 {
		return 0, false
	}
	return int64(f), true
}

// asStrings accepts []string and []any whose elements are all strings.
func asStrings(v any) ([]string, bool) {
	switch a := v.(type) {
	case []string:
		return a, true
	case []any:
		out := make([]string, len(a))
		for i, e := range a {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out[i] = s
		}
		return out, true
	}
	return nil, false
}
