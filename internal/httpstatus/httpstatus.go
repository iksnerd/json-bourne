// Package httpstatus is the one parse of an HTTP status field that the detectors
// share. It depends on the standard library alone.
package httpstatus

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// Min and Max bound a status the detectors accept.
const (
	Min = 100
	Max = 599
)

// Parse accepts int, float64 (as JSON decodes numbers) and string forms.
// Anything else, a non-integer, or a value outside 100..599 is unparsable.
func Parse(v any) (int, bool) {
	var n int
	switch x := v.(type) {
	case int:
		n = x
	case int32:
		n = int(x)
	case int64:
		if x < Min || x > Max {
			return 0, false
		}
		n = int(x)
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || x != math.Trunc(x) || x < Min || x > Max {
			return 0, false
		}
		n = int(x)
	case json.Number:
		return Parse(string(x))
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil {
			return 0, false
		}
		n = i
	default:
		return 0, false
	}
	if n < Min || n > Max {
		return 0, false
	}
	return n, true
}
