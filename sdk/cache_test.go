package sdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// serveWith runs Serve with a New that is handed each config it is asked to build.
func serveWith(t *testing.T, in string, news func(cfg string) (Mapper, error)) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	err := Serve(strings.NewReader(in), &out, Plugin{Name: "t", Version: "1", New: func(c json.RawMessage) (Mapper, error) { return news(string(c)) }})
	if err != nil {
		t.Fatal(err)
	}
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("output line is not JSON: %q", l)
		}
		lines = append(lines, m)
	}
	return lines
}

func req(id int, cfg string) string {
	return fmt.Sprintf(`{"v":1,"id":%d,"config":%s,"docs":[{}]}`+"\n", id, cfg)
}

func tagged(tag string) Mapper {
	return fixedMapper{func(map[string]any) (Event, error) {
		return Event{Time: time.Unix(0, 0), Fields: map[string]any{"cfg": tag}}, nil
	}}
}

func cfgOf(t *testing.T, resp map[string]any) string {
	t.Helper()
	ev, _ := resp["events"].([]any)
	if len(ev) != 1 || ev[0] == nil {
		t.Fatalf("response = %v", resp)
	}
	return ev[0].(map[string]any)["fields"].(map[string]any)["cfg"].(string)
}

func TestSameConfigReusesTheMapperAndAChangedOneBuildsAReplacement(t *testing.T) {
	var built []string
	out := serveWith(t, req(1, `{"a":1}`)+req(2, `{"a":1}`)+req(3, `{"a":2}`)+req(4, `{"a":2}`), func(c string) (Mapper, error) {
		built = append(built, c)
		return tagged(c), nil
	})
	if len(built) != 2 || built[0] != `{"a":1}` || built[1] != `{"a":2}` {
		t.Fatalf("built = %v, want one build per distinct config", built)
	}
	if cfgOf(t, out[3]) != `{"a":2}` {
		t.Errorf("request 3 did not use the replacement")
	}
}

func TestAFailedReplacementDoesNotCommitTheNewConfig(t *testing.T) {
	var built []string
	// A good, B fails, A again, B again. A failed B must not become the cache key: the
	// second B has to build (and fail) again, and A keeps its mapper meanwhile.
	out := serveWith(t, req(1, `"A"`)+req(2, `"B"`)+req(3, `"A"`)+req(4, `"B"`), func(c string) (Mapper, error) {
		built = append(built, c)
		if c == `"B"` {
			return nil, errors.New("bad config")
		}
		return tagged(c), nil
	})
	if s, _ := out[2]["error"].(string); !strings.Contains(s, "config: bad config") {
		t.Fatalf("request 2 = %v", out[2])
	}
	if cfgOf(t, out[3]) != `"A"` {
		t.Errorf("request 3 should be served by the still-cached mapper for A")
	}
	if out[4]["error"] == nil {
		t.Errorf("request 4 (B again) must fail again, not be served: %v", out[4])
	}
	if len(built) != 3 {
		t.Errorf("built = %v, want A once and B twice", built)
	}
}

func TestAConfigThatFailsFirstLeavesNoMapper(t *testing.T) {
	out := serveWith(t, req(1, `"B"`)+req(2, `"B"`), func(string) (Mapper, error) { return nil, errors.New("nope") })
	if out[1]["error"] == nil || out[2]["error"] == nil {
		t.Fatalf("out = %v", out)
	}
}

func TestAPanicWhileBuildingTheMapperIsAResponseErrorNotACrash(t *testing.T) {
	out := serveWith(t, req(1, `"P"`)+req(2, `"A"`), func(c string) (Mapper, error) {
		if c == `"P"` {
			panic("boom s3cr3t")
		}
		return tagged(c), nil
	})
	if len(out) != 3 {
		t.Fatalf("out = %v", out)
	}
	msg, _ := out[1]["error"].(string)
	if msg == "" || strings.Contains(msg, "s3cr3t") {
		t.Errorf("error = %q", msg)
	}
	if cfgOf(t, out[2]) != `"A"` {
		t.Errorf("the plugin did not survive a panicking New")
	}
}

func TestResponseIDEchoesTheRequestAndEveryNullSlotIsListed(t *testing.T) {
	in := `{"v":1,"id":41,"config":{},"docs":[{},"x",{"u":1},null,{}]}` + "\n"
	out := serveWith(t, in, func(string) (Mapper, error) {
		return fixedMapper{func(d map[string]any) (Event, error) {
			if d["u"] != nil {
				return Event{}, ErrUnparsable
			}
			return ok(d)
		}}, nil
	})
	r := out[1]
	if r["id"].(float64) != 41 {
		t.Errorf("id = %v", r["id"])
	}
	ev := r["events"].([]any)
	if len(ev) != 5 {
		t.Fatalf("slots = %d", len(ev))
	}
	nulls := 0
	for _, e := range ev {
		if e == nil {
			nulls++
		}
	}
	if unp := r["unparsable"].([]any); nulls != 3 || len(unp) != 3 {
		t.Errorf("nulls=%d unparsable=%v: every null slot must be listed", nulls, unp)
	}
}
