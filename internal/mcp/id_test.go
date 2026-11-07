package mcp

import (
	"strings"
	"testing"
	"time"
)

func waitEnded(g *gateRegistry, tag string) {
	deadline := time.Now().Add(60 * time.Second)
	for g.endedAs(tag) == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
}

func TestIDsAboveTwoToThe53DifferingInLowBitsAreTwoCalls(t *testing.T) {
	g := newGate()
	c := start(t, g)
	c.init()
	const hi, lo = "9007199254740993", "9007199254740992"
	c.send(hold(hi, "hi"))
	g.waitStarted(t, "hi")
	c.send(hold(lo, "lo")) // not refused as a duplicate
	g.waitStarted(t, "lo")
	c.send(cancelMsg(hi))
	waitEnded(g, "hi")
	if g.endedAs("hi") != "cancelled" || g.endedAs("lo") != "" {
		t.Fatalf("hi=%q lo=%q", g.endedAs("hi"), g.endedAs("lo"))
	}
	close(g.release)
	line, err := c.out.ReadString('\n')
	if err != nil || !strings.Contains(line, `"id":`+lo+`,`) || strings.Contains(line, `error`) {
		t.Fatalf("response = %q, %v", line, err)
	}
}

func TestOneOnePointZeroAndStringOneAreThreeIDs(t *testing.T) {
	g := newGate()
	c := start(t, g)
	c.init()
	c.send(hold("1", "int"))
	g.waitStarted(t, "int")
	c.send(hold("1.0", "float"))
	g.waitStarted(t, "float")
	c.send(hold(`"1"`, "str"))
	g.waitStarted(t, "str")
	c.send(cancelMsg("1.0"))
	waitEnded(g, "float")
	if g.endedAs("float") != "cancelled" || g.endedAs("int") != "" || g.endedAs("str") != "" {
		t.Fatalf("int=%q float=%q str=%q", g.endedAs("int"), g.endedAs("float"), g.endedAs("str"))
	}
	close(g.release)
	for i := 0; i < 2; i++ {
		line, err := c.out.ReadString('\n')
		if err != nil || strings.Contains(line, `error`) || !(strings.Contains(line, `"id":1,`) || strings.Contains(line, `"id":"1"`)) {
			t.Fatalf("response = %q, %v", line, err)
		}
	}
}

func TestIDKeyTrimsWhitespaceOnly(t *testing.T) {
	if idKey([]byte(" 1\t")) != idKey([]byte("1")) {
		t.Fatal("surrounding whitespace must not change the id")
	}
	for _, other := range []string{"1.0", `"1"`, "1e0", "01"} {
		if idKey([]byte(other)) == idKey([]byte("1")) {
			t.Fatalf("%s equals 1", other)
		}
	}
}
