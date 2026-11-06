package kibana

import (
	"fmt"
	"strings"
	"testing"
)

func TestClientNeverPrintsItsKey(t *testing.T) {
	const secret = "s3cr3t-api-key-value"
	c := New("https://kibana.example.com", secret)
	s := &Source{Client: c, Index: "logs-*"}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, v := range []any{c, s, *c} {
			if out := fmt.Sprintf(f, v); strings.Contains(out, secret) {
				t.Fatalf("format %s of %T leaked the key: %s", f, v, out)
			}
		}
	}
}
