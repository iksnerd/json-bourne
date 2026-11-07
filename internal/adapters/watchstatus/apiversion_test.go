package watchstatus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// jb.watch-status/v1 is a supported file format (RFC 0018): Read accepts that version
// and refuses another with the documented message. The string is written out, not taken
// from the constant.
func TestReadAcceptsOnlyWatchStatusV1(t *testing.T) {
	write := func(version string) string {
		p := filepath.Join(t.TempDir(), "watch-status.a.json")
		if err := os.WriteFile(p, []byte(`{"apiVersion":"`+version+`","name":"a","pid":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := Read(write("jb.watch-status/v1")); err != nil && strings.Contains(err.Error(), "apiVersion") {
		t.Errorf("refused its own version: %v", err)
	}
	for _, other := range []string{"jb.watch-status/v2", "jb.watch-status/v0", "v1", ""} {
		_, err := Read(write(other))
		if err == nil {
			t.Fatalf("%q was accepted", other)
		}
		if !strings.Contains(err.Error(), `apiVersion "`+other+`", this build reads "jb.watch-status/v1"`) || !strings.Contains(err.Error(), "restart a watcher from an older build") {
			t.Errorf("%q: message %q", other, err)
		}
	}
}
