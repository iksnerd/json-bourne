package core

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsUsageSeesThroughWrapping(t *testing.T) {
	base := Usagef("window must be positive, got %s", "-5m")
	if got := base.Error(); got != "window must be positive, got -5m" {
		t.Errorf("message = %q", got)
	}
	for name, err := range map[string]error{
		"bare":        base,
		"wrapped":     fmt.Errorf("jb: %w", base),
		"wrapped two": fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", base)),
		"joined":      errors.Join(errors.New("other"), base),
	} {
		if !IsUsage(err) {
			t.Errorf("%s: IsUsage = false", name)
		}
	}
	for name, err := range map[string]error{
		"nil":       nil,
		"plain":     errors.New("window must be positive"),
		"no-record": fmt.Errorf("x: %w", ErrNoRecords),
	} {
		if IsUsage(err) {
			t.Errorf("%s: IsUsage = true", name)
		}
	}
}
