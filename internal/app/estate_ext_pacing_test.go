package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Cancelled while waiting out the interval: the second question was never asked, it is a
// failure, and no absence (a "no" answer) is recorded for it.
func TestCancellationWhileWaitingIsNotAskedAndNotANegativeAnswer(t *testing.T) {
	b := okBGP()
	d := extDeps(b, nil, nil, nil)
	d.Sleep = func(context.Context, time.Duration) error { return context.Canceled }
	res, _ := CollectASN(context.Background(), d, ExternalRequest{Targets: []string{"AS64500", "AS64501"}, MaxTargets: 5, Interval: time.Second})
	if len(b.asked) != 1 {
		t.Errorf("only the first question may be asked: %v", b.asked)
	}
	if res.Complete() || len(res.Failures) != 1 || !errors.Is(res.Failures[0].Err, core.ErrLookupFailed) || !strings.Contains(res.Failures[0].Err.Error(), "not asked") {
		t.Errorf("failures %+v", res.Failures)
	}
	if len(res.Estate.Absences) != 0 {
		t.Errorf("a question not asked was recorded as an answer: %+v", res.Estate.Absences)
	}
}
