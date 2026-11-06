# Writing a detector

[Back to the README](../README.md)

A detector implements `core.Detector`:

```go
type Detector interface {
	Name() string
	Detect(ctx context.Context, cur, prev EventReader, w Window) ([]Finding, error)
}
```

`cur` reads the current window `w`; `prev` reads `w.Previous()`. Both read the evidence store, not the source, and are clamped to their window.

## Rules

1. **Compare against the same-length preceding window.** `Window.Previous()` returns it. A raw count means nothing without a baseline; a busy platform is not an attack. If the baseline is empty, say so in `Detail` and lower the severity, and do not invent a rise.
2. **Zero records is `core.ErrNoRecords`, not an empty result.** If the current window holds nothing to judge, return an error that wraps it (`fmt.Errorf("...: %w", core.ErrNoRecords)`). `jb hunt` then reports the detector as `no_records` and the hunt as incomplete. Returning `nil, nil` means "I looked and found nothing", which is a different statement. Reserve it for when the data was there.
3. **A failed read is not an empty read.** Return the error from the iterator. Do not treat a failed baseline read as a baseline of zero.
4. **Stable tags.** `Finding.Tag` is the key for one ongoing condition. Build it from the detector name and the subject (for example `authspike:<key>`), never from prose or numbers that change between runs. `Hunt` deduplicates on it, keeping the most severe.
5. **Never report a number you did not compute.** Every value in `Summary` and `Detail` comes from the events you read. Put both windows' numbers in `Detail` so a reader can check the comparison.
6. **Honour cancellation.** Check `ctx.Err()` after the loop as well: a reader that stops quietly when the context ends looks like a short window.
7. **Stay pure.** A detector reads through the two `EventReader`s and touches nothing else. archtest forbids `net/http`, `os/exec`, the DuckDB and Kibana adapters, `app` and cobra in `internal/adapters/detectors/authspike`; add an equivalent rule for your package.

## Example

`burst` raises a finding when the current window holds at least `Factor` times the events of the one before. It is illustrative, not part of `jb`. The code below compiled and passed a test in a scratch copy of this repository.

```go
package burst

import (
	"context"
	"fmt"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Detector flags a window that holds at least Factor times the events of the
// window before it.
type Detector struct {
	Factor    float64
	MinEvents int
}

var _ core.Detector = (*Detector)(nil)

func (d *Detector) Name() string { return "burst" }

func (d *Detector) Detect(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
	n, err := count(ctx, cur, w)
	if err != nil {
		return nil, fmt.Errorf("burst: current window: %w", err)
	}
	if n == 0 {
		return nil, fmt.Errorf("burst: %w: current window is empty", core.ErrNoRecords)
	}
	base := w.Previous()
	p, err := count(ctx, prev, base)
	if err != nil {
		return nil, fmt.Errorf("burst: preceding window: %w", err)
	}
	if n < d.MinEvents || p == 0 || float64(n) < d.Factor*float64(p) {
		return nil, nil
	}
	return []core.Finding{{
		Detector: d.Name(),
		Tag:      "burst", // one ongoing condition, one tag, across runs
		Severity: core.SevCheck,
		Window:   w,
		Baseline: base,
		Summary:  fmt.Sprintf("%d events against %d in the preceding window", n, p),
		Detail:   map[string]any{"cur_events": n, "prev_events": p, "factor": d.Factor},
	}}, nil
}

// count streams r once. A stream that ended because ctx ended is an error, not a
// short window.
func count(ctx context.Context, r core.EventReader, w core.Window) (int, error) {
	n := 0
	for _, err := range r.Events(ctx, w) {
		if err != nil {
			return 0, err
		}
		n++
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return n, nil
}
```

## Registering it

Create `internal/config/register_<name>.go`, then add one line to `detectorTypes()` in `internal/config/registry.go`. Decode with `decodeNode`, which is strict (unknown keys fail), and validate in the registry function so a bad value fails at load, not mid-incident.

```go
package config

import (
	"errors"

	"gopkg.in/yaml.v3"

	"github.com/iksnerd/json-bourne/internal/adapters/detectors/burst"
	"github.com/iksnerd/json-bourne/internal/core"
)

type burstSpec struct {
	Factor    float64 `yaml:"factor"`
	MinEvents int     `yaml:"min_events"`
}

func registerBurst(m map[string]func(*yaml.Node) (detectorSpec, error)) {
	m["burst"] = func(n *yaml.Node) (detectorSpec, error) {
		var s burstSpec
		if err := decodeNode(n, &s); err != nil { // strict: unknown keys fail
			return nil, err
		}
		if s.Factor <= 1 {
			return nil, errors.New("factor must be greater than 1")
		}
		return s, nil
	}
}

func (s burstSpec) build() (core.Detector, error) {
	return &burst.Detector{Factor: s.Factor, MinEvents: s.MinEvents}, nil
}
```

```go
func detectorTypes() map[string]func(*yaml.Node) (detectorSpec, error) {
	m := map[string]func(*yaml.Node) (detectorSpec, error){}
	registerAuthspike(m)
	registerBurst(m)
	return m
}
```

Then add an archtest rule, document the keys in [CONFIG.md](CONFIG.md), and follow [CONTRIBUTING.md](../CONTRIBUTING.md): write the failing test first and watch it fail.

## A detector that reads case data

If what the detector looks for is an incident's indicators (a user agent, a path), keep them in the case, not in the config and not in code. `fingerprint` is the worked example (`internal/adapters/detectors/fingerprint`, `internal/config/register_fingerprint.go`):

- The detector package takes plain values in its `Config` and imports `core` and the standard library only. It does not read files and does not know the case format; archtest forbids `os`, `internal/casefile`, YAML and the rest for it.
- The registry function in `internal/config` validates what needs no file (names, lexical paths) at load. Its `build(bc buildCtx)` receives the case (`bc.c`, set by `File.UseCase`, which `jb hunt --case` calls) and reads the files through `casefile.LoadActorFile`, which confines the path. Without a case it returns an error that says so.
- `jb case check` builds every listed config's detectors (`File.BuildDetectors`, no environment read), so a missing or malformed file a detector names fails the check and not the hunt.
- A rule that two settings must agree on (for example a grant path must not contain a noise marker) is checked in the detector's `New`, not in the file loader, so it holds however the values arrive.

## Tests worth having

- Zero current records returns an error that satisfies `errors.Is(err, core.ErrNoRecords)`.
- A busy window with no change in failures does not raise a finding.
- A threshold boundary behaves as documented (the real detector tolerates float rounding with an epsilon).
- A reader that errors, and a cancelled context, return errors and not findings.
- Fixtures are synthetic. Use reserved documentation addresses such as `192.0.2.7` and the `example.com` domain.
