# Writing a source

[Back to the README](../README.md)

A source implements `core.Source`:

```go
type Source interface {
	Name() string
	Fetch(ctx context.Context, w Window) iter.Seq2[Event, error]
}
```

`Fetch` streams every event in the half-open window `[w.From, w.To)`. `Hunt` asks for the current window and the one before it in a single span and stores the result.

## Rules

1. **Stream, and stop when asked.** Yield events one at a time. If `yield` returns false, return. If `ctx` ends, yield `ctx.Err()` and return. Do not collect a window in memory first.
2. **Zero records is `core.ErrNoRecords`.** If the whole fetch produced no events, yield an error wrapping it. The store also refuses an empty save with the same error, so nothing is replaced by an empty run, and `hunt` reports the source as `no_records`.
3. **An unreachable or refusing backend is `core.ErrSourceUnavailable`.** Wrap it (`%w`) so the status shows as `unavailable`. Do not put the response body or request headers in the message: a proxy can reflect a credential back.
4. **Names are unique and stable.** `Name()` becomes part of the run id (`<run>/<name>`) and `Hunt` rejects two sources with the same name. Include what distinguishes instances, as `kibana:<index>` does; the Kibana source also takes a configured `name`, so two sources can read one index. If two instances of your source can return the same record, implement `core.DocScoped` and set `Event.DocKey`, or the record is counted twice.
5. **Never report a number you did not fetch.** If a backend returns a total that differs from what you received (an index-wide count against a capped page), keep them apart. The Kibana source exposes `Stats{HitsTotal, Fetched, Unparsable}` for this reason.
   A record you cannot parse is counted, never dropped: the Kibana mappers wrap `kibana.ErrUnparsable`, the source counts those and carries on, and a window where nothing parsed is `core.ErrNoRecords`. New Kibana mappers go in the registry in `internal/adapters/kibana/mappers.go` (name to `Mapper`); the config loader checks `mapper:` against it.
6. **Normalise, and keep the original.** Set `Event.Time`, `Source`, `Fields`, and `Raw` (the document as received). `Raw` is what makes a finding traceable to evidence, and the store's de-duplication hashes it.
7. **Read only.** A source must not write to, or change anything in, the system it reads. The Kibana adapter uses one route, `POST /internal/search/es`, as a read.
8. **Credentials come from the environment**, resolved in the config registration (below), and never appear in errors, logs or `String()` output. See [CONFIG.md](CONFIG.md).

## Example

`memsrc` serves records from memory. It is illustrative, not part of `jb`. The code below compiled and passed a test in a scratch copy of this repository.

```go
package memsrc

import (
	"context"
	"fmt"
	"iter"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

type Record struct {
	At   time.Time
	Line string
}

// Source serves records held in memory.
type Source struct {
	Label   string
	Records []Record
}

var _ core.Source = (*Source)(nil)

func (s *Source) Name() string { return "mem:" + s.Label }

func (s *Source) Fetch(ctx context.Context, w core.Window) iter.Seq2[core.Event, error] {
	return func(yield func(core.Event, error) bool) {
		n := 0
		for _, r := range s.Records {
			if err := ctx.Err(); err != nil {
				yield(core.Event{}, err)
				return
			}
			if r.At.Before(w.From) || !r.At.Before(w.To) { // [From, To)
				continue
			}
			n++
			ev := core.Event{
				Time:   r.At,
				Source: s.Name(),
				Fields: map[string]any{"line": r.Line},
				Raw:    []byte(r.Line),
			}
			if !yield(ev, nil) {
				return
			}
		}
		if n == 0 {
			yield(core.Event{}, fmt.Errorf("%w: %s has nothing in [%s, %s)",
				core.ErrNoRecords, s.Name(), w.From.Format(time.RFC3339), w.To.Format(time.RFC3339)))
		}
	}
}
```

## Registering it

Same shape as a detector: one file `internal/config/register_<name>.go`, one line in `sourceTypes()` in `internal/config/registry.go`. A source spec has `build(env Env) (core.Source, error)`, which is where the credential is read:

```go
func (s mySpec) build(env Env) (core.Source, error) {
	key, ok := env(s.APIKeyEnv)
	if !ok || key == "" {
		return nil, fmt.Errorf("environment variable %s is not set", s.APIKeyEnv)
	}
	// construct the source with key
}
```

The error names the variable and never the value. Validate the variable name at load (the Kibana registration refuses anything that is not upper-case letters, digits and underscore, so a pasted key is rejected without being echoed). Refuse plain `http` URLs except to loopback.

Add the archtest rule for your package (adapters depend on `core` only and never on each other), test against a local `httptest` server or recorded synthetic JSON, and follow [CONTRIBUTING.md](../CONTRIBUTING.md).

## Mapper contract

A log mapper is a pure function from one raw document to one event. The built-in `keycloak` mapper (`internal/logmap/keycloak`) is written to this contract on purpose, so the same mapper can later run as a separate process and be proven identical. Nothing here is a plugin host; there is none yet.

**Input.** The bytes of one document as the source returned it: a JSON object with an RFC 3339 `@timestamp` (string) and a `message` (string). Other members are ignored.

**Output.** Exactly one of:

- an event: `time` (the `@timestamp`, as an instant) and `fields`, a flat object of strings. For `keycloak`: `event_type`, `outcome` (`success` or `error`), `error`, `client_ip`, `realm`, `client_id`, `username`, `email`. A field is present only when the document carries a real value for it; `-`, `null` and the empty string are absent, never emitted as text. No field is invented (there is no `status`, `method` or `path`). The event's `Raw` is the input bytes.
- **unparsable**: the document is not in the format this mapper reads. It is a property of one document. The caller counts it (`Stats.Unparsable`) and goes on; if nothing in a window parses, the fetch fails with `no records`. Examples: not a JSON object, no text `message`, no event type, an `ipAddress` that is not an address, an unterminated value, any size limit exceeded.
- **bad time**: `@timestamp` missing, not text or not RFC 3339. It is a fault in the document set, so the caller stops.

**Hostile input.** The mapper must not panic, must run in time linear in the input, and must bound memory by the limits below; a document over a limit is unparsable, never truncated. Limits for `keycloak`: document 64 KiB, `message` 16 KiB, 64 key/value pairs, keys 64 bytes, values 2048 bytes. The first occurrence of a key wins (Keycloak does not escape values and the username is the attacker's). Keycloak writes its own keys (`type`, `realmId`, `realmName`, `clientId`, `userId`, `sessionId`, `ipAddress`, `error`) before the details, so one of those keys after the first other key is ignored: a username of `x", error="none` cannot turn a success into an error. Only the keys the mapper names are read; `cookies` and `requestUri` of a TRACE line are never emitted. Unquoted values are unparsable, never guessed.

**Corpus.** `internal/logmap/keycloak/testdata/corpus` holds `NAME.in.json` (the document, byte for byte) and `NAME.want.json`, one of `{"time": ..., "fields": {...}}`, `{"unparsable": true}` or `{"bad_time": true}`. An implementation conforms when it gives the wanted result for every file; `TestCorpus` is the reference runner. Every value in the corpus is synthetic (example.com, RFC 5737 addresses, made-up names). Add a file for each odd line seen in the field, with the values replaced.

`internal/archtest` holds the package to core and the standard library, with no file, network, process, clock or shared state.

## Mapper contract: request_dump

`request_dump` (`internal/logmap/requestdump`) follows the contract above and adds a configuration, so the pure function is `New(Config)` and then `Map(bytes)`. The configuration is data (`client_ip_header`, `user_agent_header`, `header_fields`; see [CONFIG.md](CONFIG.md#mappers)); an unknown key or a credential-bearing header name is refused when the mapper is built, never at map time.

**Input.** A JSON object with an RFC 3339 `@timestamp` and a `message` string that holds the request dump: a first line `=== Request Info ===`, then `method = M`, `path = P`, any other lines (ignored), and one `header = NAME<blanks>value = VALUE` line per header. A header line is recognised only in that shape. `method` and `path` are read only before the first header line.

**Output.** An event with `method`, `path` (query and fragment removed), and, when the dump carries them and the config names them, `client_ip`, `user_agent` and the `header_fields` fields; all strings. Or **unparsable** (not a request dump, no valid method or path, any limit exceeded), or **bad time**. `Raw` is the redacted dump described below, not the input bytes.

**What it will not emit.** A header named in no config entry is never read. A header whose name contains `auth`, `cookie`, `token`, `secret`, `password`, `passwd`, `session`, `credential`, `bearer`, `jwt`, `csrf`, `xsrf`, `api-key`, `apikey`, `api_key` or `private` is refused as a configured field and has its value replaced by `[redacted]` in `Raw`, as does the query string of `path`. `TestCredentialHeadersNeverReachFieldsOrRaw` and `TestConfigRefusesCredentialHeaders` hold this with sentinel values, even for a config that asks for the header.

**Hostile input.** Limits: document 256 KiB, `message` 64 KiB, 512 lines, 256 headers, header names 64 bytes, path 2048, method 16, a header value read into a field 1024 (a marker value 256). A document over a limit is unparsable. One exception, on purpose: `user_agent` is cut to 512 bytes, so an oversized agent does not make a request vanish from the log. A repeated client-address header emits no `client_ip`. A header value is attacker text: it cannot supply `method`, `path` or the address.

**Corpus.** `internal/logmap/requestdump/testdata/corpus`, same layout and runner (`TestCorpus`) as `keycloak`, run against the configuration in `requestdump_test.go`. Every value is synthetic (example.com, RFC 5737 addresses, made-up header names). There is no plugin twin: the dump's header lines come in any order, which `regexlines` cannot express and `kvlines` does not read, so there is no built-in-versus-plugin conformance test for this mapper.

`internal/archtest` holds the package to core and the standard library, with the same purity rule as `keycloak`.
