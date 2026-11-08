# Consumer contract tests

A separate Go module (`github.com/iksnerd/json-bourne/contract`) that tests the public Go API from the outside. It imports only the root package `jb` and `sdk`, never `internal/`, so an internal change that alters what a library user sees fails here.

    cd contract && go test -race -count=1 ./...

It pins: the signature of every function in the command-to-function table of docs/LIBRARY.md, the JSON shape of each result type (`testdata/*.json`, key names, nesting, null versus absent), the byte-exact agreement of `Hunt` and `Activity` with the CLI goldens in `cmd/jb/testdata`, documented defaults and dry runs, error categories, completeness (an incomplete result is never clean), cancellation, `Operations`/`Call`/`CallTool` against `docs/operations.json`, and a mapper plugin built on `sdk`.

The shape goldens keep key names and value types, not values. After an intended change to a result type, regenerate them and read the diff:

    go test -run 'TestShape' -update ./...

The module is nested, so `go test ./...` at the repository root does not run it.
