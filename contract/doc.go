// Package contract holds consumer contract tests for the public Go API of json-bourne.
//
// It is a separate module that imports only the public packages (package jb
// and sdk), never anything under internal/, so a test here sees the library the way a
// program outside the repository does. Run it with `cd contract && go test ./...`.
package contract
