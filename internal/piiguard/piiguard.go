// Package piiguard is the one place that knows which event fields hold a
// person's identifier and how such a key is shown in a finding. Detectors that
// group events by a configurable key (authspike, newkey, behaviour) share it so
// the list and the digest cannot drift between them.
//
// The digest is UNSALTED: "h:" plus the first 12 hex digits (6 bytes) of the
// SHA-256 of the key. It is stable across runs, so a finding's tag still dedupes,
// but it is not secret. Anyone holding a candidate name or address can hash it
// and compare, so a guessable key can be confirmed. Hashing keeps the personal
// data out of the text of a finding; it does not make the key anonymous.
//
// The package imports the standard library only.
package piiguard

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Personal reports whether a field name is one that holds a person's identifier
// (username, email, user id). It is a guard against the obvious mistake, not a
// classifier: a field with another name can hold personal data too.
func Personal(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "username", "user_name", "email", "user_email", "user_id", "userid":
		return true
	}
	return false
}

// Hash returns the form of key that may appear in a finding: "h:" and 12 hex
// digits of its SHA-256, unsalted (see the package comment).
func Hash(key string) string {
	h := sha256.Sum256([]byte(key))
	return "h:" + hex.EncodeToString(h[:6])
}

// Shown returns key itself when hash is false and Hash(key) when it is true.
func Shown(key string, hash bool) string {
	if !hash {
		return key
	}
	return Hash(key)
}
