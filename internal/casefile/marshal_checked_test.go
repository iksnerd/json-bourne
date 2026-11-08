package casefile

import (
	"errors"
	"strings"
	"testing"
)

func TestMarshalCheckedBranches(t *testing.T) {
	rules := func() marshalRules {
		return marshalRules{
			invalid:  "refusing: invalid",
			validate: func() error { return nil },
			limit:    1 << 10,
			tooBig:   func(n int) error { return errors.New("too big") },
			reparse:  func([]byte) error { return nil },
			reject:   "refusing: loader",
		}
	}
	v := map[string]string{"a": "b"}

	t.Run("passes", func(t *testing.T) {
		got, err := marshalChecked(v, rules())
		if err != nil || string(got) != "a: b\n" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		r := rules()
		r.validate = func() error { return errors.New("bad") }
		if _, err := marshalChecked(v, r); err == nil || err.Error() != "refusing: invalid: bad" {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("too big", func(t *testing.T) {
		r := rules()
		r.limit = 2
		if _, err := marshalChecked(v, r); err == nil || err.Error() != "too big" {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("loader rejects", func(t *testing.T) {
		r := rules()
		r.reparse = func([]byte) error { return errors.New("no") }
		if _, err := marshalChecked(v, r); err == nil || err.Error() != "refusing: loader: no" {
			t.Fatalf("got %v", err)
		}
	})
}

func TestMarshalWrappersKeepErrorPrefixes(t *testing.T) {
	if _, err := MarshalEstate(&Estate{}); err == nil || !strings.HasPrefix(err.Error(), "refusing to write an invalid estate: ") {
		t.Fatalf("estate: %v", err)
	}
	if _, err := MarshalEstateSnapshot(&EstateSnapshot{}); err == nil || !strings.HasPrefix(err.Error(), "refusing to write an invalid snapshot: ") {
		t.Fatalf("snapshot: %v", err)
	}
}
