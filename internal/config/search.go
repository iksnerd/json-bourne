package config

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

const (
	// DefaultSearchField is the field an ad-hoc search term is matched against.
	DefaultSearchField = "message"
	// MaxSearchTerms and MaxSearchBytes bound one run's ad-hoc search.
	MaxSearchTerms = 4
	MaxSearchBytes = 256
)

// UseSearch is how a command or the Go API applies the ad-hoc search options of one run:
// no terms means no search, and a field without terms is refused, so the field is never
// silently ignored. Otherwise it is [File.WithSearch]. It is the one place `jb hunt` and
// jb.Hunt share, so the two cannot differ in what they refuse.
func (f *File) UseSearch(terms []string, field string) error {
	if err := CheckSearch(terms, field); err != nil {
		return err
	}
	if len(terms) == 0 {
		return nil
	}
	return f.WithSearch(terms, field)
}

// CheckSearch refuses a search that is malformed on its own, before any config is read:
// bad terms, a bad field, or a field without terms. No terms and no field is no search.
func CheckSearch(terms []string, field string) error {
	if len(terms) == 0 {
		if field != "" {
			return errors.New("search field needs search terms")
		}
		return nil
	}
	if err := ValidateSearch(terms); err != nil {
		return err
	}
	if field != "" && !filterField.MatchString(field) {
		return errors.New("search field must be 1-128 characters of letters, digits, _ @ . -")
	}
	return nil
}

// ValidateSearch checks the ad-hoc search terms of one run. A term is data, not query
// text: it is length-capped, must be valid UTF-8, must carry no control or format
// character (a newline, a NUL, an ANSI escape, a bidirectional override) and must not be
// blank. Surrounding space is not trimmed, because it would silently change what is
// matched: a term with it is refused. The error names the index of the term and the
// rule, never the term, which may be something pasted from a log.
func ValidateSearch(terms []string) error {
	if len(terms) == 0 {
		return errors.New("search: no term")
	}
	if len(terms) > MaxSearchTerms {
		return fmt.Errorf("search: %d terms, at most %d", len(terms), MaxSearchTerms)
	}
	for i, t := range terms {
		switch {
		case t == "":
			return fmt.Errorf("search term %d is empty", i+1)
		case len(t) > MaxSearchBytes:
			return fmt.Errorf("search term %d is %d bytes, at most %d", i+1, len(t), MaxSearchBytes)
		case !utf8.ValidString(t):
			return fmt.Errorf("search term %d is not valid UTF-8", i+1)
		}
		blank := true
		for _, r := range t {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
				return fmt.Errorf("search term %d contains a control or format character (U+%04X)", i+1, r)
			}
			if !unicode.IsSpace(r) {
				blank = false
			}
		}
		if blank {
			return fmt.Errorf("search term %d is blank", i+1)
		}
		if first, _ := utf8.DecodeRuneInString(t); unicode.IsSpace(first) {
			return fmt.Errorf("search term %d starts with whitespace", i+1)
		}
		if last, _ := utf8.DecodeLastRuneInString(t); unicode.IsSpace(last) {
			return fmt.Errorf("search term %d ends with whitespace", i+1)
		}
	}
	return nil
}
