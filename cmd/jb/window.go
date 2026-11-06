package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseWindow reads a window length: a whole number of days ("7d") or anything
// time.ParseDuration accepts ("90m", "24h"). Go has no day unit, so "d" is handled here.
// Unknown units are an error; a unit is never guessed, because a window of 30m read as
// 30h would quietly bury the spike the detector is looking for.
func parseWindow(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("window is empty")
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n < 1 {
			return 0, fmt.Errorf("window %q: days must be a whole number of at least 1", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("window %q: %w", s, err)
	}
	return d, nil
}

// windowValue lets --window accept "7d" as well as Go durations.
type windowValue time.Duration

func (w *windowValue) String() string { return time.Duration(*w).String() }
func (w *windowValue) Type() string   { return "duration" }
func (w *windowValue) Set(s string) error {
	d, err := parseWindow(s)
	if err != nil {
		return err
	}
	*w = windowValue(d)
	return nil
}
