package main

import (
	"time"

	"github.com/iksnerd/json-bourne/internal/config"
)

// parseWindow reads a window length: a whole number of days ("7d") or anything
// time.ParseDuration accepts ("90m", "24h"). Go has no day unit, so "d" is handled here.
// Unknown units are an error; a unit is never guessed, because a window of 30m read as
// 30h would quietly bury the spike the detector is looking for.
func parseWindow(s string) (time.Duration, error) { return config.ParseWindow(s) }

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
