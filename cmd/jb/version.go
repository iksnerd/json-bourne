package main

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Set at link time:
//
//	go build -ldflags "-X main.version=v0.1.0 -X main.commit=abc123 -X main.date=2026-11-05"
var (
	version = ""
	commit  = ""
	date    = ""
)

// buildInfo returns the link-time values, falling back to the module and VCS
// information the Go toolchain embeds, then to "dev".
func buildInfo() (v, c, d string) {
	v, c, d = version, commit, date
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if c == "" {
					c = s.Value
				}
			case "vcs.time":
				if d == "" {
					d = s.Value
				}
			}
		}
	}
	if v == "" {
		v = "dev"
	}
	return v, c, d
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the jb version",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, c, d := buildInfo()
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "jb %s\n", v)
			if c != "" {
				fmt.Fprintf(out, "commit %s\n", c)
			}
			if d != "" {
				fmt.Fprintf(out, "built  %s\n", d)
			}
			return nil
		},
	}
}
