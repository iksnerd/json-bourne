package main

import (
	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command { return newRootCmdWith(defaultDeps()) }

func newRootCmdWith(d deps) *cobra.Command {
	root := &cobra.Command{
		Use:           "jb",
		Short:         "Evidence-first incident response",
		Long:          "jb fetches logs for a window, stores them as evidence and runs detectors that compare the window with the one before it.",
		SilenceUsage:  true,
		SilenceErrors: true,
		// Args is set so an unknown word reaches RunE as a usage error, instead of
		// cobra printing help and exiting 0.
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usageErrorf("unknown command %q", args[0])
			}
			return cmd.Help()
		},
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageErrorf("%v", err)
	})
	root.AddCommand(newHuntCmdWith(d), newActivityCmdWith(d), newActorCmd(), newIntelCmdWith(d), newWatchCmdWith(d), newCaseCmd(), newEstateCmdWith(d), newDBCmdWith(d), newServeCmdWith(d), newDoctorCmdWith(d), newOperationsCmd(), newVersionCmd())
	return root
}

// noArgs wraps cobra.NoArgs so a stray argument is a usage error.
func noArgs(cmd *cobra.Command, args []string) error {
	if err := cobra.NoArgs(cmd, args); err != nil {
		return usageErrorf("%v", err)
	}
	return nil
}
