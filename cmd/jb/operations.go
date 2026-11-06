package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
	"github.com/iksnerd/json-bourne/internal/ops"
)

func newOperationsCmd() *cobra.Command {
	var output string
	var tool bool
	cmd := &cobra.Command{
		Use:   "operations [--tool] [--output json|table]",
		Short: "Print the definition of every operation",
		Long: "operations prints what jb offers as operations (RFC 0010): the name, description, input schema,\n" +
			"whether it only reads, and how the command line reaches it. The same definition feeds the Go\n" +
			"function jb.Call. It reads no case, no store and no environment variable.\n" +
			"--tool prints the entries an MCP tools/list result carries instead: no cli, no property that only\n" +
			"the command line accepts, and readOnlyHint and destructiveHint annotations. The output is JSON.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			if tool && output == "table" {
				return usageErrorf("--tool prints JSON; it cannot be combined with --output table")
			}
			list := jb.Operations()
			var err error
			switch {
			case output == "table":
				tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "NAME\tREAD-ONLY\tCOMMAND\tDESCRIPTION")
				for _, op := range list {
					cmdline := ""
					if op.CLI != nil {
						for _, w := range op.CLI.Command {
							cmdline += " " + w
						}
						cmdline = "jb" + cmdline
					}
					fmt.Fprintf(tw, "%s\t%t\t%s\t%s\n", op.Name, op.ReadOnly, cmdline, firstSentence(op.Description))
				}
				err = tw.Flush()
			case tool:
				entries := make([]ops.ToolEntry, len(list))
				for i, op := range list {
					entries[i] = ops.Tool(op)
				}
				err = writeIndentedJSON(cmd.OutOrStdout(), entries)
			default:
				err = writeIndentedJSON(cmd.OutOrStdout(), list)
			}
			if err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&output, "output", "json", "output format: json or table")
	cmd.Flags().BoolVar(&tool, "tool", false, "print MCP tools/list entries instead of the full definitions")
	return cmd
}

func firstSentence(s string) string {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '.' && s[i+1] == ' ' {
			return s[:i+1]
		}
	}
	return s
}
