package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/jb"
)

// newEstateFactsCmd is `jb estate facts`: the facts of an estate file. The one
// subcommand reads an export file the operator already holds; nothing is sent anywhere.
func newEstateFactsCmd(d deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "facts",
		Short: "Work with the facts of an estate file (open ports, operating system, certificate names)",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newEstateFactsImportCmd(d))
	return cmd
}

func newEstateFactsImportCmd(d deps) *cobra.Command {
	var caseDir, file, output string
	var apply bool
	cmd := &cobra.Command{
		Use:   "import --case DIR [--file NAME] [--apply] IMPORT-FILE|-",
		Short: "Add facts from an export file you hold to a node of the estate file (dry run unless --apply)",
		Long: "import reads ONE small JSON file in a neutral shape (docs/CASE-SPEC.md section 4.5.2): the method, a\n" +
			"source note, the time the store observed the data and, per node and key, a list of values. You convert\n" +
			"a vendor export to that shape with a script you control; jb reads no vendor format. The shape is one\n" +
			"document, or a header object followed by one entry object per line (JSON lines). Name the file, or\n" +
			"give - to read standard input, so a tool's output can be piped in: tool -json | jq -c ... | jb estate\n" +
			"facts import --case DIR -\n\n" +
			"Every fact gets the source `scan-cache` (docs/POLICY.md, \"The test for a source\"): a cache of past\n" +
			"observations by someone else. The target observes nothing from jb. jb sends nothing anywhere and needs\n" +
			"no estate.external switch: it reads the one file from disk, which must be at most 1 MiB and hold at\n" +
			"most 5000 facts. An unknown key is an error.\n\n" +
			"The nodes must already be in the estate file (--file, default estate.yaml); an import never creates\n" +
			"one. The whole import is refused, and the file left as it was, when it names a node that is not there\n" +
			"or would leave a file that does not load. It is a dry run unless you pass --apply. A fact already\n" +
			"recorded (same key, value, source and method) is left as it is, so importing an export twice\n" +
			"changes nothing. Rewriting the file does not preserve comments.\n\n" + jb.EstateFactsImportNote,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("give exactly one import file, got %d", len(args))
			}
			if caseDir == "" {
				return usageErrorf("--case is required")
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			opts := jb.EstateFactsImportOptions{EstateOptions: d.estateOptions(file), Apply: apply}
			name := args[0]
			if name == "-" {
				opts.Input, opts.InputName, name = cmd.InOrStdin(), "stdin", ""
			}
			res, err := jb.EstateFactsImport(caseDir, name, opts)
			if err != nil {
				return err
			}
			if output == "json" {
				return writeIndentedJSON(cmd.OutOrStdout(), res)
			}
			return writeFactsImportTable(cmd.OutOrStdout(), res)
		},
	}
	f := cmd.Flags()
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md) (required)")
	f.StringVar(&file, "file", jb.EstateDefaultFile, "estate file name inside the case's estate directory; it must exist")
	f.BoolVar(&apply, "apply", false, "write the facts (default: dry run, nothing is changed)")
	f.StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

func writeFactsImportTable(w io.Writer, r *jb.EstateFactsImportResult) error {
	fmt.Fprintf(w, "import      %s (%d entr(ies), %d fact(s))\n", r.Import, r.Entries, r.Facts)
	fmt.Fprintf(w, "file        %s\n", r.File)
	fmt.Fprintf(w, "source      %s\n", r.Source)
	fmt.Fprintf(w, "method      %s\n", oneLine(r.Method))
	fmt.Fprintf(w, "recorded    +%d fact(s), %d already recorded", r.Added, r.Unchanged)
	switch {
	case r.Applied:
		fmt.Fprint(w, " (file written)")
	case r.Added > 0:
		fmt.Fprint(w, " (dry run: nothing was changed; add --apply to write)")
	default:
		fmt.Fprint(w, " (file not changed)")
	}
	fmt.Fprintf(w, "\nnote        %s\n", r.Note)
	return nil
}
