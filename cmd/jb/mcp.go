package main

import (
	"context"
	"slices"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
	"github.com/iksnerd/json-bourne/internal/mcp"
	"github.com/iksnerd/json-bourne/internal/ops"
)

// noStoreOperations write a run to the evidence store unless told not to (RFC 0009).
// Over MCP the store property is removed and fixed to false, so they are read-only
// tools (RFC 0010).
var noStoreOperations = []string{"hunt", "activity"}

func newMCPCmd() *cobra.Command {
	var allow []string
	cmd := &cobra.Command{
		Use:   "mcp [--allow NAME ...]",
		Short: "Serve the operations as MCP tools over standard input and output",
		Long: "mcp serves the Model Context Protocol (2025-11-25) on standard input and output: one JSON-RPC message per\n" +
			"line. It lists only the read-only operations. A mutating operation is listed only when named by --allow\n" +
			"NAME (repeatable), and a call to it still needs apply=true to act. The server runs with the environment of\n" +
			"its process, so it holds whatever credentials that process holds: start it with only the ones it needs.\n" +
			"Keep a person able to deny tool calls in the client. Nothing but protocol messages goes to standard output.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			reg := &mcpRegistry{ops: jb.Operations(), call: func(ctx context.Context, name string, args map[string]any) (any, error) {
				return jb.Call(ctx, name, args, nil)
			}}
			for _, name := range allow {
				if !reg.has(name) {
					return usageErrorf("--allow %q is not an operation (see 'jb operations')", name)
				}
			}
			v, _, _ := buildInfo()
			if v == "" {
				v = "dev"
			}
			return mcp.Serve(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), mcp.Config{Version: v, Allow: allow, Registry: reg})
		},
	}
	cmd.Flags().StringArrayVar(&allow, "allow", nil, "also expose the mutating operation `NAME` (repeatable); a call still needs apply=true")
	return cmd
}

// mcpRegistry serves jb.Operations to the MCP server.
type mcpRegistry struct {
	ops  []ops.Operation
	call func(ctx context.Context, name string, args map[string]any) (any, error)
}

func (r *mcpRegistry) has(name string) bool {
	return slices.ContainsFunc(r.ops, func(o ops.Operation) bool { return o.Name == name })
}

func (r *mcpRegistry) Tools(allow []string) []ops.ToolEntry {
	var out []ops.ToolEntry
	for _, op := range r.ops {
		forced := slices.Contains(noStoreOperations, op.Name)
		if !op.ReadOnly && !forced && !slices.Contains(allow, op.Name) {
			continue
		}
		t := ops.Tool(op)
		if forced {
			delete(t.InputSchema.Properties, "store")
			t.InputSchema.Required = slices.DeleteFunc(t.InputSchema.Required, func(s string) bool { return s == "store" })
			if !slices.Contains(allow, op.Name) {
				t.Annotations = ops.ToolAnnotations{ReadOnlyHint: true}
			}
		}
		out = append(out, t)
	}
	return out
}

func (r *mcpRegistry) Call(ctx context.Context, name string, args map[string]any) (any, error) {
	for _, op := range r.ops {
		if op.Name != name {
			continue
		}
		var only []string
		if op.CLI != nil {
			only = op.CLI.Only
		}
		for k := range args {
			if slices.Contains(only, k) {
				return nil, usageErrorf("%s is not an argument of this operation", k)
			}
		}
		if slices.Contains(noStoreOperations, name) {
			if _, ok := args["store"]; ok {
				return nil, usageErrorf("store is not an argument of this operation")
			}
			args = cloneArgs(args)
			args["store"] = false
		}
		return r.call(ctx, name, args)
	}
	return nil, usageErrorf("unknown operation %q", name)
}

func cloneArgs(a map[string]any) map[string]any {
	out := make(map[string]any, len(a)+1)
	for k, v := range a {
		out[k] = v
	}
	return out
}
