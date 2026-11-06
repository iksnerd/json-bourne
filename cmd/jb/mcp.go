package main

import (
	"context"
	"slices"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
	"github.com/iksnerd/json-bourne/internal/mcp"
	"github.com/iksnerd/json-bourne/internal/ops"
)

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
			reg := newMCPRegistry()
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

// newMCPRegistry is the registry `jb mcp` serves: the real operations, called through
// jb.CallTool, which runs a tool call with the tool's fixed values (store=false for hunt
// and activity) and refuses properties the tool does not offer.
func newMCPRegistry() *mcpRegistry {
	return &mcpRegistry{ops: jb.Operations(), call: func(ctx context.Context, name string, args map[string]any) (any, error) {
		return jb.CallTool(ctx, name, args, nil)
	}}
}

// mcpRegistry serves jb.Operations to the MCP server.
type mcpRegistry struct {
	ops  []ops.Operation
	call func(ctx context.Context, name string, args map[string]any) (any, error)
}

func (r *mcpRegistry) has(name string) bool {
	return slices.ContainsFunc(r.ops, func(o ops.Operation) bool { return o.Name == name })
}

// Tools lists the tool entries: every read-only operation, plus each mutating one the
// operator named with --allow. ops.Tool removes the properties a tool must not take
// (the command-line-only ones, and `store` on hunt and activity, which a tool call
// fixes to false), so hunt and activity are read-only tools.
func (r *mcpRegistry) Tools(allow []string) []ops.ToolEntry {
	var out []ops.ToolEntry
	for _, op := range r.ops {
		if !op.ReadOnly && !slices.Contains(allow, op.Name) {
			continue
		}
		out = append(out, ops.Tool(op))
	}
	return out
}

// Call runs a tool. The registry's call function is jb.CallTool, which checks the
// arguments against the tool's schema (so a command-line-only property or `store` is
// refused as unknown) and then adds the fixed values.
func (r *mcpRegistry) Call(ctx context.Context, name string, args map[string]any) (any, error) {
	if !r.has(name) {
		return nil, usageErrorf("unknown operation %q", name)
	}
	return r.call(ctx, name, args)
}
