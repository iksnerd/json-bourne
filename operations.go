package jb

import (
	"context"
	"maps"
	"sort"

	"github.com/iksnerd/json-bourne/internal/ops"
)

// Operation is the definition of one operation (RFC 0010): its name, description,
// input schema, whether it is read-only and how the command line reaches it. It marshals
// to the JSON that `jb operations` prints. The definitions are derived from the option
// structs by their `jb:` tags, so a definition cannot disagree with the typed function.
type Operation = ops.Operation

// argv is the checked arguments of a call. A handler asks it whether a property was
// sent at all, which the decoded struct cannot say: a zero value may be a default or an
// explicit 0.
type argv map[string]any

func (a argv) has(name string) bool { _, ok := a[name]; return ok }

// handler runs one operation on arguments that have already passed the check.
type handler func(ctx context.Context, arguments argv, env Env) (any, error)

type registered struct {
	op  Operation
	run handler
}

// fixed makes an MCP tool run with value for the property and not offer it (RFC 0010).
func (r registered) fixed(property string, value any) registered {
	r.op.ToolFixed = map[string]any{property: value}
	if ps := ops.Validate(r.op); len(ps) != 0 {
		panic("jb: operation " + r.op.Name + ": " + ops.Describe(ps))
	}
	return r
}

// register builds an operation from the option struct I and a typed function. A
// definition that breaks a rule of RFC 0010 is a programming error and panics when the
// registry is built; TestRegistryIsTheRFCTable keeps that from ever happening. The
// handler decodes the checked arguments into an I and calls fn, which calls the typed
// function and converts what the schema keeps as text (a window, a time) to its type.
func register[I any](name, title, description string, readOnly bool, cli ops.CLI, fn func(ctx context.Context, in I, env Env, a argv) (any, error)) registered {
	var zero I
	schema, only, problems := ops.Reflect(zero)
	if len(problems) != 0 {
		panic("jb: operation " + name + ": " + ops.Describe(problems))
	}
	cli.Only = append(cli.Only, only...)
	op := Operation{Name: name, Title: title, Description: description, InputSchema: schema, ReadOnly: readOnly, CLI: &cli}
	if problems := ops.Validate(op); len(problems) != 0 {
		panic("jb: operation " + name + ": " + ops.Describe(problems))
	}
	return registered{op: op, run: func(ctx context.Context, arguments argv, env Env) (any, error) {
		var in I
		if err := ops.Decode(arguments, &in); err != nil {
			return nil, err
		}
		return fn(ctx, in, env, arguments)
	}}
}

// both returns a typed result and the error of the function that made it. Some
// functions return a result together with an error (an incomplete hunt, a rename that
// found an overlap); a nil pointer must not become a non-nil interface.
func both[T any](r *T, err error) (any, error) {
	if r == nil {
		return nil, err
	}
	return r, err
}

// registry builds the registered operations, sorted by name. It builds afresh on every
// call, so a caller that edits what [Operations] returns changes nothing for the next
// caller.
func registry() []registered {
	var reg []registered
	reg = append(reg, caseOperations()...)
	reg = append(reg, runOperations()...)
	reg = append(reg, dbOperations()...)
	reg = append(reg, estateOperations()...)
	sort.Slice(reg, func(i, j int) bool { return reg[i].op.Name < reg[j].op.Name })
	return reg
}

// Operations returns the definition of every operation, sorted by name. `jb watch` and
// `jb serve` run until stopped and are not operations. The result is a copy.
func Operations() []Operation {
	reg := registry()
	out := make([]Operation, len(reg))
	for i, r := range reg {
		out[i] = r.op
	}
	return out
}

func find(name string) (registered, error) {
	for _, r := range registry() {
		if r.op.Name == name {
			return r, nil
		}
	}
	return registered{}, usagef("unknown operation %q", name)
}

// Call checks arguments against the named operation's schema and runs its handler. It
// is the one entry the command line and an MCP server share. Arguments that fail the
// check, and an unknown name, are a [UsageError] that lists every problem; nothing runs.
// The check never fills a default: the handler applies them. env is passed to handlers
// that read credentials; nil reads the process environment. The result is the value
// the typed function returns (for example *[CaseShowResult]), the same object that
// `--output json` prints. A result that says the work is incomplete is still a result,
// and a handler may return a result together with an error, as the typed function does.
//
// Call runs hunt and activity with store true unless the arguments say otherwise, as
// the command line does. An MCP server calls [CallTool] instead.
func Call(ctx context.Context, name string, arguments map[string]any, env Env) (any, error) {
	r, err := find(name)
	if err != nil {
		return nil, err
	}
	if ps := ops.Check(r.op.InputSchema, arguments); len(ps) != 0 {
		return nil, usagef("invalid arguments for %s: %s", name, ops.Describe(ps))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r.run(ctx, arguments, env)
}

// toolCall checks a tool call against the schema the tool lists (so a property the
// tool does not offer is refused as unknown) and adds the values the tool fixes.
func toolCall(name string, arguments map[string]any) (registered, argv, error) {
	r, err := find(name)
	if err != nil {
		return registered{}, nil, err
	}
	tool := ops.Tool(r.op)
	if ps := ops.Check(tool.InputSchema, arguments); len(ps) != 0 {
		return registered{}, nil, usagef("invalid arguments for %s: %s", name, ops.Describe(ps))
	}
	merged := argv{}
	maps.Copy(merged, arguments)
	maps.Copy(merged, tool.Fixed)
	return r, merged, nil
}

// CallTool is [Call] for a tool call of an MCP server (RFC 0010). The arguments are
// checked against the tool's input schema, not the operation's: a property that only the
// command line accepts (cli.only) and a property the tool fixes are refused as unknown,
// even if the operation would take them. The fixed values then join the arguments, so
// hunt and activity run with store false and leave no evidence. Which operations a
// server offers, and the apply flag of a mutating one, are the server's to enforce.
func CallTool(ctx context.Context, name string, arguments map[string]any, env Env) (any, error) {
	r, merged, err := toolCall(name, arguments)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r.run(ctx, merged, env)
}
