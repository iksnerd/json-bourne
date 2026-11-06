package jb

import (
	"context"

	"github.com/iksnerd/json-bourne/internal/ops"
)

// Operation is the definition of one operation (RFC 0010): its name, description,
// input schema, whether it is read-only and how the command line reaches it. It marshals
// to the JSON that `jb operations` prints. The definitions are derived from the option
// structs by their `jb:` tags, so a definition cannot disagree with the typed function.
type Operation = ops.Operation

// handler runs one operation on arguments that have already passed the check.
type handler func(ctx context.Context, arguments map[string]any, env Env) (any, error)

type registered struct {
	op  Operation
	run handler
}

// register builds an operation from the option struct I and a typed function. A
// definition that breaks a rule of RFC 0010 is a programming error and panics when the
// registry is built; TestOperationsAreValidAndUnique keeps that from ever happening.
func register[I any](name, title, description string, readOnly bool, cli ops.CLI, fn func(ctx context.Context, in I, env Env) (any, error)) registered {
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
	return registered{op: op, run: func(ctx context.Context, arguments map[string]any, env Env) (any, error) {
		var in I
		if err := ops.Decode(arguments, &in); err != nil {
			return nil, err
		}
		return fn(ctx, in, env)
	}}
}

// caseShowInput is the input of case_show. The case directory is a property here and a
// separate argument of [CaseShow]; the embedded options keep their own tags.
type caseShowInput struct {
	Case string `jb:"case" required:"true" desc:"The case directory (docs/CASE-SPEC.md)."`
	CaseShowOptions
}

type caseCheckInput struct {
	Case string `jb:"case" required:"true" desc:"The case directory (docs/CASE-SPEC.md)."`
}

// registry builds the registered operations. It builds afresh on every call, so a
// caller that edits what [Operations] returns changes nothing for the next caller.
func registry() []registered {
	return []registered{
		register("case_show", "Show a case config",
			"Describe what one config of a case would run: sources (type, URL without query, index, the name of the credential variable), detectors, the store path and the alert sinks. Reads no environment variable, makes no connection and opens no store.",
			true, ops.CLI{Command: []string{"case", "show"}},
			func(_ context.Context, in caseShowInput, _ Env) (any, error) {
				r, err := CaseShow(in.Case, in.CaseShowOptions)
				if err != nil {
					return nil, err
				}
				return r, nil
			}),
		register("case_check", "Check a case",
			"Validate a case: case.yaml, the evidence git guard, every actor file, every listed config and the case files its detectors name. A problem in the case is in the result (ok is false), not an error. Reads no credential.",
			true, ops.CLI{Command: []string{"case", "check"}},
			func(_ context.Context, in caseCheckInput, _ Env) (any, error) {
				r, err := CaseCheck(in.Case)
				if err != nil {
					return nil, err
				}
				return r, nil
			}),
	}
}

// Operations returns the definition of every operation, in a fixed order. Only case_show
// and case_check are registered so far (RFC 0010, step 2). The result is a copy.
func Operations() []Operation {
	reg := registry()
	out := make([]Operation, len(reg))
	for i, r := range reg {
		out[i] = r.op
	}
	return out
}

// Call checks arguments against the named operation's schema and runs its handler. It
// is the one entry the command line and an MCP server share. Arguments that fail the
// check, and an unknown name, are a [UsageError] that lists every problem; nothing runs.
// The check never fills a default: the handler applies them. env is passed to handlers
// that read credentials; nil reads the process environment. The result is the value
// the typed function returns (for example *[CaseShowResult]), the same object that
// `--output json` prints. A result that says the work is incomplete is still a result.
func Call(ctx context.Context, name string, arguments map[string]any, env Env) (any, error) {
	for _, r := range registry() {
		if r.op.Name != name {
			continue
		}
		if ps := ops.Check(r.op.InputSchema, arguments); len(ps) != 0 {
			return nil, usagef("invalid arguments for %s: %s", name, ops.Describe(ps))
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return r.run(ctx, arguments, env)
	}
	return nil, usagef("unknown operation %q", name)
}
