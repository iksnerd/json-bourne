package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
)

// opFlags is the flag builder of RFC 0010. It registers one cobra flag per property of
// an operation, with the type, default and help text the operation gives, so a command
// built from it cannot drift from the operation its Go function and its MCP tool share.
//
// The mapping of a property to a flag:
//
//	string   --name VALUE           (a name's _ becomes -)
//	integer  --name N
//	boolean  --name                 (the cobra boolean form: --name, --name=false)
//	array    --name VALUE, repeated (a StringArray flag, so a comma is part of a value)
//
// A property named in cli.positional is not a flag: its value is an argument. If the
// last positional is an array, it takes all remaining arguments, so `jb intel 192.0.2.1
// 192.0.2.2` fills ips. --output is the command line's own, not a property; the command
// registers it itself.
type opFlags struct {
	op    jb.Operation
	cmd   *cobra.Command
	strs  map[string]*string
	ints  map[string]*int
	bools map[string]*bool
	arrs  map[string]*[]string
}

// mustOperation returns the registered operation or panics: a command that names an
// operation that does not exist is a programming error, found by the first test run.
func mustOperation(name string) jb.Operation {
	for _, op := range jb.Operations() {
		if op.Name == name {
			return op
		}
	}
	panic("cmd/jb: no operation " + name)
}

// flagName is the flag of a property: its name with each _ replaced by -.
func flagName(property string) string { return strings.ReplaceAll(property, "_", "-") }

// addOperationFlags registers the flags of the named operation on cmd.
func addOperationFlags(cmd *cobra.Command, operation string) *opFlags {
	o := &opFlags{op: mustOperation(operation), cmd: cmd,
		strs: map[string]*string{}, ints: map[string]*int{}, bools: map[string]*bool{}, arrs: map[string]*[]string{}}
	positional := []string{}
	if o.op.CLI != nil {
		positional = o.op.CLI.Positional
	}
	names := make([]string, 0, len(o.op.InputSchema.Properties))
	for n := range o.op.InputSchema.Properties {
		if !slices.Contains(positional, n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	f := cmd.Flags()
	for _, n := range names {
		p := o.op.InputSchema.Properties[n]
		switch p.Type {
		case "string":
			d, _ := p.Default.(string)
			o.strs[n] = f.String(flagName(n), d, p.Description)
		case "integer":
			o.ints[n] = f.Int(flagName(n), defaultInt(p.Default), p.Description)
		case "boolean":
			d, _ := p.Default.(bool)
			o.bools[n] = f.Bool(flagName(n), d, p.Description)
		case "array":
			d, _ := p.Default.([]string)
			o.arrs[n] = f.StringArray(flagName(n), slices.Clone(d), p.Description)
		default:
			panic(fmt.Sprintf("cmd/jb: operation %s: property %s has type %s", operation, n, p.Type))
		}
	}
	return o
}

func defaultInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

// String, Int, Bool and Strings return the value of a flag by its property name.
func (o *opFlags) String(property string) string    { return *o.strs[property] }
func (o *opFlags) Int(property string) int          { return *o.ints[property] }
func (o *opFlags) Bool(property string) bool        { return *o.bools[property] }
func (o *opFlags) Strings(property string) []string { return *o.arrs[property] }

// Changed reports whether the flag of the property was given on the command line.
func (o *opFlags) Changed(property string) bool { return o.cmd.Flags().Changed(flagName(property)) }

// PositionalArgs checks the arguments against cli.positional: one argument for each
// scalar, and for a last array any number. A wrong count is a usage error.
func (o *opFlags) PositionalArgs() cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		_, err := o.positionals(args)
		return err
	}
}

// positionals maps the arguments to the properties named in cli.positional.
func (o *opFlags) positionals(args []string) (map[string]any, error) {
	out := map[string]any{}
	var names []string
	if o.op.CLI != nil {
		names = o.op.CLI.Positional
	}
	rest := args
	for i, n := range names {
		if o.op.InputSchema.Properties[n].Type == "array" && i == len(names)-1 {
			if len(rest) > 0 {
				out[n] = slices.Clone(rest)
			}
			rest = nil
			break
		}
		if len(rest) == 0 {
			return nil, usageErrorf("missing argument %s (%s takes %s)", strings.ToUpper(n), o.cmd.CommandPath(), strings.ToUpper(strings.Join(names, " ")))
		}
		out[n], rest = rest[0], rest[1:]
	}
	if len(rest) > 0 {
		return nil, usageErrorf("unexpected argument %q (%s takes %d)", rest[0], o.cmd.CommandPath(), len(names))
	}
	return out, nil
}

// Arguments returns the arguments object of a call: every flag that was set and every
// positional, keyed by property. A flag that was not set is left out, so the handler
// applies its own default, as the one check expects (RFC 0010, "The input schema").
func (o *opFlags) Arguments(args []string) (map[string]any, error) {
	out, err := o.positionals(args)
	if err != nil {
		return nil, err
	}
	for n := range o.strs {
		if o.Changed(n) {
			out[n] = *o.strs[n]
		}
	}
	for n := range o.ints {
		if o.Changed(n) {
			out[n] = int64(*o.ints[n])
		}
	}
	for n := range o.bools {
		if o.Changed(n) {
			out[n] = *o.bools[n]
		}
	}
	for n := range o.arrs {
		if o.Changed(n) {
			out[n] = slices.Clone(*o.arrs[n])
		}
	}
	return out, nil
}
