// Package ops defines an operation once, from the Go option struct that a caller of
// the library already uses (RFC 0010). It holds the operation type, the reflector that
// turns tagged struct fields into an input schema, the one check of an arguments object
// against that schema, the MCP tool projection and the step that decodes checked
// arguments back into a struct. It depends on the standard library only.
package ops

import (
	"fmt"
	"regexp"
	"strings"
)

// Operation is one operation as the RFC defines it. It marshals to the JSON shape of
// RFC 0010 "An operation". There is no output schema in this cut.
type Operation struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description"`
	InputSchema Schema `json:"inputSchema"`
	ReadOnly    bool   `json:"readOnly"`
	CLI         *CLI   `json:"cli,omitempty"`
	// ToolFixed names properties that an MCP tool does not offer and that every tool
	// call runs with the value given here. hunt and activity fix store to false, so the
	// tool provably leaves no evidence (RFC 0010, "Operations"). The command line and
	// the Go API still offer the property.
	ToolFixed map[string]any `json:"toolFixed,omitempty"`
}

// CLI says how the command line reaches an operation.
type CLI struct {
	// Command is the words of the command, for example ["case", "show"].
	Command []string `json:"command"`
	// Positional names the properties filled from arguments, in order. Only the last
	// may be an array.
	Positional []string `json:"positional,omitempty"`
	// Only names the properties that the command line accepts and a tool call does not.
	Only []string `json:"only,omitempty"`
}

// Schema is the deliberately small subset of JSON Schema that an input may use.
type Schema struct {
	Type                 string              `json:"type"`
	AdditionalProperties bool                `json:"additionalProperties"`
	Properties           map[string]Property `json:"properties"`
	Required             []string            `json:"required"`
}

// Property is one argument. Its Type is one of string, integer, boolean and array.
type Property struct {
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Default     any      `json:"default,omitempty"`
	Enum        []string `json:"enum,omitempty"`
	Minimum     *int64   `json:"minimum,omitempty"`
	Maximum     *int64   `json:"maximum,omitempty"`
	Items       *Items   `json:"items,omitempty"`
}

// Items is the element schema of an array property. It is always {"type": "string"}.
type Items struct {
	Type string `json:"type"`
}

// Problem is one thing wrong, with a stable code and a reference to where.
type Problem struct {
	Code    string `json:"code"`
	Ref     string `json:"ref"`
	Message string `json:"message"`
}

func (p Problem) String() string { return fmt.Sprintf("%s %s: %s", p.Code, p.Ref, p.Message) }

// Describe joins problems into one line, in order.
func Describe(ps []Problem) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, "; ")
}

var (
	operationName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	propertyName  = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)
	commandWord   = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

func validPropertyName(n string) bool {
	return propertyName.MatchString(n) && !strings.HasPrefix(n, "no_") && n != "help"
}

// Validate checks one operation against the rules of RFC 0010 and returns every
// problem. jb runs it over its own registry in a test.
func Validate(op Operation) []Problem {
	var ps []Problem
	add := func(code, ref, format string, a ...any) {
		ps = append(ps, Problem{Code: code, Ref: ref, Message: fmt.Sprintf(format, a...)})
	}
	if !operationName.MatchString(op.Name) {
		add("operation-name", op.Name, "must match %s", operationName)
	}
	ref := op.Name
	if strings.TrimSpace(op.Description) == "" {
		add("operation-description", ref, "must be a non-empty string")
	}
	s := op.InputSchema
	if s.Type != "object" {
		add("schema-type", ref, "inputSchema type must be \"object\", got %q", s.Type)
	}
	if s.AdditionalProperties {
		add("schema-additional", ref, "additionalProperties must be false")
	}
	if s.Properties == nil || s.Required == nil {
		add("schema-shape", ref, "properties and required must be present (an empty object or list, not null)")
	}
	for _, name := range sortedKeys(s.Properties) {
		p := s.Properties[name]
		pref := ref + "." + name
		if !validPropertyName(name) {
			add("property-name", pref, "must be lower case words joined by _, not start with no_ and not be help")
		}
		switch p.Type {
		case "string":
			if p.Minimum != nil || p.Maximum != nil || p.Items != nil {
				add("property-keyword", pref, "a string takes enum only")
			}
			seen := map[string]bool{}
			for _, e := range p.Enum {
				if seen[e] {
					add("enum-duplicate", pref, "enum value %q is repeated", e)
				}
				seen[e] = true
			}
			if p.Enum != nil && len(p.Enum) == 0 {
				add("enum-empty", pref, "enum must not be empty")
			}
		case "integer":
			if p.Enum != nil || p.Items != nil {
				add("property-keyword", pref, "an integer takes minimum and maximum only")
			}
			if p.Minimum != nil && p.Maximum != nil && *p.Minimum > *p.Maximum {
				add("range-invalid", pref, "minimum %d is above maximum %d", *p.Minimum, *p.Maximum)
			}
		case "boolean":
			if p.Enum != nil || p.Minimum != nil || p.Maximum != nil || p.Items != nil {
				add("property-keyword", pref, "a boolean takes no keyword")
			}
		case "array":
			if p.Items == nil || p.Items.Type != "string" {
				add("array-items", pref, "items must be exactly {\"type\": \"string\"}")
			}
			if p.Enum != nil || p.Minimum != nil || p.Maximum != nil {
				add("property-keyword", pref, "an array takes items only")
			}
		default:
			add("property-type", pref, "type %q is not string, integer, boolean or array", p.Type)
		}
		if p.Default != nil && !defaultFits(p) {
			add("default-type", pref, "default %v does not fit type %s and its limits", p.Default, p.Type)
		}
	}
	reqSeen := map[string]bool{}
	for _, r := range s.Required {
		if _, ok := s.Properties[r]; !ok {
			add("required-unknown", ref+"."+r, "required names no property")
		}
		if reqSeen[r] {
			add("required-duplicate", ref+"."+r, "required lists it twice")
		}
		reqSeen[r] = true
	}
	for _, n := range sortedKeys(op.ToolFixed) {
		p, ok := s.Properties[n]
		if !ok {
			add("tool-fixed-unknown", ref+"."+n, "toolFixed names no property")
			continue
		}
		q := p
		q.Default = op.ToolFixed[n]
		if !defaultFits(q) {
			add("tool-fixed-type", ref+"."+n, "toolFixed value %v does not fit type %s and its limits", op.ToolFixed[n], p.Type)
		}
	}
	if op.CLI != nil {
		validateCLI(op, add)
	}
	return ps
}

func validateCLI(op Operation, add func(code, ref, format string, a ...any)) {
	c := op.CLI
	if len(c.Command) == 0 {
		add("cli-command", op.Name, "cli.command needs at least one word")
	}
	for _, w := range c.Command {
		if !commandWord.MatchString(w) {
			add("cli-command", op.Name, "command word %q must be lower case letters, digits and -", w)
		}
	}
	for i, n := range c.Positional {
		p, ok := op.InputSchema.Properties[n]
		if !ok {
			add("cli-positional-unknown", op.Name+"."+n, "positional names no property")
			continue
		}
		if p.Type == "array" && i != len(c.Positional)-1 {
			add("cli-positional-array", op.Name+"."+n, "only the last positional may be an array")
		}
	}
	for _, n := range c.Only {
		if _, ok := op.InputSchema.Properties[n]; !ok {
			add("cli-only-unknown", op.Name+"."+n, "cli.only names no property")
		}
	}
}

// ValidateAll validates every operation and that the names are unique.
func ValidateAll(list []Operation) []Problem {
	var ps []Problem
	seen := map[string]bool{}
	for _, op := range list {
		if seen[op.Name] {
			ps = append(ps, Problem{Code: "operation-duplicate", Ref: op.Name, Message: "name is used twice"})
		}
		seen[op.Name] = true
		ps = append(ps, Validate(op)...)
	}
	return ps
}

// defaultFits reports whether the default value has the type of the property and sits
// inside its enum and range. A decoded JSON number is a float64.
func defaultFits(p Property) bool {
	switch p.Type {
	case "string":
		s, ok := p.Default.(string)
		if !ok {
			return false
		}
		return p.Enum == nil || contains(p.Enum, s)
	case "boolean":
		_, ok := p.Default.(bool)
		return ok
	case "integer":
		n, ok := asInt(p.Default)
		if !ok {
			return false
		}
		return (p.Minimum == nil || n >= *p.Minimum) && (p.Maximum == nil || n <= *p.Maximum)
	case "array":
		_, ok := asStrings(p.Default)
		return ok
	}
	return false
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}
