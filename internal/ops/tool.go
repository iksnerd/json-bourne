package ops

import "slices"

// ToolEntry is one entry of an MCP tools/list result: the operation without cli and
// without the properties that only the command line accepts, plus annotations derived
// from ReadOnly. There is no outputSchema in this cut.
type ToolEntry struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description"`
	InputSchema Schema          `json:"inputSchema"`
	Annotations ToolAnnotations `json:"annotations"`
}

// ToolAnnotations are MCP's behaviour hints. A read-only operation is not destructive;
// any other is treated as destructive, the safe reading for a client.
type ToolAnnotations struct {
	ReadOnlyHint    bool `json:"readOnlyHint"`
	DestructiveHint bool `json:"destructiveHint"`
}

// Tool projects an operation to its MCP tool entry. It copies; the operation is not
// changed and shares nothing with the entry.
func Tool(op Operation) ToolEntry {
	var only []string
	if op.CLI != nil {
		only = op.CLI.Only
	}
	s := Schema{
		Type:                 op.InputSchema.Type,
		AdditionalProperties: op.InputSchema.AdditionalProperties,
		Properties:           map[string]Property{},
		Required:             []string{},
	}
	for name, p := range op.InputSchema.Properties {
		if slices.Contains(only, name) {
			continue
		}
		s.Properties[name] = cloneProperty(p)
	}
	for _, r := range op.InputSchema.Required {
		if !slices.Contains(only, r) {
			s.Required = append(s.Required, r)
		}
	}
	return ToolEntry{
		Name: op.Name, Title: op.Title, Description: op.Description, InputSchema: s,
		Annotations: ToolAnnotations{ReadOnlyHint: op.ReadOnly, DestructiveHint: !op.ReadOnly},
	}
}

func cloneProperty(p Property) Property {
	p.Enum = slices.Clone(p.Enum)
	if p.Minimum != nil {
		n := *p.Minimum
		p.Minimum = &n
	}
	if p.Maximum != nil {
		n := *p.Maximum
		p.Maximum = &n
	}
	if p.Items != nil {
		i := *p.Items
		p.Items = &i
	}
	if d, ok := p.Default.([]string); ok {
		p.Default = slices.Clone(d)
	}
	return p
}
