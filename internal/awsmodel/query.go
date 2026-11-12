package awsmodel

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Key is a serialized EC2 query leaf; N marks a one-based list index.
type Key struct {
	Path     string
	Required bool // Only requirements on the operation's top-level members propagate.
	Type     string
}

// QueryKeys expands an operation's input using botocore's EC2Serializer spelling.
func (m *Model) QueryKeys(op string) ([]Key, error) {
	o, ok := m.OperationsByName[op]
	if !ok {
		return nil, fmt.Errorf("EC2 operation %q is absent from the model", op)
	}
	root, ok := m.Shapes[o.Input.Shape]
	if !ok {
		return nil, fmt.Errorf("EC2 operation %s: missing input shape %q", op, o.Input.Shape)
	}
	w := queryWalk{model: m, visiting: map[string]bool{o.Input.Shape: true}}
	for _, name := range slices.Sorted(maps.Keys(root.Members)) {
		ref := root.Members[name]
		key := Key{Path: queryName(name, ref), Required: slices.Contains(root.Required, name)}
		if err := w.expand(ref.Shape, key); err != nil {
			return nil, fmt.Errorf("EC2 operation %s: %w", op, err)
		}
	}
	slices.SortFunc(w.keys, func(a, b Key) int { return strings.Compare(a.Path, b.Path) })
	return w.keys, nil
}

type queryWalk struct {
	model    *Model
	visiting map[string]bool
	keys     []Key
}

func (w *queryWalk) expand(name string, key Key) error {
	if w.visiting[name] {
		return fmt.Errorf("recursive input shape %q at %s", name, key.Path)
	}
	s, ok := w.model.Shapes[name]
	if !ok {
		return fmt.Errorf("missing shape %q at %s", name, key.Path)
	}
	w.visiting[name] = true
	defer delete(w.visiting, name)
	switch s.Type {
	case "structure":
		for _, member := range slices.Sorted(maps.Keys(s.Members)) {
			ref := s.Members[member]
			child := Key{Path: key.Path + "." + queryName(member, ref), Required: key.Required}
			if err := w.expand(ref.Shape, child); err != nil {
				return fmt.Errorf("expand structure %s: %w", name, err)
			}
		}
	case "list":
		child := Key{Path: key.Path + ".N", Required: key.Required}
		if err := w.expand(s.Member.Shape, child); err != nil {
			return fmt.Errorf("expand list %s: %w", name, err)
		}
	case "string", "integer", "long", "float", "double", "boolean", "timestamp", "blob":
		key.Type = s.Type
		w.keys = append(w.keys, key)
	default:
		return fmt.Errorf("unsupported shape type %q at %s", s.Type, key.Path)
	}
	return nil
}

func queryName(name string, ref reference) string {
	if ref.QueryName != "" {
		return ref.QueryName
	}
	if ref.LocationName != "" {
		first, size := utf8.DecodeRuneInString(ref.LocationName)
		return string(unicode.ToUpper(first)) + ref.LocationName[size:]
	}
	return name
}
