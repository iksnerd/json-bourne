package jb

// The surface golden (RFC 0017, step 1).
//
// TestAPISurface walks the exported API of package jb and of package sdk with
// go/types, loaded from source, and compares the result with testdata/api/jb.txt and
// testdata/api/sdk.txt. A deliberate change is made by running
//
//	go test -count=1 ./jb -run TestAPISurface -update-api
//
// and reading the diff. The golden is written only through -update-api.
//
// What the walk records, sorted and without comments or absolute paths:
//   - one line per exported identifier (const, var, func, type, alias);
//   - for every named type reached, one line for the type, one line per exported
//     field in order with its tag, and one line per exported method (receiver kind,
//     name, signature);
//   - aliases are expanded to their target (types.Unalias at every level), so a change
//     in an internal type shows in the diff.
//
// Named types are followed one at a time until closure, from any exported signature,
// field or method. Only types of this module are followed. Types of the standard
// library and of other modules appear by name only: their shape belongs to the
// toolchain, not to this repository, and would make the golden depend on the Go
// version of the machine.
//
// The /internal/ rule: a type declared under /internal/ that is reachable from the
// surface is a leak. testdata/api/known-leaks.txt lists the leaks that exist today.
// A new leak fails the test, and so does an entry that no longer leaks, so the list
// only shrinks. Package sdk must have none.

import (
	"flag"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

var updateAPI = flag.Bool("update-api", false, "rewrite testdata/api/jb.txt and testdata/api/sdk.txt")

const apiModulePrefix = "github.com/iksnerd/json-bourne"

type apiLine struct{ key, text string }

type apiWalker struct {
	lines  []apiLine
	seen   map[*types.TypeName]bool
	queue  []*types.Named
	leaks  map[string]bool
	prefix string
}

func (w *apiWalker) ownModule(pkg *types.Package) bool {
	if pkg == nil {
		return false
	}
	p := pkg.Path()
	return p == w.prefix || strings.HasPrefix(p, w.prefix+"/")
}

// ts writes a type with full package paths, expanding aliases at every level, and
// queues every named type of this module that it meets.
func (w *apiWalker) ts(t types.Type) string {
	t = types.Unalias(t)
	switch t := t.(type) {
	case *types.Basic:
		return t.Name()
	case *types.Named:
		o := t.Origin().Obj()
		name := o.Name()
		if o.Pkg() != nil {
			name = o.Pkg().Path() + "." + name
			if w.ownModule(o.Pkg()) {
				w.enqueue(t.Origin())
			}
			if strings.Contains(o.Pkg().Path(), "/internal/") {
				w.leaks[name] = true
			}
		}
		if ta := t.TypeArgs(); ta != nil && ta.Len() > 0 {
			var as []string
			for i := 0; i < ta.Len(); i++ {
				as = append(as, w.ts(ta.At(i)))
			}
			name += "[" + strings.Join(as, ", ") + "]"
		}
		return name
	case *types.Pointer:
		return "*" + w.ts(t.Elem())
	case *types.Slice:
		return "[]" + w.ts(t.Elem())
	case *types.Array:
		return "[" + strconv.FormatInt(t.Len(), 10) + "]" + w.ts(t.Elem())
	case *types.Map:
		return "map[" + w.ts(t.Key()) + "]" + w.ts(t.Elem())
	case *types.Chan:
		switch t.Dir() {
		case types.SendOnly:
			return "chan<- " + w.ts(t.Elem())
		case types.RecvOnly:
			return "<-chan " + w.ts(t.Elem())
		}
		return "chan " + w.ts(t.Elem())
	case *types.Signature:
		return "func" + w.sig(t)
	case *types.Struct:
		var fs []string
		for i := 0; i < t.NumFields(); i++ {
			f := t.Field(i)
			s := f.Name() + " " + w.ts(f.Type())
			if f.Embedded() {
				s = "embed " + w.ts(f.Type())
			}
			if tag := t.Tag(i); tag != "" {
				s += " " + strconv.Quote(tag)
			}
			fs = append(fs, s)
		}
		return "struct{" + strings.Join(fs, "; ") + "}"
	case *types.Interface:
		var ms []string
		for i := 0; i < t.NumExplicitMethods(); i++ {
			m := t.ExplicitMethod(i)
			ms = append(ms, m.Name()+w.sig(m.Type().(*types.Signature)))
		}
		sort.Strings(ms)
		for i := 0; i < t.NumEmbeddeds(); i++ {
			ms = append(ms, "embed "+w.ts(t.EmbeddedType(i)))
		}
		if len(ms) == 0 {
			return "any"
		}
		return "interface{" + strings.Join(ms, "; ") + "}"
	case *types.Union:
		var us []string
		for i := 0; i < t.Len(); i++ {
			s := w.ts(t.Term(i).Type())
			if t.Term(i).Tilde() {
				s = "~" + s
			}
			us = append(us, s)
		}
		return strings.Join(us, " | ")
	case *types.TypeParam:
		return t.Obj().Name()
	case *types.Tuple:
		return w.tuple(t, false)
	}
	return types.TypeString(t, func(p *types.Package) string { return p.Path() })
}

func (w *apiWalker) tuple(t *types.Tuple, variadic bool) string {
	var ps []string
	for i := 0; i < t.Len(); i++ {
		ty := t.At(i).Type()
		if variadic && i == t.Len()-1 {
			ps = append(ps, "..."+w.ts(ty.(*types.Slice).Elem()))
			continue
		}
		ps = append(ps, w.ts(ty))
	}
	return strings.Join(ps, ", ")
}

// sig writes parameters and results without parameter names, which are not API.
func (w *apiWalker) sig(s *types.Signature) string {
	var tp string
	if l := s.TypeParams(); l != nil && l.Len() > 0 {
		var ps []string
		for i := 0; i < l.Len(); i++ {
			ps = append(ps, l.At(i).Obj().Name()+" "+w.ts(l.At(i).Constraint()))
		}
		tp = "[" + strings.Join(ps, ", ") + "]"
	}
	out := tp + "(" + w.tuple(s.Params(), s.Variadic()) + ")"
	switch s.Results().Len() {
	case 0:
	case 1:
		out += " " + w.ts(s.Results().At(0).Type())
	default:
		out += " (" + w.tuple(s.Results(), false) + ")"
	}
	return out
}

func (w *apiWalker) enqueue(n *types.Named) {
	if w.seen[n.Obj()] {
		return
	}
	w.seen[n.Obj()] = true
	w.queue = append(w.queue, n)
}

func (w *apiWalker) add(key, text string) { w.lines = append(w.lines, apiLine{key, text}) }

// walkType writes the type, its exported fields in order and its exported methods.
func (w *apiWalker) walkType(n *types.Named) {
	name := n.Obj().Pkg().Path() + "." + n.Obj().Name()
	key := "1:" + name + "\x00"
	hdr := "type " + name
	if tp := n.TypeParams(); tp != nil && tp.Len() > 0 {
		var ps []string
		for i := 0; i < tp.Len(); i++ {
			ps = append(ps, tp.At(i).Obj().Name()+" "+w.ts(tp.At(i).Constraint()))
		}
		hdr += "[" + strings.Join(ps, ", ") + "]"
	}
	switch u := n.Underlying().(type) {
	case *types.Struct:
		w.add(key+"a", hdr+" struct")
		for i := 0; i < u.NumFields(); i++ {
			f := u.Field(i)
			if !f.Exported() {
				continue
			}
			s := fmt.Sprintf("field %s#%03d %s %s", name, i, f.Name(), w.ts(f.Type()))
			if f.Embedded() {
				s += " (embedded)"
			}
			if tag := u.Tag(i); tag != "" {
				s += " " + strconv.Quote(tag)
			}
			w.add(key+"b"+fmt.Sprintf("%03d", i), s)
		}
	case *types.Interface:
		w.add(key+"a", hdr+" "+w.ts(u))
	default:
		w.add(key+"a", hdr+" "+w.ts(u))
	}
	if _, isIface := n.Underlying().(*types.Interface); isIface {
		return
	}
	ms := types.NewMethodSet(types.NewPointer(n))
	for i := 0; i < ms.Len(); i++ {
		m := ms.At(i).Obj().(*types.Func)
		if !m.Exported() {
			continue
		}
		sig := m.Type().(*types.Signature)
		recv := "value"
		if _, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer); ptr {
			recv = "pointer"
		}
		w.add(key+"c"+m.Name(), "method "+name+" "+recv+" "+m.Name()+w.sig(sig))
	}
}

// apiSurface returns the golden text for the package and the internal types it leaks.
func apiSurface(t *testing.T, pattern string) (string, []string) {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo,
		Fset:  token.NewFileSet(),
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || len(pkgs[0].Errors) > 0 {
		t.Fatalf("loading %s: %d packages, errors %v", pattern, len(pkgs), pkgs[0].Errors)
	}
	pkg := pkgs[0].Types
	w := &apiWalker{seen: map[*types.TypeName]bool{}, leaks: map[string]bool{}, prefix: apiModulePrefix}
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		o := scope.Lookup(name)
		if !o.Exported() {
			continue
		}
		q := pkg.Path() + "." + name
		key := "0:" + q
		switch o := o.(type) {
		case *types.Const:
			w.add(key, "const "+q+" "+w.ts(o.Type())+" = "+o.Val().ExactString())
		case *types.Var:
			w.add(key, "var "+q+" "+w.ts(o.Type()))
		case *types.Func:
			w.add(key, "func "+q+w.sig(o.Type().(*types.Signature)))
		case *types.TypeName:
			if o.IsAlias() {
				w.add(key, "alias "+q+" = "+w.ts(o.Type()))
			} else {
				w.add(key, "type "+q)
				w.ts(o.Type())
			}
		}
	}
	for len(w.queue) > 0 {
		n := w.queue[0]
		w.queue = w.queue[1:]
		w.walkType(n)
	}
	sort.SliceStable(w.lines, func(i, j int) bool { return w.lines[i].key < w.lines[j].key })
	var b strings.Builder
	for _, l := range w.lines {
		b.WriteString(l.text + "\n")
	}
	var leaks []string
	for l := range w.leaks {
		leaks = append(leaks, l)
	}
	sort.Strings(leaks)
	return b.String(), leaks
}

func readKnownLeaks(t *testing.T) map[string]bool {
	t.Helper()
	data, err := os.ReadFile("testdata/api/known-leaks.txt")
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]bool{}
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		m[l] = true
	}
	return m
}

func TestAPISurface(t *testing.T) {
	for _, c := range []struct{ pattern, file string }{
		{".", "testdata/api/jb.txt"},
		{"../sdk", "testdata/api/sdk.txt"},
	} {
		t.Run(c.file, func(t *testing.T) {
			got, leaks := apiSurface(t, c.pattern)
			if *updateAPI {
				if err := os.WriteFile(c.file, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			} else {
				want, err := os.ReadFile(c.file)
				if err != nil {
					t.Fatal(err)
				}
				if got != string(want) {
					t.Errorf("exported API differs from %s (rerun with -update-api if the change is deliberate)\n%s",
						c.file, apiFirstDiff(string(want), got))
				}
			}
			known := map[string]bool{}
			if c.pattern == "." {
				known = readKnownLeaks(t)
			}
			have := map[string]bool{}
			for _, l := range leaks {
				have[l] = true
				if !known[l] {
					t.Errorf("new /internal/ type reachable from the public API: %s\n"+
						"  a public type MUST NOT expose a type under /internal/ (RFC 0017); "+
						"do not add it to testdata/api/known-leaks.txt, define it in the public package", l)
				}
			}
			for l := range known {
				if !have[l] {
					t.Errorf("testdata/api/known-leaks.txt lists %s, which no longer leaks: remove that line (the list only shrinks)", l)
				}
			}
		})
	}
}

func apiFirstDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var a, b string
		if i < len(w) {
			a = w[i]
		}
		if i < len(g) {
			b = g[i]
		}
		if a != b {
			return fmt.Sprintf("first difference at line %d\n  want: %s\n  got:  %s", i+1, a, b)
		}
	}
	return ""
}
