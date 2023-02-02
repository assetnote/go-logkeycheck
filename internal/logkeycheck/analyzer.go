package logkeycheck

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

var (
	snakeCaseRE = regexp.MustCompile("^[a-z]+(_[a-z]+)*$")

	// List of all packages containing funcs to analyze.
	pkgs = map[string]struct{}{
		"github.com/planetscale/log":                 {},
		"go.uber.org/zap":                            {},
		"github.com/assetnote/cs-core-go/v2/pkg/log": {},
	}

	// TODO: convert to struct
	// list of all zap funcs we are interested in analyzing.
	funcs = map[string]struct{}{
		"Any":         {},
		"Array":       {},
		"Binary":      {},
		"Bool":        {},
		"Boolp":       {},
		"Bools":       {},
		"ByteString":  {},
		"ByteStrings": {},
		"Complex128":  {},
		"Complex128p": {},
		"Complex128s": {},
		"Complex64":   {},
		"Complex64p":  {},
		"Complex64s":  {},
		"Duration":    {},
		"Durationp":   {},
		"Durations":   {},
		"Errors":      {},
		"Float32":     {},
		"Float32p":    {},
		"Float32s":    {},
		"Float64":     {},
		"Float64p":    {},
		"Float64s":    {},
		"Inline":      {},
		"Int":         {},
		"Int16":       {},
		"Int16p":      {},
		"Int16s":      {},
		"Int32":       {},
		"Int32p":      {},
		"Int32s":      {},
		"Int64":       {},
		"Int64p":      {},
		"Int64s":      {},
		"Int8":        {},
		"Int8p":       {},
		"Int8s":       {},
		"Intp":        {},
		"Ints":        {},
		"NamedError":  {},
		"Namespace":   {},
		"Object":      {},
		"Reflect":     {},
		"Skip":        {},
		"Stack":       {},
		"StackSkip":   {},
		"String":      {},
		"Stringer":    {},
		"Stringp":     {},
		"Strings":     {},
		"Time":        {},
		"Timep":       {},
		"Times":       {},
		"Uint":        {},
		"Uint16":      {},
		"Uint16p":     {},
		"Uint16s":     {},
		"Uint32":      {},
		"Uint32p":     {},
		"Uint32s":     {},
		"Uint64":      {},
		"Uint64p":     {},
		"Uint64s":     {},
		"Uint8":       {},
		"Uint8p":      {},
		"Uint8s":      {},
		"Uintp":       {},
		"Uintptr":     {},
		"Uintptrp":    {},
		"Uintptrs":    {},
		"Uints":       {},
	}
)

var Analyzer = &analysis.Analyzer{
	Name:     "logkeycheck",
	Doc:      "Checks that log keys are properly formatted",
	Run:      run,
	Requires: []*analysis.Analyzer{inspect.Analyzer, PreAnalyzer},
}

var PreAnalyzer = &analysis.Analyzer{
	Name:     "logkey-precheck",
	Doc:      "Aggregates the types for all the log keys so on analysis it has enough information",
	Run:      prerun,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
}

// needs to be global so all the types across all packages are made consistent
var kt = newKeyTypes()

// prerun will only analyze the types of all the log keys and store them in the global
// the run will then use this global to check the log keys
func prerun(pass *analysis.Pass) (interface{}, error) {
	// pass.ResultOf[inspect.Analyzer] will be set if we've added inspect.Analyzer to Requires.
	inspector := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	nodeFilter := []ast.Node{ // filter needed nodes: visit only them
		(*ast.CallExpr)(nil),
	}

	inspector.Preorder(nodeFilter, func(node ast.Node) {
		call := node.(*ast.CallExpr)

		// all of the funcs we're interested in have at least 2 args
		if len(call.Args) < 2 {
			return
		}

		fun, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}
		pkg := pass.TypesInfo.Uses[fun.Sel].Pkg()

		// only interested in funcs from these packages:
		// Use .Path() to match against the fully qualified package name in case the import has been aliased.
		if _, ok := pkgs[pkg.Path()]; !ok {
			return
		}

		// only interested in these funcs:
		if _, ok := funcs[fun.Sel.Name]; !ok {
			return
		}

		// the first argument must be a string
		firstArg, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return
		}
		if firstArg.Kind != token.STRING {
			return
		}

		// remove double quotes around the arg string
		trimmed := firstArg.Value[1 : len(firstArg.Value)-1]
		if trimmed == "" {
			return
		}

		_ = kt.Add(Key(trimmed), KeyType(fun.Sel.Name))
	})

	return nil, nil
}

func run(pass *analysis.Pass) (interface{}, error) {
	// pass.ResultOf[inspect.Analyzer] will be set if we've added inspect.Analyzer to Requires.
	inspector := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	nodeFilter := []ast.Node{ // filter needed nodes: visit only them
		(*ast.CallExpr)(nil),
	}

	inspector.Preorder(nodeFilter, func(node ast.Node) {
		call := node.(*ast.CallExpr)

		// all of the funcs we're interested in have at least 2 args
		if len(call.Args) < 2 {
			return
		}

		fun, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}
		pkg := pass.TypesInfo.Uses[fun.Sel].Pkg()

		// only interested in funcs from these packages:
		// Use .Path() to match against the fully qualified package name in case the import has been aliased.
		if _, ok := pkgs[pkg.Path()]; !ok {
			return
		}

		// only interested in these funcs:
		if _, ok := funcs[fun.Sel.Name]; !ok {
			return
		}

		// the first argument must be a string
		firstArg, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return
		}
		if firstArg.Kind != token.STRING {
			return
		}

		// remove double quotes around the arg string
		trimmed := firstArg.Value[1 : len(firstArg.Value)-1]
		if trimmed == "" {
			return
		}
		if v := kt.Get(Key(trimmed)); v.HasCollision() {
			pass.Report(analysis.Diagnostic{
				Pos:            firstArg.Pos(),
				End:            firstArg.End(),
				Category:       "logging",
				Message:        fmt.Sprintf("log key '%s' has conflicting types: %s", trimmed, v.String()),
				SuggestedFixes: nil,
			})
		}

		if fun.Sel.Name == "Any" {
			pass.Report(analysis.Diagnostic{
				Pos:            firstArg.Pos(),
				End:            firstArg.End(),
				Category:       "logging",
				Message:        fmt.Sprintf("log key '%s' has untyped any", trimmed),
				SuggestedFixes: nil,
			})
		}

		if !snakeCaseRE.MatchString(trimmed) {
			pass.Report(analysis.Diagnostic{
				Pos:            firstArg.Pos(),
				End:            firstArg.End(),
				Category:       "logging",
				Message:        fmt.Sprintf("log key '%s' should be snake_case.", trimmed),
				SuggestedFixes: nil,
			})
		}
	})

	return nil, nil
}

// some types to make interacting with our map type safe
type Key string
type KeyType string
type KeyTypes struct {
	m  map[Key]TypeCount
	mu sync.Mutex
}

func newKeyTypes() *KeyTypes {
	return &KeyTypes{m: map[Key]TypeCount{}}
}

func (k *KeyTypes) Add(key Key, t KeyType) TypeCount {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.m[key]; !ok {
		k.m[key] = map[KeyType]int{}
	}
	k.m[key][t]++
	return k.m[key]
}

func (k *KeyTypes) Get(key Key) TypeCount {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.m[key]
}

type TypeCount map[KeyType]int

func (c *TypeCount) String() string {
	var b strings.Builder
	for k, v := range *c {
		b.WriteString(fmt.Sprintf("%s: %d, ", k, v))
	}
	return b.String()
}

func (c TypeCount) HasCollision() bool {
	return len(c) > 1
}
