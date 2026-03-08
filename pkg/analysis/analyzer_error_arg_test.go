package analysis

import (
	"path/filepath"
	"testing"

	"github.com/Yeah114/GoSpy/pkg/loader"
	"github.com/Yeah114/GoSpy/pkg/symbols"
)

func TestRecoverErrorfWrappedArgFromGlobalObject(t *testing.T) {
	binPath := filepath.Join("..", "..", "example", "2", "main")
	bin, err := loader.Load(binPath)
	if err != nil {
		t.Fatalf("load sample binary: %v", err)
	}
	tab, err := symbols.Build(bin)
	if err != nil {
		t.Fatalf("build symbols: %v", err)
	}

	var target *symbols.Func
	for _, fn := range tab.Funcs {
		if fn.Name == "main.NewPerson" {
			target = fn
			break
		}
	}
	if target == nil {
		t.Fatalf("main.NewPerson not found")
	}

	a := New(bin, tab)
	ir, err := a.AnalyzeFunc(target)
	if err != nil {
		t.Fatalf("analyze function: %v", err)
	}

	var got string
	var walk func([]*Stmt)
	walk = func(stmts []*Stmt) {
		for _, s := range stmts {
			switch s.Kind {
			case StmtCall:
				if s.Call == nil || s.Call.Func != "fmt.Errorf" || len(s.Call.Args) < 3 {
					continue
				}
				if lit, ok := s.Call.Args[0].(*StringLit); ok && lit.Value == "person %q: %w" {
					got = s.Call.Args[2].GoString()
				}
			case StmtIf:
				if s.If != nil {
					walk(s.If.Then)
					walk(s.If.Else)
				}
			case StmtFor:
				if s.For != nil {
					walk(s.For.Body)
				}
			}
		}
	}
	walk(ir.Stmts)

	want := `fmt.Errorf("age must be between 0 and 150")`
	if got != want {
		t.Fatalf("unexpected wrapped error arg: got %q want %q", got, want)
	}
}
