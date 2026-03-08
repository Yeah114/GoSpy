package analysis

import (
	"testing"

	"github.com/Yeah114/GoSpy/pkg/symbols"
	"golang.org/x/arch/x86/x86asm"
)

func TestParseFmtVerbs(t *testing.T) {
	verbs := parseFmtVerbs("A=%s B=%08d C=%[2].2f %% D=%[1]q E=%*.*v")
	got := string(verbs)
	want := "sdfqv"
	if got != want {
		t.Fatalf("verbs mismatch: got %q want %q", got, want)
	}
}

func TestRecoverFmtArgsPreferConvCandidates(t *testing.T) {
	args := []Expr{&StringLit{Value: "Hi %s (%d)"}}
	conv := []Expr{
		&Ident{Name: "_prax0"},
		&Ident{Name: "_prax10"},
	}
	got := recoverFmtArgs(args, conv, nil)
	if len(got) != 3 {
		t.Fatalf("arg len mismatch: got %d want 3", len(got))
	}
	if got[1].GoString() != "_prax0" || got[2].GoString() != "_prax10" {
		t.Fatalf("unexpected recovered args: %s, %s", got[1].GoString(), got[2].GoString())
	}
}

func TestRecoverFmtArgsFallbackByVerb(t *testing.T) {
	args := []Expr{&StringLit{Value: "%s %.2f %t %w"}}
	got := recoverFmtArgs(args, nil, nil)
	if len(got) != 5 {
		t.Fatalf("arg len mismatch: got %d want 5", len(got))
	}
	wants := []string{`""`, "0.0", "false", "nil"}
	for i, want := range wants {
		if got[i+1].GoString() != want {
			t.Fatalf("arg[%d] mismatch: got %s want %s", i+1, got[i+1].GoString(), want)
		}
	}
}

func TestRecoverFmtArgsUseRegCandidates(t *testing.T) {
	args := []Expr{&StringLit{Value: "%q: %w"}, &Ident{Name: "arg0"}}
	reg := []Expr{&Ident{Name: "_g1234"}}
	got := recoverFmtArgs(args, nil, reg)
	if len(got) != 3 {
		t.Fatalf("arg len mismatch: got %d want 3", len(got))
	}
	if got[2].GoString() != "_g1234" {
		t.Fatalf("expected _g1234, got %s", got[2].GoString())
	}
}

func TestRecoverFmtArgsWithContextEmptyArgs(t *testing.T) {
	a := &Analyzer{}
	got := a.recoverFmtArgsWithContext(nil, nil, nil, 0)
	if len(got) != 0 {
		t.Fatalf("expected empty args, got %d", len(got))
	}
}

func TestRecoverFmtArgsWithContextReplaceNilWrappedError(t *testing.T) {
	a := &Analyzer{}
	args := []Expr{&StringLit{Value: "%w"}, &RawExpr{Code: "nil"}}
	conv := []Expr{&Ident{Name: "err"}}
	got := a.recoverFmtArgsWithContext(args, conv, nil, 0)
	if len(got) != 2 {
		t.Fatalf("arg len mismatch: got %d want 2", len(got))
	}
	if got[1].GoString() != "err" {
		t.Fatalf("expected wrapped arg err, got %s", got[1].GoString())
	}
}

func TestRecoverFmtArgsWithContextUnwrapFmtVError(t *testing.T) {
	a := &Analyzer{}
	args := []Expr{&StringLit{Value: "%w"}, &RawExpr{Code: `fmt.Errorf("%v", err)`}}
	got := a.recoverFmtArgsWithContext(args, nil, nil, 0)
	if len(got) != 2 {
		t.Fatalf("arg len mismatch: got %d want 2", len(got))
	}
	if got[1].GoString() != "err" {
		t.Fatalf("expected unwrapped err, got %s", got[1].GoString())
	}
}

func TestRecoverCallArgsFromRegsMainFunction(t *testing.T) {
	regs := map[x86asm.Reg]Expr{
		x86asm.RAX: &Ident{Name: "arg0"},
		x86asm.RBX: &Ident{Name: "arg1"},
	}
	fn := &symbols.Func{Package: "main", ArgsSize: 16}
	got := recoverCallArgsFromRegs(nil, regs, "main.Foo", fn)
	if len(got) != 2 {
		t.Fatalf("arg len mismatch: got %d want 2", len(got))
	}
	if got[0].GoString() != "arg0" || got[1].GoString() != "arg1" {
		t.Fatalf("unexpected call args: %s, %s", got[0].GoString(), got[1].GoString())
	}
}

func TestRecoverCallArgsFromRegsSkipFmtFormatting(t *testing.T) {
	regs := map[x86asm.Reg]Expr{
		x86asm.RAX: &Ident{Name: "arg0"},
	}
	fn := &symbols.Func{Package: "fmt", ArgsSize: 8}
	got := recoverCallArgsFromRegs(nil, regs, "fmt.Printf", fn)
	if len(got) != 0 {
		t.Fatalf("expected no recovered args for fmt formatting call, got %d", len(got))
	}
}

func TestRecoverCallArgsFromRegsCrossPackageFunction(t *testing.T) {
	regs := map[x86asm.Reg]Expr{
		x86asm.RAX: &Ident{Name: "data"},
	}
	fn := &symbols.Func{Package: "zip", ArgsSize: 8}
	got := recoverCallArgsFromRegs(nil, regs, "zip.readData", fn)
	if len(got) != 1 {
		t.Fatalf("arg len mismatch: got %d want 1", len(got))
	}
	if got[0].GoString() != "data" {
		t.Fatalf("unexpected recovered arg: %s", got[0].GoString())
	}
}

func TestBuildParamKindsFromPtrBits(t *testing.T) {
	kinds := buildParamKindsFromPtrBits(5, []bool{true, false, false, true, false})
	if len(kinds) != 3 {
		t.Fatalf("kind len mismatch: got %d want 3", len(kinds))
	}
	if kinds[0] != ParamString || kinds[1] != ParamInt || kinds[2] != ParamString {
		t.Fatalf("unexpected kinds: %v", kinds)
	}
}

func TestRecoverCallArgsByKinds(t *testing.T) {
	regs := map[x86asm.Reg]Expr{
		x86asm.RAX: &Ident{Name: "parts_0"},
		x86asm.RCX: &Ident{Name: "age"},
		x86asm.RDI: &Ident{Name: "email"},
	}
	kinds := []ParamKind{ParamString, ParamInt, ParamString}
	got := recoverCallArgsByKinds(kinds, regs)
	if len(got) != 3 {
		t.Fatalf("arg len mismatch: got %d want 3", len(got))
	}
	if got[0].GoString() != "parts_0" || got[1].GoString() != "age" || got[2].GoString() != "email" {
		t.Fatalf("unexpected args: %s, %s, %s", got[0].GoString(), got[1].GoString(), got[2].GoString())
	}
}

func TestRecoverCallArgsByKindsSliceComposite(t *testing.T) {
	regs := map[x86asm.Reg]Expr{
		x86asm.RAX: &Ident{Name: "basePtr"},
		x86asm.RBX: &Ident{Name: "n"},
		x86asm.RCX: &Ident{Name: "c"},
	}
	kinds := []ParamKind{ParamSlice}
	got := recoverCallArgsByKinds(kinds, regs)
	if len(got) != 1 {
		t.Fatalf("arg len mismatch: got %d want 1", len(got))
	}
	if got[0].GoString() != "sliceFromPtrLenCap(uintptr(basePtr), int(n), int(c))" {
		t.Fatalf("unexpected slice arg: %s", got[0].GoString())
	}
}

func TestScoreFmtExprForVerbVPreferSourceOverTinyImmediate(t *testing.T) {
	identScore := scoreFmtExprForVerb(&Ident{Name: "_prsp88"}, 'v')
	intScore := scoreFmtExprForVerb(&IntLit{Value: 10}, 'v')
	if identScore <= intScore {
		t.Fatalf("expected source ident score > tiny int score, got %d <= %d", identScore, intScore)
	}
}
