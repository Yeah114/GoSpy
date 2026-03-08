package analysis

import (
	"strings"
	"testing"

	"github.com/Yeah114/GoSpy/pkg/disasm"
	"golang.org/x/arch/x86/x86asm"
)

func TestSourceExprForLEAWithIndex(t *testing.T) {
	inst := &disasm.Inst{Addr: 0x1000, Size: 7, Op: x86asm.Inst{
		Op: x86asm.LEA,
		Args: [4]x86asm.Arg{
			x86asm.RAX,
			x86asm.Mem{Base: x86asm.RDX, Index: x86asm.RSI, Scale: 1, Disp: 0},
			nil,
			nil,
		},
	}}
	regExprs := map[x86asm.Reg]Expr{
		x86asm.RDX: &Ident{Name: "basePtr"},
		x86asm.RSI: &IntLit{Value: 16},
	}
	expr, ok := sourceExprForLEA(inst, 1, regExprs)
	if !ok {
		t.Fatalf("expected lea expression")
	}
	got := expr.GoString()
	if !strings.Contains(got, "basePtr") || !strings.Contains(got, "16") {
		t.Fatalf("unexpected lea expression: %s", got)
	}
}

func TestUpdateRegExprGenericArithmeticKeepsExpr(t *testing.T) {
	regExprs := map[x86asm.Reg]Expr{x86asm.RSI: &Ident{Name: "x"}}
	memExprs := map[string]Expr{}
	inst := &disasm.Inst{Op: x86asm.Inst{
		Op:   x86asm.AND,
		Args: [4]x86asm.Arg{x86asm.ESI, x86asm.Imm(0x10), nil, nil},
	}}
	updateRegExprGeneric(inst, regExprs, memExprs)
	expr, ok := regExprs[x86asm.RSI]
	if !ok {
		t.Fatalf("expected RSI expression retained")
	}
	if !strings.Contains(expr.GoString(), "&") {
		t.Fatalf("expected bitwise expression, got %s", expr.GoString())
	}
}
