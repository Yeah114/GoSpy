package analysis

import (
	"strings"
	"testing"

	"github.com/Yeah114/GoSpy/pkg/disasm"
	"golang.org/x/arch/x86/x86asm"
)

func TestBuildRegMapMovAndDecPropagation(t *testing.T) {
	mov := &disasm.Inst{Addr: 0x1000, Size: 7, Op: x86asm.Inst{
		Op: x86asm.MOV,
		Args: [4]x86asm.Arg{
			x86asm.RBX,
			x86asm.Mem{Base: x86asm.RIP, Disp: 0x20},
			nil,
			nil,
		},
	}}
	dec := &disasm.Inst{Addr: 0x1007, Size: 3, Op: x86asm.Inst{
		Op: x86asm.DEC,
		Args: [4]x86asm.Arg{
			x86asm.RBX,
			nil,
			nil,
			nil,
		},
	}}
	cmp := &disasm.Inst{Addr: 0x100A, Size: 4, Op: x86asm.Inst{
		Op: x86asm.CMP,
		Args: [4]x86asm.Arg{
			x86asm.RBX,
			x86asm.Imm(1),
			nil,
			nil,
		},
	}}
	blk := &Block{Insts: []*disasm.Inst{mov, dec, cmp}, CondInst: cmp}
	regMap := buildRegMap(blk, cmp, nil)

	got := regMap["rbx"]
	if !strings.Contains(got, "[0x1027]") || !strings.Contains(got, "- 1") {
		t.Fatalf("unexpected rbx source: %q", got)
	}
	if regMap["ebx"] != got {
		t.Fatalf("expected ebx alias to sync, got %q and %q", regMap["ebx"], got)
	}

	expr := buildCmpExpr(cmp, "<", regMap)
	if !strings.Contains(expr, "[0x1027]") {
		t.Fatalf("cmp expr should keep mapped source, got %q", expr)
	}
}

func TestBuildRegMapLeaWithIndexAndInherited(t *testing.T) {
	lea := &disasm.Inst{Addr: 0x2000, Size: 7, Op: x86asm.Inst{
		Op: x86asm.LEA,
		Args: [4]x86asm.Arg{
			x86asm.RAX,
			x86asm.Mem{Base: x86asm.RDX, Index: x86asm.RSI, Scale: 2, Disp: 8},
			nil,
			nil,
		},
	}}
	cmp := &disasm.Inst{Addr: 0x2007, Size: 3, Op: x86asm.Inst{
		Op: x86asm.CMP,
		Args: [4]x86asm.Arg{
			x86asm.RAX,
			x86asm.Imm(0),
			nil,
			nil,
		},
	}}
	blk := &Block{Insts: []*disasm.Inst{lea, cmp}, CondInst: cmp}
	regMap := buildRegMap(blk, cmp, map[string]string{
		"rdx": "basePtr",
		"rsi": "idx",
	})

	got := regMap["rax"]
	if !strings.Contains(got, "basePtr") || !strings.Contains(got, "*2") || !strings.Contains(got, "+0x8") {
		t.Fatalf("unexpected lea source: %q", got)
	}
}
