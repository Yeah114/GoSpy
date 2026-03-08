// Package disasm 封装 x86-64 反汇编器，提供指令级分析能力。
package disasm

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

// Inst 表示一条已解码的 x86-64 指令。
type Inst struct {
	Addr uint64       // 指令的虚拟地址
	Size int          // 指令字节数
	Op   x86asm.Inst // 解码结果
	Raw  []byte       // 原始字节
}

// Text 返回 GNU 语法的汇编文本。
func (i *Inst) Text() string {
	return fmt.Sprintf("0x%x:\t%s", i.Addr, x86asm.GNUSyntax(i.Op, i.Addr, nil))
}

// IsCall 判断是否为 CALL 指令。
func (i *Inst) IsCall() bool { return i.Op.Op == x86asm.CALL }

// IsRet 判断是否为 RET 指令。
func (i *Inst) IsRet() bool { return i.Op.Op == x86asm.RET }

// IsLEA 判断是否为 LEA 指令。
func (i *Inst) IsLEA() bool { return i.Op.Op == x86asm.LEA }

// IsMOV 判断是否为 MOV 系列指令。
func (i *Inst) IsMOV() bool {
	return i.Op.Op == x86asm.MOV
}

// IsJump 判断是否为跳转指令。
func (i *Inst) IsJump() bool {
	switch i.Op.Op {
	case x86asm.JMP, x86asm.JE, x86asm.JNE, x86asm.JL, x86asm.JLE,
		x86asm.JG, x86asm.JGE, x86asm.JB, x86asm.JBE, x86asm.JA,
		x86asm.JAE, x86asm.JS, x86asm.JNS, x86asm.JP, x86asm.JNP,
		x86asm.JCXZ, x86asm.JECXZ, x86asm.JRCXZ:
		return true
	}
	return false
}

// DirectTarget 返回直接跳转/调用的目标地址（RIP 相对或立即数）。
func (i *Inst) DirectTarget() (uint64, bool) {
	if len(i.Op.Args) == 0 {
		return 0, false
	}
	arg := i.Op.Args[0]
	switch a := arg.(type) {
	case x86asm.Rel:
		target := uint64(int64(i.Addr) + int64(i.Size) + int64(a))
		return target, true
	case x86asm.Imm:
		return uint64(a), true
	}
	return 0, false
}

// LEADst 返回 LEA 指令的目标寄存器（标准化为 64 位形式）。
func (i *Inst) LEADst() (x86asm.Reg, bool) {
	if !i.IsLEA() || len(i.Op.Args) < 1 {
		return 0, false
	}
	reg, ok := i.Op.Args[0].(x86asm.Reg)
	if !ok {
		return 0, false
	}
	return to64(reg), true
}

// to64 将 32 位寄存器规范化为对应的 64 位寄存器。
func to64(r x86asm.Reg) x86asm.Reg {
	switch r {
	case x86asm.EAX:
		return x86asm.RAX
	case x86asm.EBX:
		return x86asm.RBX
	case x86asm.ECX:
		return x86asm.RCX
	case x86asm.EDX:
		return x86asm.RDX
	case x86asm.ESI:
		return x86asm.RSI
	case x86asm.EDI:
		return x86asm.RDI
	}
	return r
}

// LEATarget 返回 LEA 指令中 RIP 相对寻址的目标地址。
func (i *Inst) LEATarget() (uint64, bool) {
	if !i.IsLEA() || len(i.Op.Args) < 2 {
		return 0, false
	}
	mem, ok := i.Op.Args[1].(x86asm.Mem)
	if !ok || mem.Base != x86asm.RIP {
		return 0, false
	}
	target := uint64(int64(i.Addr) + int64(i.Size) + int64(mem.Disp))
	return target, true
}

// RIPMemTarget 返回任意 RIP 相对内存操作数的目标地址（用于 MOV 等）。
func (i *Inst) RIPMemTarget() (uint64, bool) {
	for _, arg := range i.Op.Args {
		if arg == nil {
			continue
		}
		if mem, ok := arg.(x86asm.Mem); ok && mem.Base == x86asm.RIP {
			target := uint64(int64(i.Addr) + int64(i.Size) + int64(mem.Disp))
			return target, true
		}
	}
	return 0, false
}

// RegArg 返回第 n 个操作数的寄存器（规范化为 64 位形式）。
func (i *Inst) RegArg(n int) (x86asm.Reg, bool) {
	if n >= len(i.Op.Args) || i.Op.Args[n] == nil {
		return 0, false
	}
	reg, ok := i.Op.Args[n].(x86asm.Reg)
	if !ok {
		return 0, false
	}
	return to64(reg), true
}

// ImmArg 返回第 n 个操作数的立即数值（若存在）。
func (i *Inst) ImmArg(n int) (int64, bool) {
	if n >= len(i.Op.Args) || i.Op.Args[n] == nil {
		return 0, false
	}
	if imm, ok := i.Op.Args[n].(x86asm.Imm); ok {
		return int64(imm), true
	}
	return 0, false
}

// Func 反汇编给定字节序列（属于起始地址为 baseAddr 的函数）。
func Func(data []byte, baseAddr uint64) ([]*Inst, error) {
	var out []*Inst
	off := 0
	for off < len(data) {
		inst, err := x86asm.Decode(data[off:], 64)
		if err != nil {
			// 跳过无法解码的字节
			off++
			continue
		}
		raw := make([]byte, inst.Len)
		copy(raw, data[off:off+inst.Len])
		out = append(out, &Inst{
			Addr: baseAddr + uint64(off),
			Size: inst.Len,
			Op:   inst,
			Raw:  raw,
		})
		off += inst.Len
	}
	return out, nil
}
