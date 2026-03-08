// fields.go 通过方法体内存访问模式推断结构体字段。
// 适用于未被 .typelink 覆盖的 stub 类型（如 Team）。
package analysis

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Yeah114/GoSpy/pkg/disasm"
	"github.com/Yeah114/GoSpy/pkg/loader"
	"github.com/Yeah114/GoSpy/pkg/symbols"
	"github.com/Yeah114/GoSpy/pkg/typeinfo"
	"golang.org/x/arch/x86/x86asm"
)

// AnalyzeReceiverFields 通过分析方法体的内存访问模式，推断 stub 类型的字段。
// 仅处理 Kind==KindStruct 且 Fields 为空的类型（inferMissingTypes 创建的 stub）。
// 原地修改 types 中符合条件的 TypeDecl.Fields。
func AnalyzeReceiverFields(bin *loader.Binary, table *symbols.Table, types []*typeinfo.TypeDecl) {
	textSec := bin.Sections[".text"]
	if textSec == nil {
		return
	}

	// 建立 "pkg.TypeName" → *TypeDecl 映射（仅 stub 类型）
	stubs := make(map[string]*typeinfo.TypeDecl)
	for _, td := range types {
		if td.Kind == typeinfo.KindStruct && len(td.Fields) == 0 {
			stubs[td.Pkg+"."+td.Name] = td
		}
	}
	if len(stubs) == 0 {
		return
	}

	// 按类型收集来自各方法的访问偏移
	offsets := make(map[string]map[int64]bool)

	for _, fn := range table.Funcs {
		// 仅处理指针接收者方法（*T 的 receiver 在 RAX）
		if !strings.Contains(fn.Name, ".(*") {
			continue
		}
		pkg, typName := parseReceiverType(fn.Name)
		if pkg == "" || typName == "" {
			continue
		}
		key := pkg + "." + typName
		if stubs[key] == nil {
			continue
		}

		// 反汇编此方法
		start := fn.Entry - textSec.Addr
		end := min(fn.End-textSec.Addr, uint64(len(textSec.Data)))
		if start >= uint64(len(textSec.Data)) {
			continue
		}
		insts, err := disasm.Func(textSec.Data[start:end], fn.Entry)
		if err != nil {
			continue
		}

		seen := offsets[key]
		if seen == nil {
			seen = make(map[int64]bool)
			offsets[key] = seen
		}
		for _, off := range analyzeReceiverAccesses(insts) {
			seen[off] = true
		}
	}

	// 将偏移转换为 FieldDecl，填充 stub
	for key, offSet := range offsets {
		if len(offSet) == 0 {
			continue
		}
		td := stubs[key]

		sorted := make([]int64, 0, len(offSet))
		for off := range offSet {
			sorted = append(sorted, off)
		}
		slices.Sort(sorted)

		td.Fields = offsetsToFields(sorted)
		td.Comment = "fields inferred from memory access patterns"
	}
}

// analyzeReceiverAccesses 扫描指令序列，收集通过 receiver 寄存器访问的偏移量。
// Go register ABI（1.17+）：方法 receiver *T 在入口时位于 RAX。
// 支持一级寄存器别名追踪：MOV RBX, RAX → RBX 也指向 receiver。
func analyzeReceiverAccesses(insts []*disasm.Inst) []int64 {
	// 初始 receiver 寄存器集合
	receiverRegs := map[x86asm.Reg]bool{x86asm.RAX: true}
	seenOffsets := make(map[int64]bool)

	for _, inst := range insts {
		args := inst.Op.Args

		// CALL 后 RAX 被返回值覆盖
		if inst.IsCall() {
			delete(receiverRegs, x86asm.RAX)
			continue
		}

		// 检测寄存器别名：MOV r64, receiver_reg
		if inst.Op.Op == x86asm.MOV && len(args) >= 2 && args[0] != nil && args[1] != nil {
			if dstReg, ok := args[0].(x86asm.Reg); ok {
				if srcReg, ok := args[1].(x86asm.Reg); ok {
					if receiverRegs[srcReg] && is64BitReg(dstReg) {
						receiverRegs[dstReg] = true
					}
					// 若目标寄存器被重写（非 receiver 源），从集合中移除
					if !receiverRegs[srcReg] && receiverRegs[dstReg] {
						delete(receiverRegs, dstReg)
					}
				}
			}
		}

		// 检测 [receiver+offset] 内存访问（任意指令）
		for _, arg := range args {
			if arg == nil {
				continue
			}
			if mem, ok := arg.(x86asm.Mem); ok {
				// 仅处理无缩放索引的简单偏移寻址：[BASE + DISP]
				// Disp >= 0：包含 offset=0（结构体第一个字段）
				if receiverRegs[mem.Base] && mem.Index == 0 &&
					mem.Disp >= 0 && mem.Disp < 512 {
					seenOffsets[mem.Disp] = true
				}
			}
		}
	}

	result := make([]int64, 0, len(seenOffsets))
	for off := range seenOffsets {
		result = append(result, off)
	}
	slices.Sort(result)
	return result
}

// offsetsToFields 根据已发现的偏移列表推断字段声明。
// 优先将相邻 8 字节偏移三元组识别为 []byte（slice header），
// 双元组识别为 string，其余按 gap 猜测单字段类型。
func offsetsToFields(sortedOffsets []int64) []typeinfo.FieldDecl {
	var fields []typeinfo.FieldDecl
	i := 0
	for i < len(sortedOffsets) {
		off := sortedOffsets[i]

		// 两个连续 8 字节偏移 → string header（ptr+len）
		// 同时保留 off+8 的 hidden 条目，以便替换 [rax+(off+8)] 时能找到父字段名。
		if i+1 < len(sortedOffsets) && sortedOffsets[i+1] == off+8 {
			name := fmt.Sprintf("F%d", off)
			fields = append(fields,
				typeinfo.FieldDecl{Name: name, TypeName: "string", Offset: uint64(off)},
				typeinfo.FieldDecl{Name: name, Hidden: true, Offset: uint64(off + 8)},
			)
			i += 2
			continue
		}

		// 单字段：按 gap 猜测
		var gap int64
		if i+1 < len(sortedOffsets) {
			gap = sortedOffsets[i+1] - off
		} else {
			gap = 8
		}
		fields = append(fields, typeinfo.FieldDecl{
			Name:     fmt.Sprintf("F%d", off),
			TypeName: guessFieldType(gap),
			Offset:   uint64(off),
		})
		i++
	}
	return fields
}

// guessFieldType 根据字段占用的字节数猜测 Go 类型。
func guessFieldType(size int64) string {
	switch size {
	case 1:
		return "uint8"
	case 2:
		return "uint16"
	case 4:
		return "uint32"
	case 8:
		return "int" // 8 字节字段多为 int/len，比 uintptr 更易通过类型检查
	case 16:
		return "string" // string header: ptr(8) + len(8)
	case 24:
		return "[]byte" // slice header: ptr(8) + len(8) + cap(8)
	default:
		if size > 0 {
			return fmt.Sprintf("[%d]byte", size)
		}
		return "uintptr"
	}
}

// parseReceiverType 从函数名提取指针接收者类型名（去除 *）。
// "main.(*Team).Stats" → ("main", "Team")
// "main.main"          → ("", "")
func parseReceiverType(funcName string) (pkg, typ string) {
	before, rest, ok := strings.Cut(funcName, ".(")
	if !ok {
		return "", ""
	}
	pkg = before
	if _, after, found := strings.Cut(pkg, "/"); found {
		// 取最后一段（LastIndex 等价：多次 Cut 直到找不到 "/"）
		for {
			if _, next, more := strings.Cut(after, "/"); more {
				after = next
			} else {
				pkg = after
				break
			}
		}
	}
	inner, _, ok2 := strings.Cut(rest, ")")
	if !ok2 {
		return "", ""
	}
	typ = strings.TrimPrefix(inner, "*")
	return
}

// is64BitReg 判断是否为 64 位通用寄存器。
func is64BitReg(r x86asm.Reg) bool {
	switch r {
	case x86asm.RAX, x86asm.RCX, x86asm.RDX, x86asm.RBX,
		x86asm.RSP, x86asm.RBP, x86asm.RSI, x86asm.RDI,
		x86asm.R8, x86asm.R9, x86asm.R10, x86asm.R11,
		x86asm.R12, x86asm.R13, x86asm.R14, x86asm.R15:
		return true
	}
	return false
}
