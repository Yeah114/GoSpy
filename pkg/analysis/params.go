// params.go：从反汇编指令和 pclntab args 字段推断函数参数列表。
//
// Go 1.17+ 寄存器 ABI（x86-64）整型参数寄存器顺序：
//
//	rax, rbx, rcx, rdx, rsi, rdi, r8, r9
//
// 多字类型占用连续寄存器：
//   - string:    (ptr, len)   → 2 个寄存器
//   - []T:       (ptr, len, cap) → 3 个寄存器
//   - interface{}: (type*, data*) → 2 个寄存器
//
// 检测策略（优先级从高到低）：
//  1. ArgsPointerMaps 位图（ptrArgs）：精确知道哪些槽为指针
//     - ptr 槽后接 scalar 槽 → string/slice 对（ptr+len 或 ptr+len+cap）
//     - standalone scalar → int
//  2. 指令模式启发式（ptrArgs 不可用时）：
//     - ptrLike：出现在 Mem.Base（解引用），排除 NOP/rsp/rbp/rip/r14
//     - lenLike：出现在 CMP/TEST/算术指令中
//     - 分组规则：(ptrLike, lenLike) → string；(ptrLike, lenLike, !) → slice
package analysis

import (
	"fmt"
	"strings"

	"github.com/Yeah114/GoSpy/pkg/disasm"
	"golang.org/x/arch/x86/x86asm"
)

// ParamKind 标识参数的 Go 类型种类。
type ParamKind int

const (
	ParamInt    ParamKind = iota // int, bool, uintptr（单字整数/枚举）
	ParamPtr                     // *T（单字指针，无紧跟的 len）
	ParamString                  // string（ptr+len，两字）
	ParamSlice                   // []T（ptr+len+cap，三字）
	ParamIface                   // interface{}（type*+data*，两字）
)

// ZeroValue 返回该参数种类对应的 Go 零值字符串（用于生成调用占位符）。
func (k ParamKind) ZeroValue() string {
	switch k {
	case ParamString:
		return `""`
	case ParamPtr, ParamSlice, ParamIface:
		return "nil"
	default: // ParamInt 及其他
		return "0"
	}
}

// GoType 返回该参数种类对应的 Go 类型注解字符串。
func (k ParamKind) GoType() string {
	switch k {
	case ParamInt:
		return "int"
	case ParamPtr:
		return "uintptr"
	case ParamString:
		return "string"
	case ParamSlice:
		return "[]string"
	case ParamIface:
		return "interface{}"
	default:
		return "int"
	}
}

// ParamInfo 描述一个检测到的函数显式参数（不含接收者）。
type ParamInfo struct {
	Name  string    // 参数名，命名规则：argN（N = 可见参数的序号，从 0 开始）
	Kind  ParamKind // 推断的参数类型
	Words int       // 占用 ABI 整型寄存器槽数（int=1, string=2, slice=3）
	Regs  []string  // 对应的 ABI 寄存器名（小写，如 ["rax","rbx"]）
}

// abiIntArgRegs Go x86-64 ABI 整型参数寄存器，按调用顺序排列。
var abiIntArgRegs = []string{"rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10"}

// DetectParams 从反汇编指令和 pclntab 元数据推断函数的显式参数列表。
//
//   - insts:    函数全部指令（用于寄存器使用模式分析）
//   - argsSize: _func.args 字段值（输入参数帧字节数）；≤0 表示无参数或未知
//   - isMethod: 若为 true，rax 为接收者（跳过），显式参数从 rbx（slot 1）开始
//   - ptrArgs:  来自 ArgsPointerMaps 的指针位图（nil 表示不可用，退回到启发式）
func DetectParams(insts []*disasm.Inst, argsSize int32, isMethod bool, ptrArgs []bool) []ParamInfo {
	if argsSize <= 0 {
		return nil
	}
	nSlots := int(argsSize / 8)
	if nSlots == 0 {
		return nil
	}

	// 接收者占第 0 槽（rax）
	startSlot := 0
	if isMethod {
		startSlot = 1
		nSlots-- // 减去接收者槽
	}
	if nSlots <= 0 {
		return nil
	}
	// 限制为可用 ABI 寄存器数量
	if startSlot+nSlots > len(abiIntArgRegs) {
		nSlots = len(abiIntArgRegs) - startSlot
	}
	if nSlots <= 0 {
		return nil
	}

	regs := abiIntArgRegs[startSlot : startSlot+nSlots]

	// 始终计算 lenLike（用于 slice vs string 的决策）
	regSet := make(map[string]bool, len(regs))
	for _, r := range regs {
		regSet[r] = true
	}
	_, lenLike := analyzeParamRegs(insts, regSet)

	// 路径 A：使用 ArgsPointerMaps 位图（精确指针标记），lenLike 辅助区分 slice/string
	if ptrArgs != nil && len(ptrArgs) >= startSlot+nSlots {
		return groupParamsWithPtrBits(regs, ptrArgs[startSlot:startSlot+nSlots], lenLike, startSlot)
	}

	// 路径 B：纯启发式（无位图时的回退）
	var ptrLike map[string]bool
	ptrLike, lenLike = analyzeParamRegs(insts, regSet)
	return groupParamsFromRegs(regs, ptrLike, lenLike, startSlot)
}

// ── 路径 A：指针位图分组 ──────────────────────────────────────────────────────

// groupParamsWithPtrBits 使用 ArgsPointerMaps 位图分组参数，以 lenLike 辅助区分 slice/string。
//
// 规则：
//  1. ptr slot 后接 1 个 scalar → string（ptr+len）
//  2. ptr slot 后接 ≥2 个 scalar（直到下一个 ptr 或末尾）：
//     a. 若 lenLike[scalar1] && !lenLike[scalar2]：→ slice（ptr+len+cap）
//     b. 若 !lenLike[scalar1] && lenLike[scalar2]：→ string（ptr+len）+ 剩余 scalar 单独处理
//     c. 其余：默认 slice
//  3. standalone scalar → int
func groupParamsWithPtrBits(regs []string, ptrBits []bool, lenLike map[string]bool, startSlot int) []ParamInfo {
	var params []ParamInfo
	i := 0
	visibleIdx := 0 // 可见参数序号（用于命名 arg0/arg1/arg2…），不含 len/cap 等内部字

	for i < len(regs) {
		name := fmt.Sprintf("arg%d", visibleIdx)
		if ptrBits[i] {
			// 统计到下一个 ptr 或末尾之间的连续 scalar 槽数
			scalarsAfter := 0
			for j := i + 1; j < len(regs) && !ptrBits[j]; j++ {
				scalarsAfter++
			}
			switch {
			case scalarsAfter == 0:
				// 末尾独立指针 → uintptr
				params = append(params, ParamInfo{
					Name:  name,
					Kind:  ParamPtr,
					Words: 1,
					Regs:  regs[i : i+1],
				})
				i++
				visibleIdx++
			case scalarsAfter == 1:
				// (ptr, scalar) → string（ptr+len）
				params = append(params, ParamInfo{
					Name:  name,
					Kind:  ParamString,
					Words: 2,
					Regs:  regs[i : i+2],
				})
				i += 2
				visibleIdx++
			default:
				// (ptr, scalar, scalar[, ...])：用 lenLike 区分 slice vs string+int
				// scalar1=regs[i+1], scalar2=regs[i+2]
				s1Len := lenLike[regs[i+1]]
				s2Len := lenLike[regs[i+2]]
				if !s1Len && s2Len {
					// scalar2 是整数比较语义 → scalar1 是 string.len，scalar2 是独立 int
					// (ptr, len) → string，scalar2 留给后续迭代
					params = append(params, ParamInfo{
						Name:  name,
						Kind:  ParamString,
						Words: 2,
						Regs:  regs[i : i+2],
					})
					i += 2
					visibleIdx++
				} else {
					// 默认：(ptr, len, cap) → slice
					params = append(params, ParamInfo{
						Name:  name,
						Kind:  ParamSlice,
						Words: 3,
						Regs:  regs[i : i+3],
					})
					i += 3
					visibleIdx++
				}
			}
		} else {
			// scalar 槽 → int
			params = append(params, ParamInfo{
				Name:  name,
				Kind:  ParamInt,
				Words: 1,
				Regs:  regs[i : i+1],
			})
			i++
			visibleIdx++
		}
	}
	_ = startSlot // startSlot 仅在调用方用于截取 ptrBits，此处不参与命名
	return params
}

// ── 路径 B：启发式分析 ────────────────────────────────────────────────────────

// analyzeParamRegs 扫描第一个 CALL 之前的指令，判断哪些 ABI 参数寄存器是：
//   - ptrLike：作为 Mem.Base 出现（寄存器被解引用），排除 NOP 指令、rsp/rbp/rip/r14
//   - lenLike：出现在 CMP/TEST/算术指令中（整数比较/运算语义）
//
// 注意：NOP [reg] 是编译器填充字节，不代表真实内存访问，必须排除。
// 只分析 CALL 前的指令：CALL 之后寄存器值被覆盖，不再反映原始参数。
func analyzeParamRegs(insts []*disasm.Inst, argRegSet map[string]bool) (ptrLike, lenLike map[string]bool) {
	ptrLike = make(map[string]bool)
	lenLike = make(map[string]bool)

	// 不计入 ptrLike 的特殊寄存器（帧/栈/PC/goroutine 相关）
	skipBase := map[x86asm.Reg]bool{
		x86asm.RSP: true,
		x86asm.RBP: true,
		x86asm.RIP: true,
		x86asm.R14: true, // goroutine 指针
	}

	for _, inst := range insts {
		// CALL 之后原始参数寄存器被覆盖，停止分析
		if inst.IsCall() {
			break
		}
		op := inst.Op.Op

		// NOP 指令：编译器使用 NOP [RAX] 等多字节 NOP 做字节填充，
		// 这些指令不实际访问内存，不应标记任何寄存器为 ptrLike。
		if op == x86asm.NOP {
			continue
		}

		// CMP / TEST → 操作数中的 ABI 寄存器是整数类语义
		if op == x86asm.CMP || op == x86asm.TEST {
			for _, arg := range inst.Op.Args {
				if arg == nil {
					continue
				}
				if reg, ok := arg.(x86asm.Reg); ok {
					name := strings.ToLower(reg.String())
					if argRegSet[name] {
						lenLike[name] = true
					}
				}
			}
		}

		// 算术指令（SUB/ADD/IMUL/SAR/SHR/SHL/AND/OR/XOR）→ 整数运算语义
		switch op {
		case x86asm.SUB, x86asm.ADD, x86asm.IMUL,
			x86asm.SAR, x86asm.SHR, x86asm.SHL,
			x86asm.AND, x86asm.OR, x86asm.XOR:
			for _, arg := range inst.Op.Args {
				if arg == nil {
					continue
				}
				if reg, ok := arg.(x86asm.Reg); ok {
					name := strings.ToLower(reg.String())
					if argRegSet[name] {
						lenLike[name] = true
					}
				}
			}
		}

		// 任意指令中的 Mem.Base → 该寄存器被解引用（指针语义）
		for _, arg := range inst.Op.Args {
			if arg == nil {
				continue
			}
			mem, ok := arg.(x86asm.Mem)
			if !ok || mem.Base == 0 || skipBase[mem.Base] {
				continue
			}
			name := strings.ToLower(mem.Base.String())
			if argRegSet[name] {
				ptrLike[name] = true
			}
		}
	}
	return
}

// groupParamsFromRegs 将寄存器序列按 ptrLike/lenLike 模式分组为 []ParamInfo。
//
// 分组规则（按优先级）：
//  1. (ptrLike AND NOT lenLike, lenLike)：ptr+len 对
//     a. 若 ptrLike[reg_n] && reg_n+2 存在 && NOT lenLike[reg_n+2]
//     且 reg_n+3 不存在 OR NOT lenLike[reg_n+3]：→ slice (ptr+len+cap) 3 字
//     b. 否则：→ string (ptr+len) 2 字
//  2. 其余：→ 单字 int（或 *T 若 ptrLike）
func groupParamsFromRegs(regs []string, ptrLike, lenLike map[string]bool, startSlot int) []ParamInfo {
	var params []ParamInfo
	i := 0
	visibleIdx := 0 // 可见参数序号，len/cap 等内部字不计入

	for i < len(regs) {
		reg := regs[i]
		name := fmt.Sprintf("arg%d", visibleIdx)

		// 检测 (ptr/unknown, len) 对
		if !lenLike[reg] && i+1 < len(regs) && lenLike[regs[i+1]] {
			// 尝试检测 slice：
			if ptrLike[reg] && i+2 < len(regs) && !lenLike[regs[i+2]] {
				nextMayBeLen := i+3 < len(regs) && lenLike[regs[i+3]]
				if !nextMayBeLen {
					// (ptr, len, cap) → slice
					params = append(params, ParamInfo{
						Name:  name,
						Kind:  ParamSlice,
						Words: 3,
						Regs:  regs[i : i+3],
					})
					i += 3
					visibleIdx++
					continue
				}
			}
			// 默认：(ptr, len) → string
			params = append(params, ParamInfo{
				Name:  name,
				Kind:  ParamString,
				Words: 2,
				Regs:  regs[i : i+2],
			})
			i += 2
			visibleIdx++
			continue
		}

		// 单字参数：若被解引用则为 *T，否则为 int
		kind := ParamInt
		if ptrLike[reg] {
			kind = ParamPtr
		}
		params = append(params, ParamInfo{
			Name:  name,
			Kind:  kind,
			Words: 1,
			Regs:  regs[i : i+1],
		})
		i++
		visibleIdx++
	}
	_ = startSlot // startSlot 仅在调用方用于截取寄存器区间
	return params
}
