package analysis

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Yeah114/GoSpy/pkg/disasm"
	"github.com/Yeah114/GoSpy/pkg/loader"
	"github.com/Yeah114/GoSpy/pkg/symbols"
	"golang.org/x/arch/x86/x86asm"
)

// Analyzer 分析反汇编指令，提取 Go 语义。
type Analyzer struct {
	bin        *loader.Binary
	table      *symbols.Table
	rodataAddr uint64
	rodataEnd  uint64
	rodataData []byte
}

// New 创建分析器。
func New(bin *loader.Binary, table *symbols.Table) *Analyzer {
	a := &Analyzer{bin: bin, table: table}
	if r := bin.Sections[".rodata"]; r != nil {
		a.rodataAddr = r.Addr
		a.rodataEnd = r.Addr + uint64(len(r.Data))
		a.rodataData = r.Data
	}
	return a
}

// AnalyzeFunc 分析单个函数，返回其 IR。
func (a *Analyzer) AnalyzeFunc(fn *symbols.Func) (*FuncIR, error) {
	text := a.bin.Sections[".text"]
	if text == nil {
		return nil, fmt.Errorf("no .text section")
	}

	start := fn.Entry - text.Addr
	end := fn.End - text.Addr
	end = min(end, uint64(len(text.Data)))
	if start >= uint64(len(text.Data)) {
		return &FuncIR{Name: fn.Name}, nil
	}

	insts, err := disasm.Func(text.Data[start:end], fn.Entry)
	if err != nil {
		return nil, fmt.Errorf("disasm %s: %w", fn.Name, err)
	}

	ir := &FuncIR{Name: fn.Name}

	// 构建 CFG 并提升为结构化 IR
	cfg := Build(insts, fn.Entry)
	ir.Stmts = cfg.Lift(func(blk *Block) []*Stmt {
		return a.extractBlock(ir, blk)
	})

	// 推断参数列表（需要全部指令以分析寄存器使用模式）。
	// 方法判断：指针接收者（"main.(*T).Method"）或值接收者（"main.T.Method"）
	short := fn.ShortName
	isMethod := strings.Contains(fn.Name, ".(") || // 指针接收者
		(strings.Contains(short, ".") && !strings.HasPrefix(short, "(*")) // 值接收者
	ir.Params = DetectParams(insts, fn.ArgsSize, isMethod, fn.PtrArgs)

	return ir, nil
}

// extractBlock 从基本块中提取语句（不含控制流结构）。
func (a *Analyzer) extractBlock(ir *FuncIR, blk *Block) []*Stmt {
	var stmts []*Stmt

	// strCandidate 记录一个潜在的字符串参数。
	// str 非空表示已解析（Pattern B: LEA + 立即数长度）；
	// va 非零表示需要通过 tryStringStruct 解析（Pattern A: rodata 字符串结构体指针）。
	type strCandidate struct {
		va  uint64 // Pattern A: rodata 字符串结构体地址
		str string // Pattern B: 已提前解析的字符串
	}

	resolve := func(sc strCandidate) (string, bool) {
		if sc.str != "" {
			return sc.str, true
		}
		return a.tryStringStruct(sc.va)
	}

	var strCandidates []strCandidate
	// fmtArgCandidates 记录 runtime.convT* 推断出的候选参数，供后续 fmt 格式化调用补全。
	var fmtArgCandidates []Expr
	// regExprs 跟踪当前块内寄存器来源表达式（用于恢复 convT* 的入参来源）。
	regExprs := make(map[x86asm.Reg]Expr)
	// memExprs 跟踪当前块内可识别内存槽位来源（如 _prsp88 -> err），用于跨指令回填参数来源。
	memExprs := make(map[string]Expr)
	for _, reg := range abiArgOrder {
		regExprs[reg] = &Ident{Name: strings.ToLower(reg.String())}
	}
	// intCandidates 追踪 MOV reg, imm 到 ABI 参数寄存器，用于检测整数参数（如 strings.Repeat count）。
	// 每个字符串参数消耗 2 个 ABI 槽（ptr+len），之后的整数参数依序追加。
	intCandidates := make(map[x86asm.Reg]int64)

	for idx, inst := range blk.Insts {
		switch {
		case inst.IsRet():
			// 尝试将当前字符串候选附加到 return（如 switch 字符串返回）
			var retCall *CallExpr
			for _, sc := range strCandidates {
				if s, ok := resolve(sc); ok {
					if retCall == nil {
						retCall = &CallExpr{Func: "return"}
					}
					retCall.Args = append(retCall.Args, &StringLit{Value: s})
					ir.Strings = appendUniq(ir.Strings, s)
				}
			}
			if retCall != nil {
				stmts = append(stmts, &Stmt{Kind: StmtReturn, Call: retCall, PC: inst.Addr})
			} else {
				stmts = append(stmts, &Stmt{Kind: StmtReturn, PC: inst.Addr})
			}
			strCandidates = nil
			fmtArgCandidates = nil
			intCandidates = make(map[x86asm.Reg]int64)

		case inst.IsCall():
			target, ok := inst.DirectTarget()
			if !ok {
				// 间接调用（接口 dispatch / 函数指针）
				stmts = append(stmts, &Stmt{
					Kind:    StmtAsm,
					Comment: fmt.Sprintf("indirect call @ 0x%x", inst.Addr),
					PC:      inst.Addr,
				})
				strCandidates = nil
				fmtArgCandidates = nil
				intCandidates = make(map[x86asm.Reg]int64)
				clobberCallerSaved(regExprs)
				continue
			}

			callee := fmt.Sprintf("sub_0x%x", target)
			var calleeFn *symbols.Func
			if fn := a.table.PCToFunc(target); fn != nil {
				callee = fn.Name
				calleeFn = fn
			}

			if isFmtArgRuntimeConv(callee) {
				if arg, ok := pickFmtConvArg(regExprs); ok {
					fmtArgCandidates = append(fmtArgCandidates, arg)
				}
			}

			if isSkippableRuntime(callee) {
				strCandidates = nil
				intCandidates = make(map[x86asm.Reg]int64)
				clobberCallerSaved(regExprs)
				continue
			}

			call := &CallExpr{Func: callee}
			var firstStringAddr uint64

			// 尝试从候选字符串中恢复参数（Pattern A 和 Pattern B）
			for idxSC, sc := range strCandidates {
				if s, ok := resolve(sc); ok {
					call.Args = append(call.Args, &StringLit{Value: s})
					ir.Strings = appendUniq(ir.Strings, s)
					if idxSC == 0 && sc.va != 0 {
						firstStringAddr = sc.va
					}
				}
			}
			strCandidates = nil

			fmtLike := isFmtFormattingCall(callee)
			if !fmtLike {
				// 在字符串参数之后，追加整数参数（MOV reg, imm 检测）。
				// 每个字符串参数消耗 2 个 ABI 槽（ptr+len），从下一个空闲槽开始查找整数参数。
				strArgSlots := len(call.Args) * 2
				for slotIdx := strArgSlots; slotIdx < len(abiArgOrder); slotIdx++ {
					reg := abiArgOrder[slotIdx]
					v, hasInt := intCandidates[reg]
					if !hasInt {
						break // 首个空缺槽后停止，避免误采
					}
					call.Args = append(call.Args, &IntLit{Value: v})
				}
				call.Args = recoverCallArgsFromRegs(call.Args, regExprs, callee, calleeFn)
			}
			intCandidates = make(map[x86asm.Reg]int64)

			if fmtLike {
				call.Args = a.recoverFmtArgsWithContext(call.Args, fmtArgCandidates, collectFmtRegCandidates(regExprs), firstStringAddr)
			}
			fmtArgCandidates = nil

			ir.Calls = appendUniq(ir.Calls, callee)
			kind := classifyCall(callee)
			stmts = append(stmts, &Stmt{Kind: kind, Call: call, PC: inst.Addr})
			clobberCallerSaved(regExprs)

		case inst.IsLEA():
			updateRegExprFromLEA(inst, regExprs)
			va, ok := inst.LEATarget()
			if !ok || !a.inRodata(va) {
				break
			}
			// LEA 覆盖目标寄存器，清除该寄存器的整数候选
			if leaDst, okDst := inst.LEADst(); okDst {
				delete(intCandidates, leaDst)
			}
			cand := strCandidate{va: va}
			// Pattern B: 向后最多 4 条指令找配对的立即数长度。
			// 遇到第二个 LEA 立即中止：说明寄存器已被重新分配给其他参数，
			// 此后的立即数不属于当前字符串的长度（防止误把 MOV EDI,1 等当成字符串长度）。
			for j := idx + 1; j < len(blk.Insts) && j < idx+5; j++ {
				next := blk.Insts[j]
				if next.IsLEA() {
					break // 另一条 LEA 介入，终止搜索
				}
				if imm, ok2 := next.ImmArg(1); ok2 && imm > 0 && imm <= 4096 {
					if s, ok3 := a.rawString(va, int(imm)); ok3 && s != "" {
						cand = strCandidate{va: va, str: s} // Pattern B: 已解析
						// 字符串长度寄存器已被消耗，从整数候选中清除
						if lenReg, okReg := next.RegArg(0); okReg {
							delete(intCandidates, lenReg)
						}
					}
					break
				}
			}
			strCandidates = append(strCandidates, cand)

		default:
			var (
				dstReg    x86asm.Reg
				hasDstReg bool
				prevExpr  Expr
			)
			if r, ok := inst.RegArg(0); ok {
				dstReg = r
				hasDstReg = true
				if prev, okPrev := regExprs[r]; okPrev {
					prevExpr = cloneExpr(prev)
				}
			}
			updateRegExprGeneric(inst, regExprs, memExprs)
			// 检测变量增量模式：INC/DEC reg 及 ADD/SUB reg, small_imm
			// 仅针对非帧寄存器（跳过 RSP/RBP/R14/R15 等）
			if s := extractIncrStmt(inst); s != nil {
				stmts = append(stmts, s)
				// 对已经提升成 IncrStmt 的指令，寄存器值应与“变量当前值”一致；
				// 避免在表达式里再次叠加 ±1（如先输出 v--，后续参数又出现 (v)-1）。
				if hasDstReg && prevExpr != nil {
					regExprs[dstReg] = prevExpr
				}
			}
			// 追踪 MOV reg, imm 到 ABI 参数寄存器，用于检测整数参数（如 strings.Repeat count）
			if inst.IsMOV() {
				if dstReg, okDst := inst.RegArg(0); okDst && abiArgRegs[dstReg] {
					if imm, ok2 := inst.ImmArg(1); ok2 && imm > 0 {
						intCandidates[dstReg] = imm
					} else {
						delete(intCandidates, dstReg) // 非立即数覆盖，清除追踪
					}
				}
			}
		}
	}
	return stmts
}

// frameRegs 是帧/运行时相关寄存器，不视为用户变量。
var frameRegs = map[x86asm.Reg]bool{
	x86asm.RSP: true, x86asm.RBP: true,
	x86asm.R14: true, x86asm.R15: true, // goroutine/GC 指针
	x86asm.ESP: true, x86asm.EBP: true,
}

// abiArgOrder 是 Go x86-64 ABI 整数参数寄存器的顺序。
// 字符串参数每个消耗 2 个槽（ptr+len），整数参数各消耗 1 个槽。
var abiArgOrder = []x86asm.Reg{
	x86asm.RAX, x86asm.RBX, x86asm.RCX, x86asm.RDI,
	x86asm.RSI, x86asm.R8, x86asm.R9, x86asm.R10,
}

// abiArgRegs 是 abiArgOrder 对应的快速查找集合。
var abiArgRegs = func() map[x86asm.Reg]bool {
	m := make(map[x86asm.Reg]bool, len(abiArgOrder))
	for _, r := range abiArgOrder {
		m[r] = true
	}
	return m
}()

// callerSavedSet 是 Go x86-64 调用约定中的调用者保存寄存器。
var callerSavedSet = map[x86asm.Reg]bool{
	x86asm.RAX: true, x86asm.RBX: true, x86asm.RCX: true, x86asm.RDX: true,
	x86asm.RSI: true, x86asm.RDI: true,
	x86asm.R8: true, x86asm.R9: true, x86asm.R10: true, x86asm.R11: true,
}

// clobberCallerSaved 在 CALL 后清除调用者保存寄存器来源。
func clobberCallerSaved(regExprs map[x86asm.Reg]Expr) {
	for reg := range callerSavedSet {
		delete(regExprs, reg)
	}
}

// cloneExpr 复制表达式对象，避免后续跟踪状态共享引用。
func cloneExpr(e Expr) Expr {
	switch v := e.(type) {
	case *StringLit:
		return &StringLit{Value: v.Value}
	case *IntLit:
		return &IntLit{Value: v.Value}
	case *Ident:
		return &Ident{Name: v.Name}
	case *RawExpr:
		return &RawExpr{Code: v.Code}
	default:
		return e
	}
}

// updateRegExprFromLEA 跟踪 LEA 结果到目标寄存器。
func updateRegExprFromLEA(inst *disasm.Inst, regExprs map[x86asm.Reg]Expr) {
	dst, ok := inst.LEADst()
	if !ok {
		return
	}
	if expr, ok := sourceExprForLEA(inst, 1, regExprs); ok {
		regExprs[dst] = expr
		return
	}
	delete(regExprs, dst)
}

// updateRegExprGeneric 跟踪 MOV/XOR 指令对寄存器来源表达式的影响。
// 额外维护 memExprs 以跨栈槽/内存中转恢复实参来源。
func updateRegExprGeneric(inst *disasm.Inst, regExprs map[x86asm.Reg]Expr, memExprs map[string]Expr) {
	switch inst.Op.Op {
	case x86asm.MOV:
		if dstMem, ok := inst.Op.Args[0].(x86asm.Mem); ok {
			if dstName, okName := memExprName(inst, dstMem); okName {
				if src, okSrc := sourceExprWithMem(inst, 1, memExprs); okSrc {
					memExprs[dstName] = cloneExpr(src)
				} else {
					delete(memExprs, dstName)
				}
			}
		}

		dst, ok := inst.RegArg(0)
		if !ok {
			return
		}
		if srcReg, ok := inst.RegArg(1); ok {
			if srcExpr, found := regExprs[srcReg]; found {
				regExprs[dst] = cloneExpr(srcExpr)
			} else {
				regExprs[dst] = &Ident{Name: strings.ToLower(srcReg.String())}
			}
			return
		}
		if imm, ok := inst.ImmArg(1); ok {
			regExprs[dst] = &IntLit{Value: imm}
			return
		}
		if expr, ok := sourceExprWithMem(inst, 1, memExprs); ok {
			regExprs[dst] = expr
			return
		}
		delete(regExprs, dst)

	case x86asm.XOR:
		dst, okDst := inst.RegArg(0)
		src, okSrc := inst.RegArg(1)
		if okDst && okSrc && dst == src {
			regExprs[dst] = &IntLit{Value: 0}
			return
		}
		if okDst {
			delete(regExprs, dst)
		}

	case x86asm.ADD, x86asm.SUB, x86asm.INC, x86asm.DEC, x86asm.AND, x86asm.OR,
		x86asm.SHL, x86asm.SHR, x86asm.SAR, x86asm.NEG, x86asm.NOT, x86asm.IMUL:
		if !updateRegExprByArithmetic(inst, regExprs) {
			if dst, ok := inst.RegArg(0); ok {
				delete(regExprs, dst)
			}
		}
	}
}

func sourceExprForLEA(inst *disasm.Inst, n int, regExprs map[x86asm.Reg]Expr) (Expr, bool) {
	if n >= len(inst.Op.Args) || inst.Op.Args[n] == nil {
		return nil, false
	}
	mem, ok := inst.Op.Args[n].(x86asm.Mem)
	if !ok {
		return sourceExpr(inst, n)
	}
	if name, okName := memExprName(inst, mem); okName {
		return &Ident{Name: name}, true
	}
	if mem.Segment != 0 {
		return nil, false
	}
	if mem.Base == x86asm.RIP {
		return nil, false
	}
	var terms []string
	if mem.Base != 0 {
		baseReg := normalizeReg64(mem.Base)
		terms = append(terms, regExprCode(baseReg, regExprs))
	}
	if mem.Index != 0 {
		idxReg := normalizeReg64(mem.Index)
		idxExpr := regExprCode(idxReg, regExprs)
		scale := int(mem.Scale)
		if scale <= 0 {
			scale = 1
		}
		if scale != 1 {
			idxExpr = fmt.Sprintf("(%s) * %d", idxExpr, scale)
		}
		terms = append(terms, idxExpr)
	}
	if len(terms) == 0 {
		return nil, false
	}
	code := terms[0]
	for i := 1; i < len(terms); i++ {
		code = fmt.Sprintf("(%s) + (%s)", code, terms[i])
	}
	if mem.Disp > 0 {
		code = fmt.Sprintf("(%s) + %d", code, mem.Disp)
	} else if mem.Disp < 0 {
		code = fmt.Sprintf("(%s) - %d", code, -mem.Disp)
	}
	return &RawExpr{Code: code}, true
}

func regExprCode(reg x86asm.Reg, regExprs map[x86asm.Reg]Expr) string {
	if expr, ok := regExprs[reg]; ok && expr != nil {
		if code := strings.TrimSpace(expr.GoString()); code != "" {
			return code
		}
	}
	return strings.ToLower(reg.String())
}

func updateRegExprByArithmetic(inst *disasm.Inst, regExprs map[x86asm.Reg]Expr) bool {
	dst, ok := inst.RegArg(0)
	if !ok {
		return false
	}
	lhs := regExprCode(dst, regExprs)
	switch inst.Op.Op {
	case x86asm.INC:
		regExprs[dst] = &RawExpr{Code: fmt.Sprintf("(%s) + 1", lhs)}
		return true
	case x86asm.DEC:
		regExprs[dst] = &RawExpr{Code: fmt.Sprintf("(%s) - 1", lhs)}
		return true
	case x86asm.NEG:
		regExprs[dst] = &RawExpr{Code: fmt.Sprintf("-(%s)", lhs)}
		return true
	case x86asm.ADD, x86asm.SUB, x86asm.AND, x86asm.OR, x86asm.SHL, x86asm.SHR, x86asm.SAR, x86asm.IMUL:
		rhs, ok := arithmeticRHSCode(inst, regExprs)
		if !ok {
			return false
		}
		op := arithmeticOpToken(inst.Op.Op)
		if op == "" {
			return false
		}
		regExprs[dst] = &RawExpr{Code: fmt.Sprintf("(%s) %s (%s)", lhs, op, rhs)}
		return true
	default:
		return false
	}
}

func arithmeticRHSCode(inst *disasm.Inst, regExprs map[x86asm.Reg]Expr) (string, bool) {
	if imm, ok := inst.ImmArg(1); ok {
		return fmt.Sprintf("%d", imm), true
	}
	if reg, ok := inst.RegArg(1); ok {
		return regExprCode(reg, regExprs), true
	}
	if len(inst.Op.Args) > 1 && inst.Op.Args[1] != nil {
		if expr, ok := sourceExpr(inst, 1); ok {
			return strings.TrimSpace(expr.GoString()), true
		}
	}
	return "", false
}

func arithmeticOpToken(op x86asm.Op) string {
	switch op {
	case x86asm.ADD:
		return "+"
	case x86asm.SUB:
		return "-"
	case x86asm.AND:
		return "&"
	case x86asm.OR:
		return "|"
	case x86asm.SHL:
		return "<<"
	case x86asm.SHR, x86asm.SAR:
		return ">>"
	case x86asm.IMUL:
		return "*"
	default:
		return ""
	}
}

func sourceExprWithMem(inst *disasm.Inst, n int, memExprs map[string]Expr) (Expr, bool) {
	if n >= len(inst.Op.Args) || inst.Op.Args[n] == nil {
		return nil, false
	}
	if mem, ok := inst.Op.Args[n].(x86asm.Mem); ok {
		name, okName := memExprName(inst, mem)
		if !okName {
			return nil, false
		}
		if expr, ok := memExprs[name]; ok {
			return cloneExpr(expr), true
		}
		return &Ident{Name: name}, true
	}
	return sourceExpr(inst, n)
}

// sourceExpr 将指令第 n 个操作数提取为可渲染表达式。
func sourceExpr(inst *disasm.Inst, n int) (Expr, bool) {
	if n >= len(inst.Op.Args) || inst.Op.Args[n] == nil {
		return nil, false
	}
	switch a := inst.Op.Args[n].(type) {
	case x86asm.Reg:
		return &Ident{Name: strings.ToLower(normalizeReg64(a).String())}, true
	case x86asm.Imm:
		return &IntLit{Value: int64(a)}, true
	case x86asm.Mem:
		name, ok := memExprName(inst, a)
		if !ok {
			return nil, false
		}
		return &Ident{Name: name}, true
	}
	return nil, false
}

// memExprName 将内存操作数转换为伪标识符（如 _prax18 / _g4012ab）。
func memExprName(inst *disasm.Inst, mem x86asm.Mem) (string, bool) {
	if mem.Segment != 0 || mem.Index != 0 || mem.Base == 0 {
		return "", false
	}
	if mem.Base == x86asm.RIP {
		target := uint64(int64(inst.Addr) + int64(inst.Size) + int64(mem.Disp))
		return fmt.Sprintf("_g%x", target), true
	}
	base := normalizeReg64(mem.Base)
	if base == 0 || mem.Disp < 0 {
		return "", false
	}
	return fmt.Sprintf("_p%s%x", strings.ToLower(base.String()), uint64(mem.Disp)), true
}

// normalizeReg64 将 32 位寄存器名标准化为 64 位寄存器。
func normalizeReg64(r x86asm.Reg) x86asm.Reg {
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
	case x86asm.R8L, x86asm.R8B, x86asm.R8W:
		return x86asm.R8
	case x86asm.R9L, x86asm.R9B, x86asm.R9W:
		return x86asm.R9
	case x86asm.R10L, x86asm.R10B, x86asm.R10W:
		return x86asm.R10
	case x86asm.R11L, x86asm.R11B, x86asm.R11W:
		return x86asm.R11
	case x86asm.R12L, x86asm.R12B, x86asm.R12W:
		return x86asm.R12
	case x86asm.R13L, x86asm.R13B, x86asm.R13W:
		return x86asm.R13
	case x86asm.R14L, x86asm.R14B, x86asm.R14W:
		return x86asm.R14
	case x86asm.R15L, x86asm.R15B, x86asm.R15W:
		return x86asm.R15
	}
	return r
}

// isFmtArgRuntimeConv 判断是否为 fmt 变参常见的 runtime 转换调用。
func isFmtArgRuntimeConv(name string) bool {
	return strings.HasPrefix(name, "runtime.convT") || strings.HasPrefix(name, "runtime.convI")
}

// pickFmtConvArg 从寄存器来源中提取一个可用于 fmt 变参的候选表达式。
func pickFmtConvArg(regExprs map[x86asm.Reg]Expr) (Expr, bool) {
	var best Expr
	bestScore := -1
	for _, reg := range fmtCandidateRegOrder() {
		expr, ok := regExprs[reg]
		if !ok {
			continue
		}
		score := fmtExprScore(expr)
		if score > bestScore {
			bestScore = score
			best = expr
		}
	}
	if bestScore < 0 {
		return nil, false
	}
	return cloneExpr(best), true
}

// isUsefulFmtExpr 过滤掉无法稳定渲染为 Go 表达式的候选。
func isUsefulFmtExpr(expr Expr) bool {
	switch v := expr.(type) {
	case *StringLit, *IntLit:
		return true
	case *Ident:
		name := strings.TrimSpace(v.Name)
		if name == "" || name == "nil" {
			return false
		}
		return strings.HasPrefix(name, "_p") || strings.HasPrefix(name, "_g") || x86RegNameSet[name] || isValidIdent(name)
	case *RawExpr:
		return strings.TrimSpace(v.Code) != ""
	default:
		return false
	}
}

// x86RegNameSet 用于识别寄存器名标识符。
var x86RegNameSet = map[string]bool{
	"rax": true, "rbx": true, "rcx": true, "rdx": true,
	"rsi": true, "rdi": true, "r8": true, "r9": true,
	"r10": true, "r11": true, "r12": true, "r13": true,
	"r14": true, "r15": true, "rsp": true, "rbp": true,
}

// fmtExprScore 返回候选表达式质量分值，越高越优先。
func fmtExprScore(expr Expr) int {
	if !isUsefulFmtExpr(expr) {
		return -1
	}
	switch v := expr.(type) {
	case *StringLit, *IntLit:
		return 5
	case *Ident:
		if strings.HasPrefix(v.Name, "_p") {
			return 4
		}
		if x86RegNameSet[v.Name] {
			return 3
		}
		if strings.HasPrefix(v.Name, "_g") {
			return 1
		}
	case *RawExpr:
		return 2
	}
	return 0
}

// isFmtFormattingCall 判断是否为格式化类调用。
func isFmtFormattingCall(name string) bool {
	return strings.HasSuffix(name, ".Sprintf") ||
		strings.HasSuffix(name, ".Printf") ||
		strings.HasSuffix(name, ".Fprintf") ||
		strings.HasSuffix(name, ".Errorf")
}

// recoverFmtArgsWithContext 在 fmt 参数恢复时应用上下文过滤：
//  1. 排除与格式串地址相同的全局候选（避免 "%w" 误选 format ptr）
//  2. 对 %w 排除 .rodata 文本地址，优先选择真正 error 来源。
func (a *Analyzer) recoverFmtArgsWithContext(args []Expr, convArgs, regArgs []Expr, formatAddr uint64) []Expr {
	skip := func(verb byte, expr Expr) bool {
		addr, ok := globalAddrFromExpr(expr)
		if !ok {
			return false
		}
		if formatAddr != 0 && addr == formatAddr {
			return true
		}
		if verb == 'w' && a.inRodata(addr) {
			return true
		}
		return false
	}
	out := recoverFmtArgsFiltered(args, convArgs, regArgs, skip)
	if len(out) == 0 {
		return out
	}
	fmtLit, ok := out[0].(*StringLit)
	if !ok {
		return out
	}
	verbs := parseFmtVerbs(fmtLit.Value)
	for i, verb := range verbs {
		if verb != 'w' {
			continue
		}
		argIdx := i + 1
		if argIdx >= len(out) {
			break
		}
		if rewritten, ok := a.rewriteErrorArgExpr(out[argIdx]); ok {
			out[argIdx] = rewritten
		}
		if unwrapped, ok := unwrapFmtVWrapperExpr(out[argIdx]); ok {
			out[argIdx] = unwrapped
		}
		if isLikelyErrorExpr(out[argIdx]) && !isNilExpr(out[argIdx]) {
			continue
		}
		if picked, ok := a.pickBestWrappedErrorExpr(convArgs, regArgs, skip, formatAddr); ok {
			out[argIdx] = picked
		}
	}
	return out
}

func (a *Analyzer) pickBestWrappedErrorExpr(convArgs, regArgs []Expr, skip func(byte, Expr) bool, formatAddr uint64) (Expr, bool) {
	var pool []Expr
	pool = append(pool, convArgs...)
	pool = append(pool, regArgs...)
	bestScore := -1
	var best Expr
	for _, cand := range pool {
		if cand == nil {
			continue
		}
		if skip != nil && skip('w', cand) {
			continue
		}
		score := errorExprScore(cand)
		if score < 0 {
			continue
		}
		if score > bestScore {
			bestScore = score
			best = cloneExpr(cand)
		}
	}
	if bestScore < 0 || best == nil {
		return nil, false
	}
	if rewritten, ok := a.rewriteErrorArgExpr(best); ok {
		best = rewritten
	}
	if unwrapped, ok := unwrapFmtVWrapperExpr(best); ok {
		best = unwrapped
	}
	if addr, ok := globalAddrFromExpr(best); ok && formatAddr != 0 && addr == formatAddr {
		return nil, false
	}
	if !isLikelyErrorExpr(best) {
		return nil, false
	}
	return best, true
}

func errorExprScore(expr Expr) int {
	base := fmtExprScore(expr)
	if base < 0 {
		return -1
	}
	switch v := expr.(type) {
	case *Ident:
		name := strings.ToLower(strings.TrimSpace(v.Name))
		if name == "" {
			return -1
		}
		if name == "nil" {
			return -1
		}
		if strings.Contains(name, "err") {
			return base + 20
		}
		if strings.HasPrefix(name, "_g") {
			return base + 12
		}
		if strings.HasPrefix(name, "_p") {
			return base + 8
		}
		if x86RegNameSet[name] {
			return base + 6
		}
		return base + 2
	case *RawExpr:
		code := strings.TrimSpace(v.Code)
		if code == "" || code == "nil" {
			return -1
		}
		if strings.HasPrefix(code, `fmt.Errorf("%v",`) {
			return base + 14
		}
		if strings.Contains(strings.ToLower(code), "err") {
			return base + 10
		}
		return base + 4
	case *IntLit, *StringLit:
		return -1
	default:
		return base
	}
}

func isLikelyErrorExpr(expr Expr) bool {
	switch v := expr.(type) {
	case *Ident:
		name := strings.ToLower(strings.TrimSpace(v.Name))
		if name == "" || name == "nil" {
			return false
		}
		if strings.Contains(name, "err") {
			return true
		}
		return strings.HasPrefix(name, "_g") || strings.HasPrefix(name, "_p") || x86RegNameSet[name]
	case *RawExpr:
		code := strings.TrimSpace(v.Code)
		if code == "" || code == "nil" {
			return false
		}
		if strings.HasPrefix(code, `fmt.Errorf(`) || strings.HasPrefix(code, `errors.New(`) {
			return true
		}
		return strings.Contains(strings.ToLower(code), "err")
	default:
		return false
	}
}

func isNilExpr(expr Expr) bool {
	r, ok := expr.(*RawExpr)
	if !ok {
		return false
	}
	return strings.TrimSpace(r.Code) == "nil"
}

func unwrapFmtVWrapperExpr(expr Expr) (Expr, bool) {
	r, ok := expr.(*RawExpr)
	if !ok {
		return nil, false
	}
	code := strings.TrimSpace(r.Code)
	prefix := `fmt.Errorf("%v",`
	if !strings.HasPrefix(code, prefix) || !strings.HasSuffix(code, ")") {
		return nil, false
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(code, prefix), ")"))
	if inner == "" || inner == "nil" {
		return nil, false
	}
	if isValidIdent(inner) {
		return &Ident{Name: inner}, true
	}
	return &RawExpr{Code: inner}, true
}

// recoverFmtArgs 根据格式串补全缺失参数：优先使用 convT 候选，其次按 verb 类型补零值。
func recoverFmtArgs(args []Expr, convArgs, regArgs []Expr) []Expr {
	return recoverFmtArgsFiltered(args, convArgs, regArgs, nil)
}

func recoverFmtArgsFiltered(args []Expr, convArgs, regArgs []Expr, skip func(verb byte, expr Expr) bool) []Expr {
	if len(args) == 0 {
		return args
	}
	fmtLit, ok := args[0].(*StringLit)
	if !ok {
		return args
	}
	verbs := parseFmtVerbs(fmtLit.Value)
	existingVarArgs := len(args) - 1
	if existingVarArgs >= len(verbs) {
		return args
	}

	need := len(verbs) - existingVarArgs
	seen := make(map[string]bool, len(args))
	for _, a := range args {
		seen[a.GoString()] = true
	}

	var pool []Expr
	pushPool := func(candidates []Expr) {
		for _, c := range candidates {
			if !isUsefulFmtExpr(c) {
				continue
			}
			pool = append(pool, c)
		}
	}

	if len(convArgs) > 0 {
		start := len(convArgs) - len(verbs)
		if start < 0 {
			start = 0
		}
		pushPool(convArgs[start:])
	}
	pushPool(regArgs)

	for verbIdx := existingVarArgs; verbIdx < len(verbs); verbIdx++ {
		verb := verbs[verbIdx]
		bestIdx := -1
		bestScore := -1
		for i, c := range pool {
			if c == nil {
				continue
			}
			key := c.GoString()
			if seen[key] {
				continue
			}
			if skip != nil && skip(verb, c) {
				continue
			}
			score := scoreFmtExprForVerb(c, verb)
			if score > bestScore {
				bestScore = score
				bestIdx = i
			}
		}
		if bestIdx >= 0 {
			picked := pool[bestIdx]
			args = append(args, cloneExpr(picked))
			seen[picked.GoString()] = true
			pool[bestIdx] = nil
			need--
			continue
		}
		args = append(args, defaultFmtArgExpr(verb))
	}
	return args
}

func globalAddrFromExpr(expr Expr) (uint64, bool) {
	id, ok := expr.(*Ident)
	if !ok {
		return 0, false
	}
	name := strings.TrimSpace(id.Name)
	if !strings.HasPrefix(name, "_g") || len(name) <= 2 {
		return 0, false
	}
	v, err := strconv.ParseUint(name[2:], 16, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// rewriteErrorArgExpr 尝试将全局地址候选还原为 error 构造表达式。
// 当前支持从静态对象中解出形如 errors.errorString 的文本内容。
func (a *Analyzer) rewriteErrorArgExpr(expr Expr) (Expr, bool) {
	addr, ok := globalAddrFromExpr(expr)
	if !ok {
		return nil, false
	}
	msg, ok := a.tryDecodeErrorMessage(addr)
	if !ok {
		return nil, false
	}
	return &RawExpr{Code: fmt.Sprintf("fmt.Errorf(%q)", msg)}, true
}

func (a *Analyzer) tryDecodeErrorMessage(addr uint64) (string, bool) {
	ptr, ln, ok := a.readStringHeader(addr)
	if ok {
		if s, ok2 := a.rawString(ptr, int(ln)); ok2 && s != "" {
			return s, true
		}
	}
	first, ok := a.readUint64(addr)
	if !ok || first == 0 {
		return "", false
	}
	ptr, ln, ok = a.readStringHeader(first)
	if !ok {
		return "", false
	}
	if s, ok := a.rawString(ptr, int(ln)); ok && s != "" {
		return s, true
	}
	return "", false
}

func (a *Analyzer) readStringHeader(addr uint64) (uint64, uint64, bool) {
	ptr, ok := a.readUint64(addr)
	if !ok || !a.inRodata(ptr) {
		return 0, 0, false
	}
	ln, ok := a.readUint64(addr + 8)
	if !ok || ln == 0 || ln > 4096 {
		return 0, 0, false
	}
	return ptr, ln, true
}

func (a *Analyzer) readUint64(addr uint64) (uint64, bool) {
	b, ok := a.bin.ReadAt(addr, 8)
	if !ok || len(b) != 8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b), true
}

// scoreFmtExprForVerb 返回表达式作为指定 fmt verb 实参时的匹配分数。
// 分数越高越优先，负数表示不适配。
func scoreFmtExprForVerb(expr Expr, verb byte) int {
	base := fmtExprScore(expr)
	if base < 0 {
		return -1
	}
	switch verb {
	case 's', 'q':
		switch v := expr.(type) {
		case *StringLit:
			return base + 10
		case *Ident:
			if strings.HasPrefix(v.Name, "_p") {
				return base + 8
			}
			if x86RegNameSet[v.Name] {
				return base + 6
			}
			if strings.HasPrefix(v.Name, "_g") {
				return base + 5
			}
			return base + 2
		case *IntLit:
			return -1
		default:
			return base
		}
	case 'w':
		switch v := expr.(type) {
		case *Ident:
			name := strings.ToLower(v.Name)
			if strings.Contains(name, "err") {
				return base + 12
			}
			if strings.HasPrefix(v.Name, "_g") {
				return base + 9
			}
			if strings.HasPrefix(v.Name, "_p") {
				return base + 7
			}
			if x86RegNameSet[v.Name] {
				return base + 5
			}
			return base + 2
		case *IntLit, *StringLit:
			return -1
		default:
			return base
		}
	case 'd', 'b', 'o', 'x', 'X', 'c', 'U':
		switch v := expr.(type) {
		case *Ident:
			if strings.HasPrefix(v.Name, "_p") || x86RegNameSet[v.Name] {
				return base + 10
			}
			return base + 6
		case *IntLit:
			return base + 4
		default:
			return base
		}
	case 'f', 'F', 'e', 'E', 'g', 'G':
		switch expr.(type) {
		case *RawExpr:
			return base + 6
		default:
			return base + 1
		}
	case 'v':
		switch v := expr.(type) {
		case *Ident:
			name := strings.ToLower(strings.TrimSpace(v.Name))
			if strings.Contains(name, "err") {
				return base + 12
			}
			if strings.HasPrefix(name, "_p") || strings.HasPrefix(name, "_g") || x86RegNameSet[name] {
				return base + 9
			}
			return base + 4
		case *RawExpr:
			code := strings.ToLower(strings.TrimSpace(v.Code))
			if strings.Contains(code, "err") {
				return base + 10
			}
			return base + 6
		case *IntLit:
			if v.Value >= -16 && v.Value <= 16 {
				return base - 3
			}
			return base
		default:
			return base + 1
		}
	default:
		return base
	}
}

// collectFmtRegCandidates 从寄存器来源图中提取 fmt 参数候选，按质量与 ABI 顺序排序。
func collectFmtRegCandidates(regExprs map[x86asm.Reg]Expr) []Expr {
	type cand struct {
		expr  Expr
		score int
		ord   int
	}
	var cands []cand
	for idx, reg := range fmtCandidateRegOrder() {
		expr, ok := regExprs[reg]
		if !ok {
			continue
		}
		score := fmtExprScore(expr)
		if score < 0 {
			continue
		}
		cands = append(cands, cand{expr: expr, score: score, ord: idx})
	}
	slices.SortFunc(cands, func(a, b cand) int {
		if a.score != b.score {
			return b.score - a.score
		}
		return a.ord - b.ord
	})
	out := make([]Expr, 0, len(cands))
	for _, c := range cands {
		out = append(out, cloneExpr(c.expr))
	}
	return out
}

func collectFmtMemCandidates(memExprs map[string]Expr) []Expr {
	type cand struct {
		expr  Expr
		score int
		key   string
	}
	var cands []cand
	for key, expr := range memExprs {
		if expr == nil {
			continue
		}
		score := fmtExprScore(expr)
		if score < 0 {
			continue
		}
		if strings.Contains(key, "rsp") {
			score += 2
		}
		cands = append(cands, cand{expr: expr, score: score, key: key})
	}
	slices.SortFunc(cands, func(a, b cand) int {
		if a.score != b.score {
			return b.score - a.score
		}
		return strings.Compare(a.key, b.key)
	})
	out := make([]Expr, 0, len(cands))
	seen := make(map[string]bool, len(cands))
	for _, c := range cands {
		code := strings.TrimSpace(c.expr.GoString())
		if code == "" || seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, cloneExpr(c.expr))
	}
	return out
}

func fmtCandidateRegOrder() []x86asm.Reg {
	orders := append([]x86asm.Reg{}, abiArgOrder...)
	if !slices.Contains(orders, x86asm.RDX) {
		orders = append(orders, x86asm.RDX)
	}
	return orders
}

// recoverCallArgsFromRegs 为普通调用补全寄存器参数，尽量减少后续代码生成中的零值占位符。
// 仅对用户函数启用，避免为标准库调用误补参数。
func recoverCallArgsFromRegs(args []Expr, regExprs map[x86asm.Reg]Expr, callee string, calleeFn *symbols.Func) []Expr {
	if !shouldRecoverRegArgs(callee, calleeFn) {
		return args
	}
	if len(args) == 0 {
		if kinds := expectedParamKinds(calleeFn); len(kinds) > 0 {
			if recovered := recoverCallArgsByKinds(kinds, regExprs); len(recovered) > 0 {
				return recovered
			}
		}
	}

	expectedCount := expectedCallArgCount(callee, calleeFn)
	if expectedCount > 0 && len(args) >= expectedCount {
		return args
	}
	consumedSlots := callArgSlots(args)
	startSlot := consumedSlots
	if startSlot >= len(abiArgOrder) {
		return args
	}
	isMethodCall := strings.Contains(callee, ".(")

	seen := make(map[string]bool, len(args))
	for _, a := range args {
		seen[a.GoString()] = true
	}

	for slot := startSlot; slot < len(abiArgOrder); slot++ {
		if expectedCount > 0 && len(args) >= expectedCount {
			break
		}
		expr, ok := regExprs[abiArgOrder[slot]]
		if !ok {
			if expectedCount > 0 {
				break
			}
			continue
		}
		if !isUsefulCallExpr(expr) {
			continue
		}
		if isMethodCall && len(args) == 0 && !isLikelyMethodRecvExpr(expr) {
			continue
		}
		key := expr.GoString()
		if key == "" || seen[key] {
			continue
		}
		args = append(args, cloneExpr(expr))
		seen[key] = true
	}

	return args
}

func shouldRecoverRegArgs(callee string, calleeFn *symbols.Func) bool {
	if isFmtFormattingCall(callee) {
		return false
	}
	if strings.HasPrefix(callee, "runtime.") || strings.HasPrefix(callee, "internal/") {
		return false
	}
	if calleeFn == nil {
		return strings.Contains(callee, ".(")
	}
	if calleeFn.IsRuntime() {
		return false
	}
	// 对所有可解析的非 runtime 调用尝试补全，优先减少 nil/0 占位参数。
	return true
}

func expectedCallArgCount(callee string, calleeFn *symbols.Func) int {
	if calleeFn != nil && calleeFn.ArgsSize > 0 {
		nSlots := int(calleeFn.ArgsSize / 8)
		if nSlots > len(abiArgOrder) {
			nSlots = len(abiArgOrder)
		}
		if nSlots > 0 {
			if n := estimateParamCountFromPtrBits(nSlots, calleeFn.PtrArgs); n > 0 {
				return n
			}
			return nSlots
		}
	}
	if strings.Contains(callee, ".(") {
		return 1
	}
	return 0
}

func expectedParamKinds(calleeFn *symbols.Func) []ParamKind {
	if calleeFn == nil || calleeFn.ArgsSize <= 0 {
		return nil
	}
	nSlots := int(calleeFn.ArgsSize / 8)
	if nSlots <= 0 {
		return nil
	}
	if nSlots > len(abiArgOrder) {
		nSlots = len(abiArgOrder)
	}
	if len(calleeFn.PtrArgs) < nSlots {
		return nil
	}
	return buildParamKindsFromPtrBits(nSlots, calleeFn.PtrArgs)
}

func buildParamKindsFromPtrBits(nSlots int, ptrBits []bool) []ParamKind {
	if nSlots <= 0 || len(ptrBits) < nSlots {
		return nil
	}
	var kinds []ParamKind
	for i := 0; i < nSlots; {
		if !ptrBits[i] {
			kinds = append(kinds, ParamInt)
			i++
			continue
		}
		if i+1 < nSlots && !ptrBits[i+1] {
			if i+2 < nSlots && !ptrBits[i+2] {
				if i+3 < nSlots && ptrBits[i+3] {
					kinds = append(kinds, ParamString)
					i += 2
					continue
				}
				kinds = append(kinds, ParamSlice)
				i += 3
				continue
			}
			kinds = append(kinds, ParamString)
			i += 2
			continue
		}
		kinds = append(kinds, ParamPtr)
		i++
	}
	return kinds
}

func recoverCallArgsByKinds(kinds []ParamKind, regExprs map[x86asm.Reg]Expr) []Expr {
	if len(kinds) == 0 {
		return nil
	}
	var out []Expr
	slot := 0
	for _, kind := range kinds {
		if slot >= len(abiArgOrder) {
			break
		}
		if kind == ParamSlice {
			if expr, ok := buildSliceArgExpr(slot, regExprs); ok {
				out = append(out, expr)
				slot += paramKindSlotWidth(kind)
				continue
			}
		}
		expr, ok := regExprs[abiArgOrder[slot]]
		if ok && isUsefulCallExpr(expr) {
			out = append(out, cloneExpr(expr))
		} else {
			out = append(out, defaultExprForParamKind(kind))
		}
		slot += paramKindSlotWidth(kind)
	}
	return out
}

func buildSliceArgExpr(slot int, regExprs map[x86asm.Reg]Expr) (Expr, bool) {
	if slot+2 >= len(abiArgOrder) {
		return nil, false
	}
	baseReg := abiArgOrder[slot]
	lenReg := abiArgOrder[slot+1]
	capReg := abiArgOrder[slot+2]
	baseExpr, okBase := regExprs[baseReg]
	lenExpr, okLen := regExprs[lenReg]
	capExpr, okCap := regExprs[capReg]
	if !okBase || !okLen || !okCap {
		return nil, false
	}
	if !isUsefulCallExpr(baseExpr) || !isUsefulCallExpr(lenExpr) || !isUsefulCallExpr(capExpr) {
		return nil, false
	}
	baseCode := strings.TrimSpace(baseExpr.GoString())
	lenCode := strings.TrimSpace(lenExpr.GoString())
	capCode := strings.TrimSpace(capExpr.GoString())
	if baseCode == "" || lenCode == "" || capCode == "" {
		return nil, false
	}
	code := fmt.Sprintf("sliceFromPtrLenCap(uintptr(%s), int(%s), int(%s))", baseCode, lenCode, capCode)
	return &RawExpr{Code: code}, true
}

func paramKindSlotWidth(kind ParamKind) int {
	switch kind {
	case ParamString, ParamIface:
		return 2
	case ParamSlice:
		return 3
	default:
		return 1
	}
}

func defaultExprForParamKind(kind ParamKind) Expr {
	switch kind {
	case ParamString:
		return &StringLit{Value: ""}
	case ParamPtr, ParamSlice, ParamIface:
		return &RawExpr{Code: "nil"}
	default:
		return &IntLit{Value: 0}
	}
}

func estimateParamCountFromPtrBits(nSlots int, ptrBits []bool) int {
	if nSlots <= 0 || len(ptrBits) < nSlots {
		return 0
	}
	count := 0
	for i := 0; i < nSlots; {
		if !ptrBits[i] {
			count++
			i++
			continue
		}
		// 指针槽：优先识别 string（ptr+len）；若更像 slice（ptr+len+cap）则按 1 个参数计。
		if i+1 < nSlots && !ptrBits[i+1] {
			if i+2 < nSlots && !ptrBits[i+2] {
				if i+3 < nSlots && ptrBits[i+3] {
					count++
					i += 2
					continue
				}
				count++
				i += 3
				continue
			}
			count++
			i += 2
			continue
		}
		count++
		i++
	}
	return count
}

func isLikelyMethodRecvExpr(expr Expr) bool {
	id, ok := expr.(*Ident)
	if !ok {
		return false
	}
	name := strings.TrimSpace(id.Name)
	if name == "" {
		return false
	}
	if isFrameMemIdent(name) {
		return false
	}
	return strings.HasPrefix(name, "_p") || strings.HasPrefix(name, "arg")
}

func callArgSlots(args []Expr) int {
	slots := 0
	for _, a := range args {
		slots += exprArgSlots(a)
	}
	if slots > len(abiArgOrder) {
		return len(abiArgOrder)
	}
	return slots
}

func exprArgSlots(e Expr) int {
	if _, ok := e.(*StringLit); ok {
		return 2
	}
	return 1
}

func isUsefulCallExpr(expr Expr) bool {
	switch v := expr.(type) {
	case *StringLit, *IntLit:
		return true
	case *RawExpr:
		return strings.TrimSpace(v.Code) != ""
	case *Ident:
		name := strings.TrimSpace(v.Name)
		if name == "" {
			return false
		}
		if isFrameMemIdent(name) {
			return false
		}
		if x86RegNameSet[name] {
			return name != "rsp" && name != "rbp" && name != "r14" && name != "r15"
		}
		return strings.HasPrefix(name, "_p") || strings.HasPrefix(name, "_g") || isValidIdent(name)
	default:
		return false
	}
}

func isFrameMemIdent(name string) bool {
	return strings.HasPrefix(name, "_prsp") ||
		strings.HasPrefix(name, "_prbp") ||
		strings.HasPrefix(name, "_pr14") ||
		strings.HasPrefix(name, "_pr15")
}

func isValidIdent(name string) bool {
	for i, r := range name {
		if r == '_' || (r >= '0' && r <= '9' && i > 0) || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			continue
		}
		return false
	}
	return len(name) > 0
}

// parseFmtVerbs 解析格式串中的格式化动词（忽略 %%）。
func parseFmtVerbs(format string) []byte {
	var verbs []byte
	b := []byte(format)
	for i := 0; i < len(b); {
		if b[i] != '%' {
			i++
			continue
		}
		i++
		if i >= len(b) {
			break
		}
		if b[i] == '%' {
			i++
			continue
		}
		i = skipFmtIndex(b, i)
		for i < len(b) && strings.ContainsRune("+#- 0", rune(b[i])) {
			i++
		}
		if i < len(b) && b[i] == '*' {
			i++
			i = skipFmtIndex(b, i)
		} else {
			for i < len(b) && b[i] >= '0' && b[i] <= '9' {
				i++
			}
		}
		if i < len(b) && b[i] == '.' {
			i++
			if i < len(b) && b[i] == '*' {
				i++
				i = skipFmtIndex(b, i)
			} else {
				for i < len(b) && b[i] >= '0' && b[i] <= '9' {
					i++
				}
			}
		}
		i = skipFmtIndex(b, i)
		if i < len(b) {
			verbs = append(verbs, b[i])
			i++
		}
	}
	return verbs
}

// skipFmtIndex 跳过 %[n] 索引描述。
func skipFmtIndex(b []byte, i int) int {
	if i >= len(b) || b[i] != '[' {
		return i
	}
	for i < len(b) && b[i] != ']' {
		i++
	}
	if i < len(b) {
		return i + 1
	}
	return i
}

// defaultFmtArgExpr 为指定格式化动词生成可编译的零值占位符。
func defaultFmtArgExpr(verb byte) Expr {
	switch verb {
	case 's', 'q':
		return &StringLit{Value: ""}
	case 't':
		return &RawExpr{Code: "false"}
	case 'p', 'v', 'T', 'w':
		return &RawExpr{Code: "nil"}
	case 'f', 'F', 'e', 'E', 'g', 'G':
		return &RawExpr{Code: "0.0"}
	default:
		return &IntLit{Value: 0}
	}
}

// extractIncrStmt 尝试将单条指令解析为自增/自减语句。
// 支持：INC reg, DEC reg, ADD reg imm（imm∈[1,16]），SUB reg imm（imm∈[1,16]）。
// 帧寄存器直接返回 nil（不视为用户变量）。
func extractIncrStmt(inst *disasm.Inst) *Stmt {
	if len(inst.Op.Args) == 0 || inst.Op.Args[0] == nil {
		return nil
	}
	dstReg, ok := inst.Op.Args[0].(x86asm.Reg)
	if !ok || frameRegs[dstReg] {
		return nil
	}
	regName := strings.ToLower(dstReg.String())

	switch inst.Op.Op {
	case x86asm.INC:
		return &Stmt{Kind: StmtIncr, Incr: &IncrStmt{Var: regName, Delta: 1}, PC: inst.Addr}
	case x86asm.DEC:
		return &Stmt{Kind: StmtIncr, Incr: &IncrStmt{Var: regName, Delta: -1}, PC: inst.Addr}
	case x86asm.ADD:
		if len(inst.Op.Args) < 2 || inst.Op.Args[1] == nil {
			return nil
		}
		imm, ok2 := inst.Op.Args[1].(x86asm.Imm)
		if !ok2 || imm <= 0 || imm > 16 {
			return nil
		}
		return &Stmt{Kind: StmtIncr, Incr: &IncrStmt{Var: regName, Delta: int64(imm)}, PC: inst.Addr}
	case x86asm.SUB:
		if len(inst.Op.Args) < 2 || inst.Op.Args[1] == nil {
			return nil
		}
		imm, ok2 := inst.Op.Args[1].(x86asm.Imm)
		if !ok2 || imm <= 0 || imm > 16 {
			return nil
		}
		return &Stmt{Kind: StmtIncr, Incr: &IncrStmt{Var: regName, Delta: -int64(imm)}, PC: inst.Addr}
	}
	return nil
}

// ── 字符串检测 ──────────────────────────────────────────────────────────────

// tryStringStruct 尝试把 va 处解释为 stringStruct{ptr uint64, len int64}，
// 若成功返回字符串。
func (a *Analyzer) tryStringStruct(va uint64) (string, bool) {
	if va == 0 || va&(1<<62) != 0 {
		return "", false
	}
	if !a.inRodata(va) {
		return "", false
	}
	off := va - a.rodataAddr
	if off+16 > uint64(len(a.rodataData)) {
		return "", false
	}
	ptr := binary.LittleEndian.Uint64(a.rodataData[off:])
	length := int64(binary.LittleEndian.Uint64(a.rodataData[off+8:]))
	if length <= 0 || length > 4096 {
		return "", false
	}
	return a.rawString(ptr, int(length))
}

// rawString 从 .rodata 中读取字符串字节，验证 UTF-8。
func (a *Analyzer) rawString(ptr uint64, length int) (string, bool) {
	if !a.inRodata(ptr) {
		return "", false
	}
	off := ptr - a.rodataAddr
	if off+uint64(length) > uint64(len(a.rodataData)) {
		return "", false
	}
	b := a.rodataData[off : off+uint64(length)]
	if !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}

func (a *Analyzer) inRodata(addr uint64) bool {
	return addr >= a.rodataAddr && addr < a.rodataEnd
}

// ── 工具函数 ─────────────────────────────────────────────────────────────────

func classifyCall(name string) StmtKind {
	switch {
	case strings.Contains(name, "gopanic") || strings.HasSuffix(name, ".panic"):
		return StmtPanic
	case name == "runtime.newproc":
		return StmtGo
	case name == "runtime.deferproc":
		return StmtDefer
	default:
		return StmtCall
	}
}

// isSkippableRuntime 判断是否为应跳过的 runtime 内部调用。
// 保留: gopanic, newproc(go), deferproc(defer) 等用户可见语义。
// 跳过: GC 屏障, 内存分配/复制, 栈检查, 类型转换等实现细节。
func isSkippableRuntime(name string) bool {
	for _, prefix := range []string{
		// 栈增长
		"runtime.morestack",
		// goroutine 退出（由 Go runtime 调用，非用户 return）
		"runtime.goexit1", "runtime.goexit",
		// GC 写屏障（用户不感知）
		"runtime.gcWriteBarrier",
		// 内存分配（通常对应 new/make，不展示底层细节）
		"runtime.newobject", "runtime.newarray",
		"runtime.makeslice", "runtime.makeslice64",
		"runtime.makemap", "runtime.makemap_small",
		"runtime.makechan",
		// 内存操作
		"runtime.memmove", "runtime.memclrNoHeapPointers",
		// 接口类型转换（boxing/unboxing 细节）
		"runtime.convT", "runtime.convI",
		"runtime.assertI", "runtime.assertE",
		"runtime.typeAssert",
		// slice 扩容
		"runtime.growslice",
		// map 操作（底层实现）
		"runtime.mapassign", "runtime.mapaccess",
		"runtime.mapdelete", "runtime.mapiterinit",
		"runtime.mapiternext",
		// string 操作（底层实现）
		"runtime.stringtoslicebyte", "runtime.slicebytetostring",
		"runtime.concatstring",
		// 其他内部辅助
		"runtime.panicdivide", "runtime.panicshift",
		"runtime.panicIndex", "runtime.panicSlice",
		"runtime.panicmem", "runtime.panicwrap",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func appendUniq(ss []string, s string) []string {
	if slices.Contains(ss, s) {
		return ss
	}
	return append(ss, s)
}
