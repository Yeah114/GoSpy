package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Yeah114/GoSpy/pkg/disasm"
	"golang.org/x/arch/x86/x86asm"
)

// ── 基本块 ──────────────────────────────────────────────────────────────────

// TermKind 描述基本块的终止方式。
type TermKind int

const (
	TermFall     TermKind = iota // 顺序执行到下一块
	TermJmp                      // 无条件跳转
	TermCond                     // 条件跳转（2 个后继）
	TermRet                      // 函数返回
	TermIndirect                 // 间接跳转（switch/函数指针）
)

// Block 是控制流图中的基本块。
type Block struct {
	ID    int
	Start uint64 // 第一条指令地址
	End   uint64 // 最后一条指令之后的地址

	Insts []*disasm.Inst

	Term      TermKind
	CondInst  *disasm.Inst // 条件跳转指令（Term == TermCond）
	BranchTgt uint64       // 跳转目标地址
	FallAddr  uint64       // 顺序执行地址

	Succs []*Block // 后继：[0]=fall-through/unconditional, [1]=branch-taken（条件）
	Preds []*Block // 前驱
}

// IsBackEdge 判断到目标 b 是否为回边（向前跳是前向边，向后跳是回边）。
func (blk *Block) IsBackEdge(target *Block) bool {
	return target.Start <= blk.Start
}

// ── CFG ─────────────────────────────────────────────────────────────────────

// CFG 是函数的控制流图。
type CFG struct {
	Blocks  []*Block
	Entry   *Block
	byStart map[uint64]*Block
}

// Build 从反汇编指令构建 CFG。
func Build(insts []*disasm.Inst, funcEntry uint64) *CFG {
	if len(insts) == 0 {
		return &CFG{}
	}

	// ── Step 1: 找 leader（基本块首指令地址） ──────────────────────────────
	leaders := make(map[uint64]bool)
	leaders[insts[0].Addr] = true

	for i, inst := range insts {
		if inst.IsJump() {
			tgt, ok := inst.DirectTarget()
			if ok {
				leaders[tgt] = true
			}
			// 跳转后的下一条指令（fall-through）也是 leader
			if i+1 < len(insts) {
				leaders[insts[i+1].Addr] = true
			}
		}
	}

	// ── Step 2: 切分基本块 ─────────────────────────────────────────────────
	cfg := &CFG{byStart: make(map[uint64]*Block)}
	var cur *Block

	for _, inst := range insts {
		if leaders[inst.Addr] {
			if cur != nil {
				// 当前块未遇到显式跳转，补 TermFall
				if cur.Term == 0 && len(cur.Insts) > 0 {
					cur.Term = TermFall
					cur.FallAddr = inst.Addr
				}
				cfg.Blocks = append(cfg.Blocks, cur)
				cfg.byStart[cur.Start] = cur
			}
			cur = &Block{ID: len(cfg.Blocks), Start: inst.Addr}
		}
		if cur == nil {
			continue
		}
		cur.Insts = append(cur.Insts, inst)
		cur.End = inst.Addr + uint64(inst.Size)

		switch {
		case inst.IsRet():
			cur.Term = TermRet
		case inst.IsJump():
			tgt, ok := inst.DirectTarget()
			if !ok {
				cur.Term = TermIndirect
			} else if inst.Op.Op == x86asm.JMP {
				cur.Term = TermJmp
				cur.BranchTgt = tgt
			} else {
				// 条件跳转
				cur.Term = TermCond
				cur.CondInst = inst
				cur.BranchTgt = tgt
				cur.FallAddr = inst.Addr + uint64(inst.Size)
			}
		}
	}
	if cur != nil && len(cur.Insts) > 0 {
		cfg.Blocks = append(cfg.Blocks, cur)
		cfg.byStart[cur.Start] = cur
	}

	if len(cfg.Blocks) > 0 {
		cfg.Entry = cfg.Blocks[0]
	}

	// ── Step 3: 连接边 ────────────────────────────────────────────────────
	addEdge := func(from, to *Block) {
		if from == nil || to == nil {
			return
		}
		from.Succs = append(from.Succs, to)
		to.Preds = append(to.Preds, from)
	}

	for _, b := range cfg.Blocks {
		switch b.Term {
		case TermJmp:
			addEdge(b, cfg.byStart[b.BranchTgt])
		case TermCond:
			addEdge(b, cfg.byStart[b.FallAddr])
			addEdge(b, cfg.byStart[b.BranchTgt])
		case TermFall:
			addEdge(b, cfg.byStart[b.FallAddr])
		}
	}

	return cfg
}

// ── 结构化控制流提升 ─────────────────────────────────────────────────────────

// Lift 将 CFG 转换为嵌套的 []*Stmt。
// extractStmts 负责从基本块中提取语句（调用方传入）。
func (cfg *CFG) Lift(extractStmts func(*Block) []*Stmt) []*Stmt {
	if cfg.Entry == nil {
		return nil
	}
	visited := make(map[int]bool)
	return cfg.liftFrom(cfg.Entry, visited, extractStmts, nil, nil)
}

// liftFrom 从 start 块递归生成代码，遇到 stopAt 停止。
// inherited 为前驱块传入的寄存器来源映射（跨块传播，顺序推进时更新）。
func (cfg *CFG) liftFrom(start *Block, visited map[int]bool, extract func(*Block) []*Stmt, stopAt *Block, inherited map[string]string) []*Stmt {
	var result []*Stmt
	b := start

	// 初始化跨块寄存器映射（浅拷贝，避免污染调用者）
	inh := make(map[string]string, len(inherited))
	for k, v := range inherited {
		inh[k] = v
	}

	for b != nil && b != stopAt && !visited[b.ID] {
		visited[b.ID] = true
		stmts := extract(b)
		result = append(result, stmts...)

		switch b.Term {
		case TermRet, TermIndirect:
			return result

		case TermJmp:
			if len(b.Succs) == 0 {
				// 跳转目标不在本函数范围内（如跳到 runtime 辅助函数）
				return result
			}
			next := b.Succs[0]
			// 先检查 stopAt：JMP 直接到 merge 点时不算回边，直接退出
			if next == stopAt {
				return result
			}
			if b.IsBackEdge(next) {
				// 共享出口跳转：目标是 TermRet/TermIndirect/函数入口 时是死代码路径
				if next.Term == TermRet || next.Term == TermIndirect || next == cfg.Entry {
					return result
				}
				// 目标已被访问（如 for 循环 body 的另一个入口边），不重复输出
				if visited[next.ID] {
					return result
				}
				// 真正的循环回边（目前输出注释以标记未完全处理的控制流）
				result = append(result, &Stmt{Kind: StmtAsm, Comment: "/* loop continue */", PC: b.End})
				return result
			}
			// 顺序推进：将当前块的出口寄存器状态传给下一块
			inh = buildOutRegMap(b, inh)
			b = next

		case TermCond:
			if len(b.Succs) < 2 {
				return result
			}
			fallBlk := b.Succs[0] // fall-through（条件不成立路径）
			jmpBlk := b.Succs[1]  // branch-taken（条件成立路径）
			cmpInst := findCmpInst(b)
			cond := condStr(b.CondInst, cmpInst, b, inh)

			// ── Goroutine 栈溢出检查（函数头 CMP RSP, 0x10(%R14); JBE morestack）
			if isStackCheck(b) {
				inh = buildOutRegMap(b, inh)
				b = fallBlk
				continue
			}

			// 检查是否是回边（循环头检查）
			if b.IsBackEdge(jmpBlk) {
				// 真实的循环条件：for cond { body }
				// jmpBlk = BranchTgt（back-edge，循环体入口）
				// fallBlk = FallAddr（循环出口，条件不满足时执行）
				bodyVisited := cloneVisited(visited)
				bodyStmts := cfg.liftFrom(jmpBlk, bodyVisited, extract, b, inh)

				// 将当前块（CMP 块）末尾连续的 StmtIncr 移入循环体末尾。
				// 典型模式：i=0; JMP→CMP; body; [INC i; CMP i,n; JL body]
				// INC 语义上属于循环体（每次迭代的末尾），但汇编上位于 CMP 块。
				bodyStmts = append(bodyStmts, popTrailingIncr(&result)...)

				forStmt := &Stmt{
					Kind: StmtFor,
					For:  &ForStmt{Cond: cond, Body: bodyStmts},
					PC:   b.CondInst.Addr,
				}
				result = append(result, forStmt)
				mergeVisited(visited, bodyVisited)
				// 循环后寄存器状态不确定，保守清空
				inh = nil
				b = fallBlk // 继续处理循环出口之后的代码

			} else {
				// 前向分支 → if / if-else
				merge := cfg.mergeBlock(fallBlk, jmpBlk, stopAt)

				// Case 1: stopAt 本身就是 merge（mergeBlock 把 stopAt 排除在外）
				if merge == nil && stopAt != nil {
					if cfg.canReach(fallBlk, stopAt) && cfg.canReach(jmpBlk, stopAt) {
						merge = stopAt
					}
				}
				if jmpBlk == merge || jmpBlk == stopAt {
					// 简单 if（无 else）：条件成立时直接跳到 merge，fall 分支对应否定条件
					thenVisited := cloneVisited(visited)
					thenStmts := cfg.liftFrom(fallBlk, thenVisited, extract, merge, inh)
					result = append(result, &Stmt{
						Kind: StmtIf,
						If:   &IfStmt{Cond: negateCondStr(b.CondInst, cmpInst, b, inh), Then: thenStmts},
						PC:   b.CondInst.Addr,
					})
					mergeVisited(visited, thenVisited)
					// merge 点前有两条路径，保守清空
					inh = nil
					b = merge

				} else if merge != nil {
					// if-else：条件成立走 jmpBlk，条件不成立走 fallBlk
					thenVisited := cloneVisited(visited)
					elseVisited := cloneVisited(visited)
					thenStmts := cfg.liftFrom(jmpBlk, thenVisited, extract, merge, inh)
					elseStmts := cfg.liftFrom(fallBlk, elseVisited, extract, merge, inh)
					result = append(result, &Stmt{
						Kind: StmtIf,
						If:   &IfStmt{Cond: cond, Then: thenStmts, Else: elseStmts},
						PC:   b.CondInst.Addr,
					})
					mergeVisited(visited, thenVisited)
					mergeVisited(visited, elseVisited)
					// merge 点前有两条路径，保守清空
					inh = nil
					b = merge

				} else {
					// merge == nil：先尝试 early-exit，再尝试扩展 merge 搜索
					if !visited[jmpBlk.ID] && cfg.quicklyTerminates(jmpBlk, 10) {
						// jmpBlk 快速终止（如 panic/return）→ if cond { exit_stmts }
						// fallBlk 是主流，顺序继承当前块的寄存器状态
						thenVisited := cloneVisited(visited)
						thenStmts := cfg.liftFrom(jmpBlk, thenVisited, extract, nil, inh)
						if len(thenStmts) == 0 {
							thenStmts = []*Stmt{{Kind: StmtAsm, Comment: "/* return */", PC: jmpBlk.Start}}
						}
						result = append(result, &Stmt{
							Kind: StmtIf,
							If:   &IfStmt{Cond: cond, Then: thenStmts},
							PC:   b.CondInst.Addr,
						})
						mergeVisited(visited, thenVisited)
						// fallBlk 是顺序主流：从当前块传播寄存器状态
						inh = buildOutRegMap(b, inh)
						b = fallBlk
					} else if !visited[fallBlk.ID] && cfg.quicklyTerminates(fallBlk, 10) {
						// fallBlk 快速终止 → if negCond { exit_stmts }，主流走 jmpBlk
						// jmpBlk 是主流，顺序继承当前块的寄存器状态
						thenVisited := cloneVisited(visited)
						thenStmts := cfg.liftFrom(fallBlk, thenVisited, extract, nil, inh)
						if len(thenStmts) == 0 {
							thenStmts = []*Stmt{{Kind: StmtAsm, Comment: "/* return */", PC: fallBlk.Start}}
						}
						result = append(result, &Stmt{
							Kind: StmtIf,
							If:   &IfStmt{Cond: negateCondStr(b.CondInst, cmpInst, b, inh), Then: thenStmts},
							PC:   b.CondInst.Addr,
						})
						mergeVisited(visited, thenVisited)
						// jmpBlk 是顺序主流：从当前块传播寄存器状态
						inh = buildOutRegMap(b, inh)
						b = jmpBlk
					} else if extMerge := cfg.mergeBlockExtended(fallBlk, jmpBlk, stopAt); extMerge != nil {
						// 扩展搜索：两路径通过后向 JMP 汇合到共享出口块
						thenVisited := cloneVisited(visited)
						elseVisited := cloneVisited(visited)
						thenStmts := cfg.liftFrom(jmpBlk, thenVisited, extract, extMerge, inh)
						elseStmts := cfg.liftFrom(fallBlk, elseVisited, extract, extMerge, inh)
						result = append(result, &Stmt{
							Kind: StmtIf,
							If:   &IfStmt{Cond: cond, Then: thenStmts, Else: elseStmts},
							PC:   b.CondInst.Addr,
						})
						mergeVisited(visited, thenVisited)
						mergeVisited(visited, elseVisited)
						// 两路汇合，保守清空
						inh = nil
						b = extMerge
					} else {
						// 无法确定结构，退化为注释；顺序推进到 fallBlk
						result = append(result, &Stmt{
							Kind:    StmtAsm,
							Comment: fmt.Sprintf("if %s { goto 0x%x }", cond, jmpBlk.Start),
							PC:      b.CondInst.Addr,
						})
						inh = buildOutRegMap(b, inh)
						b = fallBlk
					}
				}
			}

		default: // TermFall
			if len(b.Succs) == 0 {
				return result
			}
			// 顺序推进：传播寄存器状态
			inh = buildOutRegMap(b, inh)
			b = b.Succs[0]
		}
	}
	return result
}

// mergeBlock 找到 a、b 两条路径的汇合块（最近公共后继，仅使用前向可达集）。
func (cfg *CFG) mergeBlock(a, b *Block, stopAt *Block) *Block {
	ra := cfg.forwardReach(a, stopAt)
	rb := cfg.forwardReach(b, stopAt)

	var common []*Block
	for id, blk := range ra {
		if rb[id] != nil {
			common = append(common, blk)
		}
	}
	if len(common) == 0 {
		return nil
	}
	sort.Slice(common, func(i, j int) bool { return common[i].Start < common[j].Start })
	return common[0]
}

// mergeBlockExtended 在标准前向搜索失败时，检测通过 TermJmp 后向跳共享的出口块。
// 典型场景：编译器将函数尾部（fmt.Printf + RET）放在较低地址，
// 两路径分别以后向 JMP 跳到同一块。
// 此函数仅在标准 mergeBlock 和 early-exit 均失败时调用。
func (cfg *CFG) mergeBlockExtended(a, b *Block, stopAt *Block) *Block {
	ra := cfg.forwardReach(a, stopAt)
	rb := cfg.forwardReach(b, stopAt)

	var common []*Block
	commonSet := make(map[int]*Block)
	addCommon := func(blk *Block) {
		if commonSet[blk.ID] == nil {
			commonSet[blk.ID] = blk
			common = append(common, blk)
		}
	}

	// 收集 a 路径中 TermJmp 后向跳的目标
	backTgtsA := make(map[int]*Block)
	for _, blk := range ra {
		if blk.Term == TermJmp && len(blk.Succs) > 0 {
			tgt := blk.Succs[0]
			if blk.IsBackEdge(tgt) {
				backTgtsA[tgt.ID] = tgt
			}
		}
	}

	// 检查 b 路径的后向跳目标是否在 a 路径（直接或同为后向跳目标）
	for _, blk := range rb {
		if blk.Term == TermJmp && len(blk.Succs) > 0 {
			tgt := blk.Succs[0]
			if blk.IsBackEdge(tgt) {
				if ra[tgt.ID] != nil {
					addCommon(tgt) // 情形1：b 后向跳目标直接在 a 前向可达集中
				}
				if backTgtsA[tgt.ID] != nil {
					addCommon(tgt) // 情形2：a、b 均后向跳到同一块
				}
			}
		}
	}
	// 情形3：a 后向跳目标直接在 b 前向可达集中
	for tgtID, tgt := range backTgtsA {
		if rb[tgtID] != nil {
			addCommon(tgt)
		}
	}

	if len(common) == 0 {
		return nil
	}
	sort.Slice(common, func(i, j int) bool { return common[i].Start < common[j].Start })
	return common[0]
}

// forwardReach 返回从 start 可达（不经过 stopAt）的所有块（含自身）。
// 沿前向边（IsBackEdge 为 false）DFS 遍历。
func (cfg *CFG) forwardReach(start *Block, stopAt *Block) map[int]*Block {
	seen := make(map[int]*Block)
	var dfs func(b *Block)
	dfs = func(b *Block) {
		if b == nil || b == stopAt || seen[b.ID] != nil {
			return
		}
		seen[b.ID] = b
		for _, s := range b.Succs {
			if !b.IsBackEdge(s) {
				dfs(s)
			}
		}
	}
	dfs(start)
	return seen
}

// ── 工具 ─────────────────────────────────────────────────────────────────────

// isStackCheck 检测 goroutine 栈溢出检查模式（函数开头）。
func isStackCheck(b *Block) bool {
	if b.CondInst == nil || len(b.Insts) < 2 {
		return false
	}
	// 模式: CMP 0x10(%R14), RSP  +  JBE target
	for _, inst := range b.Insts {
		if inst.Op.Op == x86asm.CMP {
			for _, arg := range inst.Op.Args {
				if mem, ok := arg.(x86asm.Mem); ok && mem.Base == x86asm.R14 {
					return true
				}
			}
		}
	}
	return false
}

// condStr 将条件跳转翻译为 Go 风格的条件字符串。
// cmp 为可选的前置 CMP/TEST 指令；b 为当前基本块；inherited 为跨块继承的寄存器映射。
func condStr(jcc, cmp *disasm.Inst, b *Block, inherited map[string]string) string {
	return buildCondStr(jcc, cmp, false, b, inherited)
}

// buildCondStr 构建条件字符串（negate=true 时生成否定条件）。
func buildCondStr(jcc, cmp *disasm.Inst, negate bool, b *Block, inherited map[string]string) string {
	if jcc == nil {
		return "/* cond */"
	}
	opStr, negStr := jccOpPair(jcc.Op.Op)
	s := opStr
	if negate {
		s = negStr
	}
	if cmp != nil {
		var regMap map[string]string
		if b != nil {
			regMap = buildRegMap(b, cmp, inherited)
		}
		if expr := buildCmpExpr(cmp, s, regMap); expr != "" {
			return expr
		}
	}
	return fmt.Sprintf("/* %s @ 0x%x */", s, jcc.Addr)
}

// reg32to64 将 32 位寄存器名映射到其 64 位等价名（x86-64 写 32 位寄存器会零扩展到 64 位）。
var reg32to64 = map[string]string{
	"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
	"esi": "rsi", "edi": "rdi",
	"r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
	"r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15",
}

// callerSavedRegs 是 x86-64 System V ABI 中调用者保存的寄存器集合。
// CALL 指令执行后，这些寄存器的值不再可信。
var callerSavedRegs = map[string]bool{
	"rax": true, "rbx": true, "rcx": true, "rdx": true, "rsi": true, "rdi": true,
	"r8": true, "r9": true, "r10": true, "r11": true,
	"eax": true, "ebx": true, "ecx": true, "edx": true, "esi": true, "edi": true,
	"r8d": true, "r9d": true, "r10d": true, "r11d": true,
}

// reg64to32 是 64 位寄存器对应的 32 位别名（用于别名同步）。
var reg64to32 = map[string]string{
	"rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx",
	"rsi": "esi", "rdi": "edi",
	"r8": "r8d", "r9": "r9d", "r10": "r10d", "r11": "r11d",
	"r12": "r12d", "r13": "r13d", "r14": "r14d", "r15": "r15d",
}

// buildRegMap 扫描基本块中 cmpInst 之前的指令，
// 构建寄存器→来源表达式映射（MOV/LEA/算术传播）。
// inherited 为前驱块传入的初始映射（跨块寄存器传播）；cmpInst 为搜索终止点。
func buildRegMap(b *Block, cmpInst *disasm.Inst, inherited map[string]string) map[string]string {
	regMap := make(map[string]string, len(inherited))
	for k, v := range inherited {
		regMap[k] = v
	}
	for _, inst := range b.Insts {
		if inst == cmpInst || inst == b.CondInst {
			break
		}
		switch inst.Op.Op {
		case x86asm.MOV:
			if len(inst.Op.Args) < 2 {
				break
			}
			dstReg, ok := inst.Op.Args[0].(x86asm.Reg)
			if !ok {
				break
			}
			src := formatCmpArgMapped(inst, inst.Op.Args[1], regMap)
			if src == "" {
				deleteRegMapAlias(regMap, dstReg)
				break
			}
			setRegMapAlias(regMap, dstReg, src)

		case x86asm.LEA:
			if len(inst.Op.Args) < 2 {
				break
			}
			dstReg, ok := inst.Op.Args[0].(x86asm.Reg)
			if !ok {
				break
			}
			src := formatCmpArgMapped(inst, inst.Op.Args[1], regMap)
			if strings.HasPrefix(src, "[") && strings.HasSuffix(src, "]") && len(src) > 2 {
				src = strings.TrimSpace(src[1 : len(src)-1])
			}
			if src == "" {
				deleteRegMapAlias(regMap, dstReg)
				break
			}
			setRegMapAlias(regMap, dstReg, src)

		case x86asm.XOR:
			dstReg, okDst := inst.Op.Args[0].(x86asm.Reg)
			srcReg, okSrc := inst.Op.Args[1].(x86asm.Reg)
			if okDst && okSrc && strings.EqualFold(dstReg.String(), srcReg.String()) {
				setRegMapAlias(regMap, dstReg, "0")
				break
			}
			if okDst {
				deleteRegMapAlias(regMap, dstReg)
			}

		case x86asm.INC, x86asm.DEC, x86asm.NEG,
			x86asm.ADD, x86asm.SUB, x86asm.AND, x86asm.OR,
			x86asm.SHL, x86asm.SHR, x86asm.SAR, x86asm.IMUL:
			if !updateCmpRegMapByArithmetic(inst, regMap) {
				if len(inst.Op.Args) > 0 {
					if dstReg, ok := inst.Op.Args[0].(x86asm.Reg); ok {
						deleteRegMapAlias(regMap, dstReg)
					}
				}
			}

		case x86asm.CALL:
			for reg := range callerSavedRegs {
				delete(regMap, reg)
			}
		}
	}
	return regMap
}

func canonicalRegName(reg x86asm.Reg) string {
	name := strings.ToLower(reg.String())
	if name64, ok := reg32to64[name]; ok {
		return name64
	}
	return name
}

func isSimpleCmpAtom(s string) bool {
	trim := strings.TrimSpace(s)
	if trim == "" {
		return false
	}
	for i, r := range trim {
		if i == 0 {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_') {
				return false
			}
			continue
		}
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

func setRegMapAlias(regMap map[string]string, reg x86asm.Reg, expr string) {
	name := strings.ToLower(reg.String())
	regMap[name] = expr
	if name64, ok := reg32to64[name]; ok {
		regMap[name64] = expr
	}
	if name32, ok := reg64to32[name]; ok {
		regMap[name32] = expr
	}
}

func deleteRegMapAlias(regMap map[string]string, reg x86asm.Reg) {
	name := strings.ToLower(reg.String())
	delete(regMap, name)
	if name64, ok := reg32to64[name]; ok {
		delete(regMap, name64)
	}
	if name32, ok := reg64to32[name]; ok {
		delete(regMap, name32)
	}
}

func updateCmpRegMapByArithmetic(inst *disasm.Inst, regMap map[string]string) bool {
	if len(inst.Op.Args) == 0 || inst.Op.Args[0] == nil {
		return false
	}
	dstReg, ok := inst.Op.Args[0].(x86asm.Reg)
	if !ok {
		return false
	}
	lhs := canonicalRegName(dstReg)
	if mapped, ok := regMap[lhs]; ok && mapped != "" {
		lhs = mapped
	}
	switch inst.Op.Op {
	case x86asm.INC:
		setRegMapAlias(regMap, dstReg, fmt.Sprintf("(%s) + 1", lhs))
		return true
	case x86asm.DEC:
		setRegMapAlias(regMap, dstReg, fmt.Sprintf("(%s) - 1", lhs))
		return true
	case x86asm.NEG:
		setRegMapAlias(regMap, dstReg, fmt.Sprintf("-(%s)", lhs))
		return true
	case x86asm.ADD, x86asm.SUB, x86asm.AND, x86asm.OR, x86asm.SHL, x86asm.SHR, x86asm.SAR, x86asm.IMUL:
		if len(inst.Op.Args) < 2 || inst.Op.Args[1] == nil {
			return false
		}
		rhs := formatCmpArgMapped(inst, inst.Op.Args[1], regMap)
		if rhs == "" {
			return false
		}
		op := ""
		switch inst.Op.Op {
		case x86asm.ADD:
			op = "+"
		case x86asm.SUB:
			op = "-"
		case x86asm.AND:
			op = "&"
		case x86asm.OR:
			op = "|"
		case x86asm.SHL:
			op = "<<"
		case x86asm.SHR, x86asm.SAR:
			op = ">>"
		case x86asm.IMUL:
			op = "*"
		}
		if op == "" {
			return false
		}
		setRegMapAlias(regMap, dstReg, fmt.Sprintf("(%s) %s (%s)", lhs, op, rhs))
		return true
	default:
		return false
	}
}

// buildOutRegMap 计算块 b 执行完毕后的寄存器状态（传给顺序后继块）。
// 处理 b 中所有指令（JCC 不修改通用寄存器，故停在 b.CondInst 前即可）。
func buildOutRegMap(b *Block, inherited map[string]string) map[string]string {
	return buildRegMap(b, nil, inherited)
}

// jccOpPair 返回条件跳转的（正向运算符, 否定运算符）对。
func jccOpPair(op x86asm.Op) (string, string) {
	switch op {
	case x86asm.JE:
		return "==", "!="
	case x86asm.JNE:
		return "!=", "=="
	case x86asm.JL:
		return "<", ">="
	case x86asm.JLE:
		return "<=", ">"
	case x86asm.JG:
		return ">", "<="
	case x86asm.JGE:
		return ">=", "<"
	case x86asm.JB:
		return "< (u)", ">= (u)"
	case x86asm.JBE:
		return "<= (u)", "> (u)"
	case x86asm.JA:
		return "> (u)", "<= (u)"
	case x86asm.JAE:
		return ">= (u)", "< (u)"
	case x86asm.JS:
		return "< 0", ">= 0"
	case x86asm.JNS:
		return ">= 0", "< 0"
	default:
		s := op.String()
		return s, "!" + s
	}
}

// buildCmpExpr 从 CMP/TEST 指令提取操作数，拼接为 "lhs opStr [rhs]" 表达式。
// regMap 非 nil 时，将寄存器名替换为其块内来源表达式（如 "rcx" → "[rax+0x28]"）。
// 返回空字符串表示无法提取（调用方回退到注释格式）。
func buildCmpExpr(cmp *disasm.Inst, opStr string, regMap map[string]string) string {
	if len(cmp.Op.Args) < 1 || cmp.Op.Args[0] == nil {
		return ""
	}
	lhs := formatCmpArgMapped(cmp, cmp.Op.Args[0], regMap)
	if lhs == "" {
		return ""
	}
	// JS/JNS：opStr 已含右侧 "0"（如 "< 0"），直接拼接
	if opStr == "< 0" || opStr == ">= 0" {
		return lhs + " " + opStr
	}
	if len(cmp.Op.Args) < 2 || cmp.Op.Args[1] == nil {
		return ""
	}
	switch cmp.Op.Op {
	case x86asm.CMP:
		rhs := formatCmpArgMapped(cmp, cmp.Op.Args[1], regMap)
		if rhs == "" {
			return ""
		}
		return lhs + " " + opStr + " " + rhs
	case x86asm.TEST:
		// TEST r, r → 检测零值（JE: ==0, JNE: !=0）
		if r0, ok := cmp.Op.Args[0].(x86asm.Reg); ok {
			if r1, ok2 := cmp.Op.Args[1].(x86asm.Reg); ok2 && r0 == r1 {
				return lhs + " " + opStr + " 0"
			}
		}
	}
	return ""
}

// formatCmpArgMapped 是 formatCmpArgFromInst 的增强版，支持寄存器→来源替换。
func formatCmpArgMapped(inst *disasm.Inst, arg x86asm.Arg, regMap map[string]string) string {
	return formatCmpArgWithMap(inst, arg, regMap)
}

// formatCmpArgFromInst 将汇编操作数格式化为可读字符串，无法格式化时返回空字符串。
func formatCmpArgFromInst(inst *disasm.Inst, arg x86asm.Arg) string {
	return formatCmpArgWithMap(inst, arg, nil)
}

func formatCmpArgWithMap(inst *disasm.Inst, arg x86asm.Arg, regMap map[string]string) string {
	if arg == nil {
		return ""
	}
	switch a := arg.(type) {
	case x86asm.Reg:
		name := canonicalRegName(a)
		if regMap != nil {
			if v, ok := regMap[name]; ok && strings.TrimSpace(v) != "" {
				return v
			}
		}
		return name
	case x86asm.Imm:
		v := int64(a)
		if v >= -512 && v <= 4096 {
			return fmt.Sprintf("%d", v)
		}
		return fmt.Sprintf("0x%x", uint64(a))
	case x86asm.Mem:
		if a.Segment != 0 {
			return ""
		}
		if a.Base == x86asm.RIP {
			if inst == nil {
				return ""
			}
			target := uint64(int64(inst.Addr) + int64(inst.Size) + int64(a.Disp))
			return fmt.Sprintf("[0x%x]", target)
		}
		var terms []string
		if a.Base != 0 {
			base := canonicalRegName(a.Base)
			if regMap != nil {
				if mapped, ok := regMap[base]; ok && isSimpleCmpAtom(mapped) {
					base = mapped
				}
			}
			terms = append(terms, base)
		}
		if a.Index != 0 {
			idx := canonicalRegName(a.Index)
			if regMap != nil {
				if mapped, ok := regMap[idx]; ok && isSimpleCmpAtom(mapped) {
					idx = mapped
				}
			}
			scale := int(a.Scale)
			if scale <= 0 {
				scale = 1
			}
			if scale != 1 {
				idx = fmt.Sprintf("(%s)*%d", idx, scale)
			}
			terms = append(terms, idx)
		}
		if len(terms) == 0 {
			if a.Disp > 0 {
				return fmt.Sprintf("[0x%x]", a.Disp)
			}
			if a.Disp < 0 {
				return fmt.Sprintf("[-0x%x]", -a.Disp)
			}
			return ""
		}
		expr := terms[0]
		for i := 1; i < len(terms); i++ {
			expr = fmt.Sprintf("(%s)+(%s)", expr, terms[i])
		}
		if a.Disp > 0 {
			expr = fmt.Sprintf("(%s)+0x%x", expr, a.Disp)
		} else if a.Disp < 0 {
			expr = fmt.Sprintf("(%s)-0x%x", expr, -a.Disp)
		}
		return "[" + expr + "]"
	}
	return ""
}

// findCmpInst 在基本块中向前查找紧挨 CondInst 的 CMP/TEST 指令。
// 跳过不修改标志的 MOV/LEA/NOP 等；遇到其他指令即停止搜索。
func findCmpInst(b *Block) *disasm.Inst {
	if b.CondInst == nil {
		return nil
	}
	for i := len(b.Insts) - 1; i >= 0; i-- {
		inst := b.Insts[i]
		if inst == b.CondInst {
			continue
		}
		op := inst.Op.Op
		if op == x86asm.CMP || op == x86asm.TEST {
			return inst
		}
		// 不修改标志寄存器的指令：继续向前扫描
		switch op {
		case x86asm.MOV, x86asm.LEA, x86asm.NOP:
			continue
		}
		// 其他指令可能修改标志，停止搜索
		return nil
	}
	return nil
}

// popTrailingIncr 从 stmts 末尾弹出连续的 StmtIncr，返回弹出的部分。
// 用于将 CMP 块末尾的自增语句移入 for-loop 体（保持语义正确性）。
func popTrailingIncr(stmts *[]*Stmt) []*Stmt {
	if stmts == nil {
		return nil
	}
	ss := *stmts
	end := len(ss)
	start := end
	for start > 0 && ss[start-1].Kind == StmtIncr {
		start--
	}
	if start == end {
		return nil
	}
	result := make([]*Stmt, end-start)
	copy(result, ss[start:end])
	*stmts = ss[:start]
	return result
}

func cloneVisited(v map[int]bool) map[int]bool {
	c := make(map[int]bool, len(v))
	for k, x := range v {
		c[k] = x
	}
	return c
}

func mergeVisited(dst, src map[int]bool) {
	for k, v := range src {
		dst[k] = v
	}
}

// canReach 报告从 start 是否能通过前向边到达 target。
func (cfg *CFG) canReach(start, target *Block) bool {
	if start == nil || target == nil {
		return false
	}
	seen := make(map[int]bool)
	var dfs func(*Block) bool
	dfs = func(b *Block) bool {
		if b == nil || seen[b.ID] {
			return false
		}
		if b == target {
			return true
		}
		seen[b.ID] = true
		for _, s := range b.Succs {
			if !b.IsBackEdge(s) && dfs(s) {
				return true
			}
		}
		return false
	}
	return dfs(start)
}

// quicklyTerminates 检查从 blk 出发，沿无条件边最多 maxSteps 步内是否到达 TermRet/TermIndirect。
// 遇到条件分支则尝试两侧都终止的情形。
func (cfg *CFG) quicklyTerminates(blk *Block, maxSteps int) bool {
	b := blk
	for step := 0; step < maxSteps && b != nil; step++ {
		switch b.Term {
		case TermRet, TermIndirect:
			return true
		case TermCond:
			// 若两条路径都快速终止（如 panic 路径中的 defer 判断），视为终止
			remaining := maxSteps - step - 1
			if remaining > 0 && len(b.Succs) >= 2 {
				if cfg.quicklyTerminates(b.Succs[0], remaining) &&
					cfg.quicklyTerminates(b.Succs[1], remaining) {
					return true
				}
			}
			return false
		case TermJmp:
			if len(b.Succs) == 0 {
				return true // 跳出函数范围，视为终止
			}
			next := b.Succs[0]
			if b.IsBackEdge(next) {
				// 后向 JMP：若目标是 TermRet/TermIndirect 或函数入口（morestack 后死代码），视为终止
				return next.Term == TermRet || next.Term == TermIndirect || next == cfg.Entry
			}
			b = next
		case TermFall:
			if len(b.Succs) == 0 {
				return false
			}
			b = b.Succs[0]
		default:
			return false
		}
	}
	return false
}

// negateCondStr 返回条件跳转的否定条件字符串。
// cmp 为可选的前置 CMP/TEST 指令；b 为当前基本块；inherited 为跨块继承的寄存器映射。
func negateCondStr(jcc, cmp *disasm.Inst, b *Block, inherited map[string]string) string {
	return buildCondStr(jcc, cmp, true, b, inherited)
}
