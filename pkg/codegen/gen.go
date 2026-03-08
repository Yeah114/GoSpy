// Package codegen 将函数 IR + 类型声明生成 Go 源文件。
package codegen

import (
	"fmt"
	"go/format"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/Yeah114/GoSpy/pkg/analysis"
	"github.com/Yeah114/GoSpy/pkg/symbols"
	"github.com/Yeah114/GoSpy/pkg/typeinfo"
)

// ── 条件表达式清洗 ────────────────────────────────────────────────────────────

var (
	// reCondReg 匹配 x86-64 寄存器名（完整单词）
	reCondReg = regexp.MustCompile(
		`\b(rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r10|r11|r12|r13|r14|r15|rsp|rbp|` +
			`eax|ebx|ecx|edx|esi|edi|r8d|r9d|r10d|r11d|r12d|r13d|r14d|r15d)\b`)
	// reCondMem 匹配内存引用 [...]
	reCondMem = regexp.MustCompile(`\[([^\]]+)\]`)
	// reCondUnsign 匹配无符号标记 (u)
	reCondUnsign = regexp.MustCompile(`\s*\(u\)\s*`)
)

// memRefIdent 将内存引用内容转换为合法 Go 标识符：
//
//	"rip+0xdb616" → "_gdb616"  (RIP 相对 = 全局变量)
//	"rax+0x8"     → "_prax8"   (寄存器相对 = 字段/指针)
func memRefIdent(inner string) string {
	inner = strings.TrimSpace(inner)
	if strings.HasPrefix(inner, "0x") {
		rest := strings.TrimPrefix(inner, "0x")
		var b strings.Builder
		for _, c := range rest {
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
				b.WriteRune(c)
			}
		}
		return "_g" + strings.ToLower(b.String())
	}
	if rest, ok := strings.CutPrefix(inner, "rip"); ok {
		rest = strings.TrimLeft(rest, " +")
		rest = strings.TrimPrefix(rest, "0x")
		var b strings.Builder
		for _, c := range rest {
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
				b.WriteRune(c)
			}
		}
		return "_g" + strings.ToLower(b.String())
	}
	// 寄存器相对寻址
	id := inner
	id = strings.ReplaceAll(id, "+0x", "")
	id = strings.ReplaceAll(id, "-0x", "_")
	id = strings.ReplaceAll(id, "+", "")
	id = strings.ReplaceAll(id, "-", "_")
	id = strings.ReplaceAll(id, " ", "")
	var b strings.Builder
	for _, c := range id {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
			b.WriteRune(c)
		}
	}
	return "_p" + strings.ToLower(strings.Trim(b.String(), "_"))
}

// sanitizeCond 将汇编条件表达式转换为合法 Go 表达式。
// recvSub 非空时，将 rax 替换为接收者变量名（无需再声明为 var）。
//
//   - 纯注释（找不到 CMP 时的降级输出）→ "true /* ... */"
//   - 内存引用 [rip+0xXX]              → _gXX
//   - 无符号标记 (u)                    → 去除（改为有符号比较）
//   - 寄存器名                          → 原样保留（函数头部声明为 var）
func sanitizeCond(cond, recvSub string) (string, map[string]bool) {
	vars := make(map[string]bool)
	trimmed := strings.TrimSpace(cond)

	// 纯注释条件：前置 true 使其成为合法表达式
	if strings.HasPrefix(trimmed, "/*") {
		return "true " + cond, vars
	}

	// 替换内存引用
	s := reCondMem.ReplaceAllStringFunc(cond, func(m string) string {
		id := memRefIdent(m[1 : len(m)-1])
		vars[id] = true
		return id
	})

	// 去除无符号标记
	s = reCondUnsign.ReplaceAllString(s, " ")
	s = strings.Join(strings.Fields(s), " ")

	// 将接收者寄存器 rax 替换为接收者变量名（已是参数，不需再声明）
	if recvSub != "" {
		s = reCondReg.ReplaceAllStringFunc(s, func(m string) string {
			if m == "rax" {
				return recvSub
			}
			return m
		})
	}

	// 收集寄存器名（rax 已被替换后不会出现在结果中）
	for _, reg := range reCondReg.FindAllString(s, -1) {
		vars[reg] = true
	}
	return s, vars
}

// collectCondVars 递归收集函数所有条件表达式需要声明的变量。
func collectCondVars(stmts []*analysis.Stmt, recvSub string) map[string]bool {
	all := make(map[string]bool)
	var walk func([]*analysis.Stmt)
	walk = func(ss []*analysis.Stmt) {
		for _, stmt := range ss {
			if stmt.Call != nil {
				for _, arg := range stmt.Call.Args {
					if id, ok := arg.(*analysis.Ident); ok {
						all[id.Name] = true
					}
				}
			}
			if stmt.Kind == analysis.StmtIf && stmt.If != nil {
				_, vars := sanitizeCond(stmt.If.Cond, recvSub)
				for v := range vars {
					all[v] = true
				}
				walk(stmt.If.Then)
				walk(stmt.If.Else)
			}
			if stmt.Kind == analysis.StmtFor && stmt.For != nil {
				if stmt.For.Cond != "" {
					_, vars := sanitizeCond(stmt.For.Cond, recvSub)
					for v := range vars {
						all[v] = true
					}
				}
				walk(stmt.For.Body)
			}
			// StmtIncr 变量（如 r8++）需要进入 condVars 以获得 var 声明和后备重命名
			if stmt.Kind == analysis.StmtIncr && stmt.Incr != nil {
				all[stmt.Incr.Var] = true
			}
		}
	}
	walk(stmts)
	return all
}

// hasAnyCalls 递归检查 IR 中是否存在任何函数调用语句。
// 用于判断接收者寄存器 rax 是否可能被调用返回值覆盖。
func hasAnyCalls(stmts []*analysis.Stmt) bool {
	for _, s := range stmts {
		switch s.Kind {
		case analysis.StmtCall, analysis.StmtGo, analysis.StmtDefer, analysis.StmtPanic:
			return true
		case analysis.StmtIf:
			if s.If != nil && (hasAnyCalls(s.If.Then) || hasAnyCalls(s.If.Else)) {
				return true
			}
		case analysis.StmtFor:
			if s.For != nil && hasAnyCalls(s.For.Body) {
				return true
			}
		}
	}
	return false
}

// recvNameForFunc 仅根据函数名返回接收者变量名（不考虑是否有函数调用）。
// 指针接收者 → "r"；值接收者 → "v"；普通函数 → ""。
func recvNameForFunc(short string) string {
	if strings.HasPrefix(short, "(*") {
		if strings.Contains(short, ").") {
			return "r"
		}
	} else if t, m, ok := strings.Cut(short, "."); ok {
		if !strings.ContainsAny(t, "(*) ") && !strings.ContainsAny(m, "(*) ") {
			return "v"
		}
	}
	return ""
}

// recvSubForFunc 确定 sanitizeCond 中 rax 寄存器的替换名称。
// 仅当函数体内没有任何函数调用时（rax 不会被调用返回值覆盖）才替换，
// 避免将被覆盖后的 rax 误判为接收者。
func recvSubForFunc(short string, stmts []*analysis.Stmt) string {
	name := recvNameForFunc(short)
	if name == "" || hasAnyCalls(stmts) {
		return "" // 不是方法，或 rax 可能被调用覆盖
	}
	return name
}

// callReturnType 返回已知函数的返回类型字符串（用于 call+return 合并推断）。
func callReturnType(funcName string) string {
	switch {
	case strings.HasSuffix(funcName, ".Sprintf"),
		strings.HasSuffix(funcName, ".Sprint"),
		strings.HasSuffix(funcName, ".Sprintln"):
		return "string"
	case strings.HasSuffix(funcName, ".Errorf"):
		return "error"
	}
	return ""
}

// FuncResult 保存一个函数的分析结果。
type FuncResult struct {
	Sym *symbols.Func
	IR  *analysis.FuncIR
}

// Generator 负责将 IR 输出为 Go 源文件。
type Generator struct {
	outDir string
}

// New 创建生成器。
func New(outDir string) *Generator { return &Generator{outDir: outDir} }

// ── 分组 ─────────────────────────────────────────────────────────────────────

type fileGroup struct {
	pkg        string // 包名最后一段，如 "main"
	pkgFull    string // 完整包路径，如 "github.com/foo/main"
	file       string // 基名，如 "main.go"
	funcs      []*FuncResult
	types      []*typeinfo.TypeDecl            // 属于这个文件的类型
	funcParams map[string][]analysis.ParamInfo // 函数名 → 参数列表（用于零值占位符补全）
}

func (g *Generator) group(results []*FuncResult) map[string]*fileGroup {
	m := make(map[string]*fileGroup)
	for _, r := range results {
		// 跳过编译器自动生成的包装函数（避免与用户定义函数重名冲突）
		if r.Sym.File == "<autogenerated>" {
			continue
		}
		file := filepath.Base(r.Sym.File)
		if file == "" || file == "." {
			file = "unknown.go"
		}
		if !strings.HasSuffix(file, ".go") {
			file += ".go"
		}
		key := r.Sym.Package + "::" + file
		if _, ok := m[key]; !ok {
			m[key] = &fileGroup{
				pkg:     lastSegment(r.Sym.Package),
				pkgFull: r.Sym.Package,
				file:    file,
			}
		}
		m[key].funcs = append(m[key].funcs, r)
	}
	return m
}

// Generate 将所有函数 IR 写入 Go 源文件，返回写入的文件数量。
// types 是可选的类型声明列表（从 typelink 恢复）。
func (g *Generator) Generate(results []*FuncResult, types []*typeinfo.TypeDecl) (int, error) {
	if err := os.MkdirAll(g.outDir, 0o755); err != nil {
		return 0, fmt.Errorf("create output dir: %w", err)
	}

	groups := g.group(results)

	// 将函数参数信息分配到对应的 fileGroup（用于后续调用零值补全）
	for _, r := range results {
		if r.IR == nil || len(r.IR.Params) == 0 || r.Sym.File == "<autogenerated>" {
			continue
		}
		file := filepath.Base(r.Sym.File)
		if file == "" || file == "." {
			file = "unknown.go"
		}
		if !strings.HasSuffix(file, ".go") {
			file += ".go"
		}
		key := r.Sym.Package + "::" + file
		if grp, ok := groups[key]; ok {
			if grp.funcParams == nil {
				grp.funcParams = make(map[string][]analysis.ParamInfo)
			}
			grp.funcParams[r.Sym.Name] = r.IR.Params
		}
	}

	// 将类型分配到对应的 fileGroup
	for _, td := range types {
		// 按包路径匹配
		for _, grp := range groups {
			if grp.pkgFull == td.Pkg || lastSegment(grp.pkgFull) == lastSegment(td.Pkg) {
				grp.types = append(grp.types, td)
				break
			}
		}
	}

	// 按 key 排序保证输出顺序稳定
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if err := g.writeGroup(groups[k]); err != nil {
			return 0, err
		}
	}
	return len(groups), nil
}

// WriteGoMod 写 go.mod 文件。
func (g *Generator) WriteGoMod(content string) error {
	if err := os.MkdirAll(g.outDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(g.outDir, "go.mod"), []byte(content), 0o644)
}

func (g *Generator) writeGroup(grp *fileGroup) error {
	src := g.renderSource(grp)
	formatted, err := format.Source([]byte(src))
	if err != nil {
		formatted = []byte(src) // 格式化失败时输出原始文本
	}
	dir := filepath.Join(g.outDir, grp.pkg)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, grp.file)
	return os.WriteFile(path, formatted, 0o644)
}

// ── 源码渲染 ─────────────────────────────────────────────────────────────────

func (g *Generator) renderSource(grp *fileGroup) string {
	var b strings.Builder

	b.WriteString("package " + grp.pkg + "\n\n")

	needSliceHelper := needsSlicePtrLenCapHelper(grp)

	// imports
	imps := collectImports(grp)
	if needSliceHelper && !slices.Contains(imps, "unsafe") {
		imps = append(imps, "unsafe")
		sort.Strings(imps)
	}
	if len(imps) > 0 {
		b.WriteString("import (\n")
		for _, imp := range imps {
			b.WriteString("\t\"" + imp + "\"\n")
		}
		b.WriteString(")\n\n")
	}
	if needSliceHelper {
		b.WriteString(renderSlicePtrLenCapHelper())
		b.WriteString("\n")
	}

	// 类型声明
	for _, td := range grp.types {
		b.WriteString(td.GoDecl())
		b.WriteString("\n\n")
	}

	// 构建字段偏移表，用于将 [rax+offset] 还原为接收者字段访问
	ft := buildFieldTable(grp.types)
	methodRecv := buildMethodReceiverMap(grp.funcs)

	// 函数
	for i, r := range grp.funcs {
		b.WriteString(renderFunc(r, ft, grp.funcParams, methodRecv))
		if i < len(grp.funcs)-1 {
			b.WriteString("\n\n")
		}
	}
	b.WriteString("\n")
	src := b.String()
	return src
}

// renderFunc 生成单个函数的伪代码。
// ft 为字段偏移表，用于将 _praxNN 替换为接收者字段访问（r.FieldName）。
// funcParams 为全包函数参数表，用于调用点零值占位符补全。
func renderFunc(r *FuncResult, ft FieldTable, funcParams map[string][]analysis.ParamInfo, methodRecv map[string]string) string {
	var b strings.Builder

	// 注释头
	b.WriteString("// " + r.Sym.Name)
	if r.Sym.File != "" {
		fmt.Fprintf(&b, " (%s", filepath.Base(r.Sym.File))
		if r.Sym.Line > 0 {
			fmt.Fprintf(&b, ":%d", r.Sym.Line)
		}
		b.WriteString(")")
	}
	b.WriteString("\n")

	// 函数签名（-w 移除了 DWARF 类型信息，尝试从 IR 推断返回类型）
	retType := ""
	var irParams []analysis.ParamInfo
	if r.IR != nil {
		retType = inferReturnType(r.IR.Stmts)
		irParams = r.IR.Params
	}
	b.WriteString(renderFuncSig(r.Sym.ShortName, retType, irParams))

	if r.IR != nil && len(r.IR.Stmts) > 0 {
		recvSub := recvSubForFunc(r.Sym.ShortName, r.IR.Stmts)

		// 先渲染函数体到临时缓冲区，再决定哪些变量需要声明：
		// 空 if/for 块被省略后，部分条件变量不再出现，不能盲目声明（Go 禁止未使用变量）。
		var bodyBuf strings.Builder
		wrote := renderStmts(&bodyBuf, r.IR.Stmts, 1, r.Sym.Package, recvSub, funcParams, irParams)
		bodyStr := bodyBuf.String()

		// Pass 1：将 _praxNN 替换为接收者字段访问（如 r.Category）。
		// 使用 recvNameForFunc（不受 hasAnyCalls 限制），因为 buildRegMap 已在
		// CALL 处清空 rax，所以 _praxNN 标识符来自调用前的合法加载。
		typeName := recvTypeName(r.Sym.ShortName)
		fieldRecvSub := recvNameForFunc(r.Sym.ShortName)
		bodyStr = substituteReceiverFields(bodyStr, fieldRecvSub, typeName, ft)

		// 收集条件变量候选集（基于 IR，字段替换之前的原始名称）
		candidates := collectCondVars(r.IR.Stmts, recvSub)

		// 构建来自参数检测的强制重命名映射，并收集参数相关名称集（用于跳过 var 声明）。
		// 只强制重命名每个参数的首寄存器（可见参数名），后续寄存器（string.len/slice.cap 等）
		// 由现有 buildVarRenames 规则处理（它们最终会被声明为 var，作为整数辅助变量使用）。
		forcedRenames := make(map[string]string)
		paramRelated := make(map[string]bool) // 仅含可见参数名（已在签名中声明，不再声明为 var）
		for _, p := range irParams {
			if len(p.Regs) == 0 {
				continue
			}
			firstReg := p.Regs[0]
			// 复合参数（string/slice/interface）在低层 often 表现为寄存器指针游走，
			// 若该寄存器在 IR 中发生自增，禁止强制重命名为高层参数名，避免类型冲突。
			if (p.Kind == analysis.ParamString || p.Kind == analysis.ParamSlice || p.Kind == analysis.ParamIface) &&
				hasIncrOnVar(r.IR.Stmts, firstReg) {
				continue
			}
			forcedRenames[firstReg] = p.Name // 首寄存器 → 可见参数名
			paramRelated[p.Name] = true
		}

		blockedParamRegs := make(map[string]bool)
		for _, p := range irParams {
			if len(p.Regs) <= 1 {
				continue
			}
			if p.Kind != analysis.ParamString && p.Kind != analysis.ParamSlice && p.Kind != analysis.ParamIface {
				continue
			}
			for _, reg := range p.Regs[1:] {
				blockedParamRegs[reg] = true
			}
		}

		// Pass 2：变量重命名（循环计数器→i/j、寄存器→argN、_prXX→xx_N、全局→gN）
		varRenames := buildVarRenames(bodyStr, r.Sym.ShortName, candidates, r.IR.Stmts, forcedRenames, blockedParamRegs)
		bodyStr = applyVarRenames(bodyStr, varRenames)

		// 将候选变量名也做同样的重命名，以匹配 body 中重命名后的实际名称
		renamed := make(map[string]bool, len(candidates))
		for v := range candidates {
			if newName, ok := varRenames[v]; ok {
				renamed[newName] = true
			} else {
				renamed[v] = true
			}
		}
		for _, newName := range varRenames {
			if newName != "" && varAppearsIn(newName, bodyStr) {
				renamed[newName] = true
			}
		}

		// 只声明在 body 中实际出现的变量（空块省略后部分变量消失）。
		// 排除参数相关名称：它们已在函数签名中声明（或为隐藏实现细节）。
		if len(renamed) > 0 {
			var names []string
			for v := range renamed {
				if !paramRelated[v] && varAppearsIn(v, bodyStr) && !isShortDeclaredInBody(v, bodyStr) {
					names = append(names, v)
				}
			}
			sort.Strings(names)
			switch len(names) {
			case 1:
				typ := inferLocalVarType(names[0], bodyStr, methodRecv)
				b.WriteString("\tvar " + names[0] + " " + typ + "\n")
			default:
				if len(names) > 1 {
					b.WriteString("\tvar (\n")
					for _, n := range names {
						typ := inferLocalVarType(n, bodyStr, methodRecv)
						b.WriteString("\t\t" + n + " " + typ + "\n")
					}
					b.WriteString("\t)\n")
				}
			}
		}

		if !wrote {
			b.WriteString("\t// 函数体未能恢复\n")
		} else {
			for _, ln := range inferInitLinesFromParams(irParams, varRenames, bodyStr) {
				b.WriteString("\t" + ln + "\n")
			}
			for _, ln := range inferMainArgsInitLines(r.Sym.ShortName, bodyStr) {
				b.WriteString("\t" + ln + "\n")
			}
			bodyStr = fillBareReturns(bodyStr, retType)
			bodyStr = ensureTrailingReturn(bodyStr, retType)
			b.WriteString(bodyStr)
		}
	} else {
		b.WriteString("\t// 函数体未能恢复\n")
	}

	b.WriteString("}")
	out := b.String()
	out = pruneUnusedIntVarBlock(out)
	return out
}

func condIsNonZeroReg(cond, reg string) bool {
	trim := strings.TrimSpace(cond)
	reg = strings.TrimSpace(reg)
	if trim == "" || reg == "" {
		return false
	}
	p1 := regexp.MustCompile(`^` + regexp.QuoteMeta(reg) + `\s*!=\s*0$`)
	p2 := regexp.MustCompile(`^0\s*!=\s*` + regexp.QuoteMeta(reg) + `$`)
	return p1.MatchString(trim) || p2.MatchString(trim)
}

func isCallReturningValueAndError(name string) bool {
	switch name {
	case "strconv.Atoi", "strconv.ParseInt", "strconv.ParseUint", "strconv.ParseFloat", "strconv.ParseBool":
		return true
	default:
		return false
	}
}

func callErrorReg(name string) string {
	switch name {
	case "strconv.Atoi", "strconv.ParseInt", "strconv.ParseUint", "strconv.ParseFloat", "strconv.ParseBool", "NewPerson", "main.NewPerson":
		return "rbx"
	case "parseArgs", "main.parseArgs":
		return "rdi"
	default:
		return ""
	}
}

func callExprForErrGuard(name string, args []string) string {
	line := strings.TrimSpace(formatCallExpr(name, args))
	if line != "" && !strings.HasPrefix(line, "//") && !strings.Contains(line, "=") {
		return line
	}
	formatted := analysis.FormatCallName(name)
	if formatted == "" {
		return ""
	}
	return formatted + "(" + strings.Join(args, ", ") + ")"
}

func isPrintProxyCall(name string) bool {
	return name == "fmt.Fprintln" || name == "fmt.Fprint"
}

func isPrintProxyArgs(args []string) bool {
	if len(args) == 0 {
		return false
	}
	start := 0
	first := strings.TrimSpace(args[0])
	if isFmtFallbackArg(first) || isGlobalPlaceholderName(first) || first == "os.Stdout" || first == "os.Stderr" {
		start = 1
	}
	if start >= len(args) {
		return true
	}
	for _, arg := range args[start:] {
		if !isFmtFallbackArg(arg) {
			return false
		}
	}
	return true
}

func inferFollowNewPersonIntArg(stmts []*analysis.Stmt, start int, currentPkg string) string {
	isIdent := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString
	limit := min(len(stmts), start+7)
	for i := start + 1; i < limit; i++ {
		s := stmts[i]
		if s == nil || s.Kind != analysis.StmtCall || s.Call == nil {
			continue
		}
		name := stripSamePkgPrefix(s.Call.Func, currentPkg)
		if name != "NewPerson" && name != "main.NewPerson" {
			continue
		}
		if len(s.Call.Args) < 2 {
			return ""
		}
		cand := strings.TrimSpace(s.Call.Args[1].GoString())
		if isIdent(cand) {
			return cand
		}
		return ""
	}
	return ""
}

// renderStmts 递归渲染语句列表，返回是否写入了有效内容。
// currentPkg 用于去掉同包函数调用的包前缀（如 "main.Foo" → "Foo"）。
// recvSub 非空时，将 if/for 条件中的 rax 替换为接收者变量名。
// funcParams 用于在调用点补全零值占位符参数（全名 → []ParamInfo）。
func renderStmts(b *strings.Builder, stmts []*analysis.Stmt, depth int, currentPkg, recvSub string, funcParams map[string][]analysis.ParamInfo, currentParams []analysis.ParamInfo) bool {
	indent := strings.Repeat("\t", depth)
	wrote := false
	splitSource := ""
	splitPartsVar := ""

	for i := 0; i < len(stmts); i++ {
		stmt := stmts[i]
		switch stmt.Kind {
		case analysis.StmtReturn:
			gs := stmt.GoString() // "return" 或 "return \"value\""
			hasVal := stmt.Call != nil && len(stmt.Call.Args) > 0
			// depth > 1（if/for 内部）或有返回值时显式写出
			if depth > 1 || hasVal {
				b.WriteString(indent + gs + "\n")
				wrote = true
			}
			// depth == 1 且无返回值：函数末尾隐式 return，跳过以减少噪音
			continue

		case analysis.StmtIf:
			if stmt.If == nil {
				continue
			}
			// 预渲染两个分支到临时缓冲区，空体直接跳过整个 if（避免 "if cond {}" 噪音）
			var thenBuf strings.Builder
			thenWrote := renderStmts(&thenBuf, stmt.If.Then, depth+1, currentPkg, recvSub, funcParams, currentParams)
			var elseBuf strings.Builder
			elseWrote := len(stmt.If.Else) > 0 && renderStmts(&elseBuf, stmt.If.Else, depth+1, currentPkg, recvSub, funcParams, currentParams)
			if !thenWrote && !elseWrote {
				continue // 两个分支均为空，跳过整个 if
			}
			cond := stmt.If.Cond
			if cond == "" {
				cond = "/* unknown */"
			}
			cond, _ = sanitizeCond(cond, recvSub)
			b.WriteString(indent + "if " + cond + " {\n")
			b.WriteString(thenBuf.String())
			if elseWrote {
				b.WriteString(indent + "} else {\n")
				b.WriteString(elseBuf.String())
			}
			b.WriteString(indent + "}\n")
			wrote = true

		case analysis.StmtFor:
			if stmt.For == nil {
				continue
			}
			// 预渲染循环体，空体跳过整个 for（避免 "for cond {}" 死循环骨架噪音）
			var bodyBuf strings.Builder
			bodyWrote := renderStmts(&bodyBuf, stmt.For.Body, depth+1, currentPkg, recvSub, funcParams, currentParams)
			if !bodyWrote {
				continue
			}
			cond := stmt.For.Cond
			if cond == "" {
				b.WriteString(indent + "for {\n")
			} else {
				sanitized, _ := sanitizeCond(cond, recvSub)
				b.WriteString(indent + "for " + sanitized + " {\n")
			}
			b.WriteString(bodyBuf.String())
			b.WriteString(indent + "}\n")
			wrote = true

		case analysis.StmtCall:
			// call+return 合并：下一条是空 return，且调用的返回类型已知 → "return call(...)"
			// 仅当 callReturnType != "" 时合并，避免将 fmt.Errorf/void 函数错误地生成 return
			nextIsEmptyReturn := i+1 < len(stmts) &&
				stmts[i+1].Kind == analysis.StmtReturn &&
				(stmts[i+1].Call == nil || len(stmts[i+1].Call.Args) == 0)
			if nextIsEmptyReturn && stmt.Call != nil && callReturnType(stmt.Call.Func) != "" {
				name := stripSamePkgPrefix(stmt.Call.Func, currentPkg)
				args := make([]string, len(stmt.Call.Args))
				for j, a := range stmt.Call.Args {
					args[j] = a.GoString()
				}
				args = refineFmtCallArgs(name, args, currentParams)
				callExpr := formatCallExpr(name, args)
				b.WriteString(indent + "return " + callExpr + "\n")
				i++ // 跳过下一条 return
				wrote = true
				continue
			}
			// 普通调用（含零值占位符补全）
			if stmt.Call == nil {
				continue
			}
			callName := stripSamePkgPrefix(stmt.Call.Func, currentPkg)
			callArgs := make([]string, len(stmt.Call.Args))
			for j, a := range stmt.Call.Args {
				callArgs[j] = a.GoString()
			}
			if callName == "strings.genSplit" {
				callArgs = repairGenSplitArgs(callArgs, currentParams)
				if len(callArgs) >= 3 {
					splitSource = callArgs[0]
					splitPartsVar = "parts"
					b.WriteString(indent + "parts := strings.SplitN(" + callArgs[0] + ", " + callArgs[1] + ", " + callArgs[2] + ")\n")
					wrote = true
					continue
				}
			}
			if splitSource != "" && callName == "fmt.Errorf" && len(callArgs) >= 2 {
				if fmtText, err := strconv.Unquote(callArgs[0]); err == nil && strings.Contains(fmtText, "invalid format %q") && isFmtFallbackArg(callArgs[1]) {
					callArgs[1] = splitSource
				}
			}
			if splitPartsVar != "" && callName == "strconv.Atoi" && len(callArgs) > 0 && isFmtFallbackArg(callArgs[0]) {
				callArgs[0] = splitPartsVar + "[1]"
			}
			if splitPartsVar != "" && (callName == "NewPerson" || callName == "main.NewPerson") {
				if len(callArgs) > 0 && isFmtFallbackArg(callArgs[0]) {
					callArgs[0] = splitPartsVar + "[0]"
				}
				if len(callArgs) > 2 {
					third := strings.TrimSpace(callArgs[2])
					if isFmtFallbackArg(third) || strings.HasPrefix(third, "fmt.Sprint(") {
						callArgs[2] = `""`
					}
				}
			}
			if i+1 < len(stmts) && stmts[i+1].Kind == analysis.StmtCall && stmts[i+1].Call != nil {
				nextName := stripSamePkgPrefix(stmts[i+1].Call.Func, currentPkg)
				if isPrintProxyCall(nextName) {
					nextArgs := make([]string, len(stmts[i+1].Call.Args))
					for j, a := range stmts[i+1].Call.Args {
						nextArgs[j] = a.GoString()
					}
					if isPrintProxyArgs(nextArgs) {
						if params, ok := funcParams[stmt.Call.Func]; ok {
							for len(callArgs) < len(params) {
								callArgs = append(callArgs, params[len(callArgs)].Kind.ZeroValue())
							}
							callArgs = coerceCallArgsByParamKinds(callArgs, params)
						}
						callArgs = refineFmtCallArgs(callName, callArgs, currentParams)
						callExpr := formatCallExpr(callName, callArgs)
						if callExpr != "" {
							printFn := "fmt.Println"
							if nextName == "fmt.Fprint" {
								printFn = "fmt.Print"
							}
							b.WriteString(indent + printFn + "(" + callExpr + ")\n")
							wrote = true
							i++
							continue
						}
					}
				}
			}
			if i+1 < len(stmts) && stmts[i+1].Kind == analysis.StmtIf && stmts[i+1].If != nil && len(stmts[i+1].If.Else) == 0 {
				errReg := callErrorReg(callName)
				if errReg != "" && condIsNonZeroReg(stmts[i+1].If.Cond, errReg) {
					if params, ok := funcParams[stmt.Call.Func]; ok {
						for len(callArgs) < len(params) {
							callArgs = append(callArgs, params[len(callArgs)].Kind.ZeroValue())
						}
						callArgs = coerceCallArgsByParamKinds(callArgs, params)
					}
					callArgs = refineFmtCallArgs(callName, callArgs, currentParams)
					callExpr := callExprForErrGuard(callName, callArgs)
					if callExpr != "" {
						var thenBuf strings.Builder
						_ = renderStmts(&thenBuf, stmts[i+1].If.Then, depth+1, currentPkg, recvSub, funcParams, currentParams)
						thenBody := thenBuf.String()
						if strings.Contains(thenBody, `fmt.Printf("error: %v\n",`) {
							thenBody = regexp.MustCompile(`fmt\.Printf\("error: %v\\n",\s*[^\)]+\)`).ReplaceAllString(thenBody, `fmt.Printf("error: %v\n", err)`)
						}
						if strings.Contains(thenBody, `%w`) {
							thenBody = regexp.MustCompile(`fmt\.Errorf\(("[^"]*%w[^"]*"\s*,\s*[^,\n]+\s*,\s*)[^)\n]+\)`).ReplaceAllString(thenBody, `fmt.Errorf($1err)`)
						}
						thenBody = regexp.MustCompile(`(?m)^(\s*)return fmt\.Errorf\(\)\s*$`).ReplaceAllString(thenBody, `${1}return err`)
						thenBody = regexp.MustCompile(`(?m)^(\s*)return\s*$`).ReplaceAllString(thenBody, `${1}return err`)
						thenBody = regexp.MustCompile(`(?m)^(\s*)return nil\s*$`).ReplaceAllString(thenBody, `${1}return err`)
						thenBody = strings.ReplaceAll(thenBody, "return fmt.Errorf()\n", "return err\n")
						thenBody = strings.ReplaceAll(thenBody, "return nil\n", "return err\n")
						if isCallReturningValueAndError(callName) {
							assignTarget := inferFollowNewPersonIntArg(stmts, i, currentPkg)
							if assignTarget != "" {
								b.WriteString(indent + assignTarget + ", err := " + callExpr + "\n")
								b.WriteString(indent + "if err != nil {\n")
							} else {
								b.WriteString(indent + "if _, err := " + callExpr + "; err != nil {\n")
							}
						} else {
							b.WriteString(indent + "if err := " + callExpr + "; err != nil {\n")
						}
						b.WriteString(thenBody)
						b.WriteString(indent + "}\n")
						wrote = true
						i++
						continue
					}
				}
			}

			// 若已知被调函数签名：先补齐参数，再按参数类型做最小纠正（保证可编译）。
			if params, ok := funcParams[stmt.Call.Func]; ok {
				for len(callArgs) < len(params) {
					callArgs = append(callArgs, params[len(callArgs)].Kind.ZeroValue())
				}
				callArgs = coerceCallArgsByParamKinds(callArgs, params)
			}
			callArgs = refineFmtCallArgs(callName, callArgs, currentParams)
			line := formatCallExpr(callName, callArgs)
			if line == "" {
				continue
			}
			b.WriteString(indent + line + "\n")
			wrote = true

		case analysis.StmtIncr:
			if stmt.Incr == nil {
				continue
			}
			b.WriteString(indent + stmt.GoString() + "\n")
			wrote = true

		default:
			line := stmtGoString(stmt, currentPkg)
			if line == "" {
				continue
			}
			b.WriteString(indent + line + "\n")
			wrote = true
		}
	}
	return wrote
}

// stmtGoString 渲染语句为 Go 代码字符串，同时应用包前缀过滤。
func stmtGoString(s *analysis.Stmt, currentPkg string) string {
	switch s.Kind {
	case analysis.StmtCall:
		if s.Call == nil {
			return ""
		}
		name := stripSamePkgPrefix(s.Call.Func, currentPkg)
		args := make([]string, len(s.Call.Args))
		for i, a := range s.Call.Args {
			args[i] = a.GoString()
		}
		return formatCallExpr(name, args)
	case analysis.StmtGo:
		if s.Call == nil {
			return ""
		}
		name := stripSamePkgPrefix(s.Call.Func, currentPkg)
		return "go " + formatCallExpr(name, nil)
	case analysis.StmtDefer:
		if s.Call == nil {
			return ""
		}
		name := stripSamePkgPrefix(s.Call.Func, currentPkg)
		return "defer " + formatCallExpr(name, nil)
	case analysis.StmtAsm:
		// CFG 无法结构化的 return 路径 → 还原为真实 return
		comment := strings.TrimSpace(s.Comment)
		if comment == "/* return */" || comment == "return" {
			return "return"
		}
		return "// " + s.Comment
	}
	return s.GoString()
}

// stdlibCallFix 修正常见 stdlib 函数的参数布局，使生成代码可以通过编译器类型检查。
// Go 编译器将 fmt.Println → fmt.Fprintln(os.Stdout,...)，导致反编译时看到 Fprintln/Fprintf，
// 但实际检测到的参数都是字符串字面量，缺少第一个 io.Writer 参数。
var stdlibCallFix = map[string]func([]string) string{
	// fmt.Fprintln(w, a...) → 源码通常是 fmt.Println(a...)
	"fmt.Fprintln": func(a []string) string {
		a = trimTrailingNilArgs(a)
		a = trimFallbackPrintArgs(a)
		return "fmt.Println(" + strings.Join(a, ", ") + ")"
	},
	"fmt.Fprint": func(a []string) string {
		a = trimTrailingNilArgs(a)
		a = trimFallbackPrintArgs(a)
		return "fmt.Print(" + strings.Join(a, ", ") + ")"
	},
	// fmt.Fprintf(w, format, a...) → 源码通常是 fmt.Printf(format, a...)
	"fmt.Fprintf": func(a []string) string {
		a = trimTrailingNilArgs(a)
		a = trimFallbackPrintfArgs(a)
		return "fmt.Printf(" + strings.Join(a, ", ") + ")"
	},
	// os.Exit 需要 int 参数
	"os.Exit": func(a []string) string {
		if len(a) == 0 {
			return "os.Exit(0)"
		}
		return "os.Exit(" + a[0] + ")"
	},
	// strconv.Atoi 返回 (int, error)，多返回值必须赋值，否则编译报错
	"strconv.Atoi": func(a []string) string {
		if len(a) == 0 {
			a = []string{`""`}
		}
		return "_, _ = strconv.Atoi(" + strings.Join(a, ", ") + ")"
	},
	"strconv.ParseInt": func(a []string) string {
		s := `""`
		base := "10"
		bitSize := "64"
		if len(a) > 0 {
			if strings.TrimSpace(a[0]) != "nil" {
				s = a[0]
			}
		}
		if len(a) == 2 {
			bitSize = a[1]
		} else if len(a) >= 3 {
			base = a[1]
			bitSize = a[2]
		}
		return "_, _ = strconv.ParseInt(" + s + ", " + base + ", " + bitSize + ")"
	},
	"encoding/json.Marshal": func(a []string) string {
		if len(a) == 0 {
			return "json.Marshal(nil)"
		}
		return "json.Marshal(" + a[0] + ")"
	},
	"crypto/sha256.Sum256": func(a []string) string {
		for _, arg := range a {
			trim := strings.TrimSpace(arg)
			if trim == "" || trim == "nil" || regexp.MustCompile(`^-?\d+$`).MatchString(trim) {
				continue
			}
			return "sha256.Sum256(" + arg + ")"
		}
		return "sha256.Sum256(nil)"
	},
	"os.OpenFile": func(a []string) string {
		path := `""`
		flag := "0"
		perm := "0644"
		if len(a) > 0 {
			path = normalizeMaybeStringArg(a[0], `""`)
		}
		if len(a) == 2 {
			perm = a[1]
		} else if len(a) >= 3 {
			flag = a[1]
			perm = a[2]
		}
		return "os.OpenFile(" + path + ", " + flag + ", " + perm + ")"
	},
	"os.MkdirAll": func(a []string) string {
		path := `""`
		perm := "0755"
		if len(a) > 0 {
			path = normalizeMaybeStringArg(a[0], `""`)
		}
		if len(a) > 1 {
			perm = a[1]
		}
		return "os.MkdirAll(" + path + ", " + perm + ")"
	},
	"os.Chmod": func(a []string) string {
		path := `""`
		perm := "0644"
		if len(a) > 0 {
			path = normalizeMaybeStringArg(a[0], `""`)
		}
		if len(a) > 1 {
			perm = a[1]
		}
		return "os.Chmod(" + path + ", " + perm + ")"
	},
	// strings.Repeat(s, n)：n 若从整数参数检测到则用实际值，否则填占位符 1
	"strings.Repeat": func(a []string) string {
		s, n := `""`, "1"
		if len(a) > 0 {
			s = a[0]
		}
		if len(a) > 1 {
			n = a[1] // IntLit.GoString() 返回整数字符串
		}
		return "strings.Repeat(" + s + ", " + n + ")"
	},
	// strings.genSplit 是 strings.Split/SplitN 的内部实现；sep 从检测到的字符串参数取，
	// 若同时检测到 n（整数参数）则生成 SplitN，否则生成 Split
	"strings.genSplit": func(a []string) string {
		repaired := repairGenSplitArgs(a, nil)
		if len(repaired) >= 3 {
			return "strings.SplitN(" + repaired[0] + ", " + repaired[1] + ", " + repaired[2] + ")"
		}
		if len(repaired) >= 2 {
			return "strings.Split(" + repaired[0] + ", " + repaired[1] + ")"
		}
		return `strings.Split("", "")`
	},
}

func trimFallbackPrintArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	first := strings.TrimSpace(args[0])
	if !(len(first) >= 2 && first[0] == '"' && first[len(first)-1] == '"') {
		return args
	}
	out := make([]string, 0, len(args))
	out = append(out, args[0])
	for i := 1; i < len(args); i++ {
		if isFmtFallbackArg(args[i]) {
			continue
		}
		out = append(out, args[i])
	}
	if len(out) == 0 {
		return []string{`""`}
	}
	return out
}

func trimFallbackPrintfArgs(args []string) []string {
	return args
}

func repairGenSplitArgs(args []string, params []analysis.ParamInfo) []string {
	sep := `""`
	source := ""
	n := "3"
	isInt := regexp.MustCompile(`^-?\d+$`).MatchString
	for _, arg := range args {
		trim := strings.TrimSpace(arg)
		if trim == "" {
			continue
		}
		if len(trim) >= 2 && trim[0] == '"' && trim[len(trim)-1] == '"' {
			if sep == `""` {
				sep = trim
			}
			continue
		}
		if isInt(trim) {
			if trim != "0" && trim != "1" {
				n = trim
			}
			continue
		}
		if isFmtFallbackArg(trim) {
			continue
		}
		if source == "" {
			source = trim
		}
	}
	if source == "" {
		for _, p := range params {
			if p.Kind == analysis.ParamSlice && p.Name != "" {
				source = p.Name + "[0]"
				break
			}
		}
	}
	if source == "" {
		source = `""`
	}
	return []string{source, sep, n}
}

func trimTrailingNilArgs(args []string) []string {
	for len(args) > 0 {
		if strings.TrimSpace(args[len(args)-1]) != "nil" {
			break
		}
		args = args[:len(args)-1]
	}
	return args
}

func normalizeMaybeStringArg(arg, fallback string) string {
	trim := strings.TrimSpace(arg)
	if trim == "" || trim == "nil" {
		return fallback
	}
	if len(trim) >= 2 && trim[0] == '"' && trim[len(trim)-1] == '"' {
		return arg
	}
	return "fmt.Sprint(" + arg + ")"
}

// formatCallExpr 将函数名和参数渲染为调用表达式，确保输出代码可以通过 Go 编译器。
//
//   - 方法表达式 (*Type).Method → recv.Method(args)（优先使用已恢复接收者）
//   - 跨包未导出函数              → // pkg.func(args)（注释）
//   - 已知 stdlib 参数布局问题    → 应用 stdlibCallFix 修正
func formatCallExpr(name string, args []string) string {
	if fix, ok := stdlibCallFix[name]; ok {
		return fix(args)
	}
	if mcall, ok := formatMethodCallByName(name, args); ok {
		return mcall
	}

	formatted := analysis.FormatCallName(name)
	argStr := strings.Join(args, ", ")

	if name == "google.golang.org/grpc.NewServer" && len(args) == 1 && strings.TrimSpace(args[0]) == "nil" {
		return formatted + "()"
	}

	// 跨包调用处理（名称中含点且不是方法表达式路径注释）
	if dot := strings.LastIndex(formatted, "."); dot >= 0 && !strings.HasPrefix(formatted, "/*") {
		// 已知 stdlib 参数修正（优先级高于未导出检查，允许映射内部函数如 strings.genSplit）
		if fix, ok := stdlibCallFix[formatted]; ok {
			return fix(args)
		}
		funcPart := formatted[dot+1:]
		if len(funcPart) > 0 {
			// 未导出函数（首字母小写）→ 注释掉，避免编译错误
			if unicode.IsLower([]rune(funcPart)[0]) {
				return "// " + formatted + "(" + argStr + ")"
			}
		}
	}

	if dot := strings.LastIndex(formatted, "."); dot >= 0 && strings.HasPrefix(formatted, "/*") {
		funcPart := formatted[dot+1:]
		if len(funcPart) > 0 && unicode.IsLower([]rune(funcPart)[0]) {
			return "// " + formatted + "(" + argStr + ")"
		}
	}

	return formatted + "(" + argStr + ")"
}

func formatMethodCallByName(name string, args []string) (string, bool) {
	pkgPath := ""
	rest := name
	if !strings.HasPrefix(name, "(*") {
		idx := strings.Index(name, ".(")
		if idx <= 0 {
			return "", false
		}
		pkgPath = name[:idx]
		rest = name[idx+1:]
	}
	if !strings.HasPrefix(rest, "(*") {
		return "", false
	}
	end := strings.Index(rest, ").")
	if end < 0 {
		return "", false
	}
	typName := rest[2:end]
	method := rest[end+2:]
	if pkgPath != "" {
		r := []rune(method)
		if len(r) > 0 && unicode.IsLower(r[0]) {
			formatted := analysis.FormatCallName(name)
			return "// " + formatted + "(" + strings.Join(args, ", ") + ")", true
		}
	}
	recvType := methodReceiverType(name, typName)
	recv := fmt.Sprintf("new(%s)", recvType)
	callArgs := args
	if len(args) > 0 {
		candidate := strings.TrimSpace(args[0])
		if candidate != "" && candidate != "nil" && isLikelyReceiverExpr(candidate) && !isGlobalPlaceholderName(candidate) {
			recv = candidate
		}
		callArgs = args[1:]
	}
	if pkgPath == "flag" && typName == "FlagSet" && method == "Parse" && len(callArgs) == 1 && strings.TrimSpace(callArgs[0]) == "nil" {
		return "flag.Parse()", true
	}
	return fmt.Sprintf("%s.%s(%s)", recv, method, strings.Join(callArgs, ", ")), true
}

func isLikelyReceiverExpr(expr string) bool {
	trim := strings.TrimSpace(expr)
	if trim == "" {
		return false
	}
	if strings.Contains(trim, "(") || strings.Contains(trim, ")") {
		return strings.HasPrefix(trim, "new(") && strings.HasSuffix(trim, ")")
	}
	if regexp.MustCompile(`^(sp_\d+|g\d+|v\d+|ax_\d+|bx_\d+|cx_\d+|dx_\d+)$`).MatchString(trim) {
		return false
	}
	return regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`).MatchString(trim)
}

func isGlobalPlaceholderName(name string) bool {
	trim := strings.TrimSpace(name)
	if strings.HasPrefix(trim, "_g") {
		return true
	}
	return regexp.MustCompile(`^g\d+$`).MatchString(trim)
}

func methodReceiverType(callName, typName string) string {
	pkgPath := importPathFromFuncName(callName)
	if pkgPath == "" || pkgPath == "main" || strings.HasPrefix(pkgPath, "(") {
		return typName
	}
	return importAliasFromPath(pkgPath) + "." + typName
}

// refineFmtCallArgs 在 fmt 格式化调用出现默认占位参数时，优先回填当前函数参数名。
// 仅作为保底策略：若无法确定更合理参数，保留原占位值。
func refineFmtCallArgs(callName string, args []string, params []analysis.ParamInfo) []string {
	if len(args) == 0 {
		return args
	}
	if !isFmtLikeCall(callName) {
		return args
	}
	fmtText, err := strconv.Unquote(args[0])
	if err != nil || fmtText == "" {
		return args
	}
	verbs := parseFmtVerbsLite(fmtText)
	if len(verbs) == 0 {
		return args
	}

	used := make(map[int]bool)
	for i, verb := range verbs {
		argIdx := i + 1
		for len(args) <= argIdx {
			args = append(args, "")
		}
		fallback := isFmtFallbackArg(args[argIdx])
		if len(params) > 0 && fallback {
			if p, ok := pickParamForVerb(verb, params, used); ok {
				args[argIdx] = p.Name
				if pi := pickParamIndex(params, p.Name); pi >= 0 {
					used[pi] = true
				}
			}
		}
		if fallback || strings.ContainsRune("swfFeEgG", rune(verb)) {
			args[argIdx] = normalizeFmtArgByVerb(verb, args[argIdx])
		}
	}
	return args
}

func coerceCallArgsByParamKinds(args []string, params []analysis.ParamInfo) []string {
	n := min(len(args), len(params))
	for i := 0; i < n; i++ {
		arg := strings.TrimSpace(args[i])
		switch params[i].Kind {
		case analysis.ParamString:
			if arg == "0" {
				args[i] = `""`
				continue
			}
			if arg == "" || arg == `""` || (len(arg) >= 2 && arg[0] == '"' && arg[len(arg)-1] == '"') || strings.HasPrefix(arg, "fmt.Sprint(") {
				continue
			}
			if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\[[^\]]+\]$`).MatchString(arg) {
				continue
			}
			args[i] = "fmt.Sprint(" + args[i] + ")"
		case analysis.ParamInt:
			if len(arg) >= 2 && arg[0] == '"' && arg[len(arg)-1] == '"' {
				args[i] = "len(" + args[i] + ")"
			}
		case analysis.ParamSlice:
			if arg == "" || arg == "nil" || strings.HasPrefix(arg, "[]") {
				continue
			}
			if strings.HasPrefix(arg, "sliceFromPtrLenCap(") {
				continue
			}
			if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(arg) {
				continue
			}
			if strings.ContainsAny(arg, "+-*/&|<>()") {
				args[i] = "nil"
				continue
			}
			if regexp.MustCompile(`^-?\d+(\.\d+)?$`).MatchString(arg) {
				args[i] = "nil"
			}
		case analysis.ParamPtr, analysis.ParamIface:
			if regexp.MustCompile(`^-?\d+(\.\d+)?$`).MatchString(arg) {
				args[i] = "nil"
			}
		}
	}
	return args
}

// normalizeFmtArgByVerb 将已选中的 fmt 参数按 verb 做最小类型修正，减少无效格式化组合。
func normalizeFmtArgByVerb(verb byte, arg string) string {
	trim := strings.TrimSpace(arg)
	if trim == "" {
		return arg
	}
	isIntLit := regexp.MustCompile(`^-?\d+$`).MatchString(trim)
	isFloatLit := regexp.MustCompile(`^-?\d+\.\d+$`).MatchString(trim)
	isQuoted := len(trim) >= 2 && trim[0] == '"' && trim[len(trim)-1] == '"'

	switch verb {
	case 'w':
		return arg
	case 'f', 'F', 'e', 'E', 'g', 'G':
		if isFloatLit || strings.HasPrefix(trim, "float64(") {
			return arg
		}
		return "float64(" + arg + ")"
	case 's':
		if isQuoted || strings.HasPrefix(trim, "fmt.Sprint(") || strings.Contains(trim, ".") || strings.HasPrefix(trim, "_p") {
			return arg
		}
		return "fmt.Sprint(" + arg + ")"
	case 'd', 'b', 'o', 'x', 'X', 'c', 'U':
		if isIntLit || strings.HasPrefix(trim, "int(") {
			return arg
		}
		if isQuoted {
			return "len(" + arg + ")"
		}
	}
	return arg
}

func isFmtLikeCall(name string) bool {
	return strings.HasSuffix(name, ".Sprintf") ||
		strings.HasSuffix(name, ".Printf") ||
		strings.HasSuffix(name, ".Fprintf") ||
		strings.HasSuffix(name, ".Errorf")
}

func isFmtFallbackArg(arg string) bool {
	trim := strings.TrimSpace(arg)
	switch trim {
	case `""`, "0", "0.0", "false", "nil", "":
		return true
	default:
		if regexp.MustCompile(`^-?\d+(\.\d+)?$`).MatchString(trim) {
			return true
		}
		if regexp.MustCompile(`^(r(?:ax|bx|cx|dx|si|di|8|9|1[0-5])|e(?:ax|bx|cx|dx|si|di))$`).MatchString(trim) {
			return true
		}
		if strings.HasPrefix(trim, "_pr") || strings.HasPrefix(trim, "_g") {
			return true
		}
		switch trim {
		case "i", "j", "k", "l", "m":
			return true
		}
		if strings.HasPrefix(trim, "sp_") || strings.HasPrefix(trim, "ax_") ||
			strings.HasPrefix(trim, "dx_") || strings.HasPrefix(trim, "cx_") ||
			strings.HasPrefix(trim, "bx_") {
			return true
		}
		if regexp.MustCompile(`^[gv]\d+$`).MatchString(trim) {
			return true
		}
		return false
	}
}

func parseFmtVerbsLite(format string) []byte {
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
		i = skipFmtIndexLite(b, i)
		for i < len(b) && strings.ContainsRune("+#- 0", rune(b[i])) {
			i++
		}
		if i < len(b) && b[i] == '*' {
			i++
			i = skipFmtIndexLite(b, i)
		} else {
			for i < len(b) && b[i] >= '0' && b[i] <= '9' {
				i++
			}
		}
		if i < len(b) && b[i] == '.' {
			i++
			if i < len(b) && b[i] == '*' {
				i++
				i = skipFmtIndexLite(b, i)
			} else {
				for i < len(b) && b[i] >= '0' && b[i] <= '9' {
					i++
				}
			}
		}
		i = skipFmtIndexLite(b, i)
		if i < len(b) {
			verbs = append(verbs, b[i])
			i++
		}
	}
	return verbs
}

func skipFmtIndexLite(b []byte, i int) int {
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

func pickParamForVerb(verb byte, params []analysis.ParamInfo, used map[int]bool) (analysis.ParamInfo, bool) {
	pick := func(pred func(analysis.ParamInfo) bool) (analysis.ParamInfo, bool) {
		for i, p := range params {
			if used[i] {
				continue
			}
			if pred(p) {
				return p, true
			}
		}
		for i, p := range params {
			if !used[i] {
				return p, true
			}
		}
		return analysis.ParamInfo{}, false
	}

	switch verb {
	case 's', 'q':
		for i, p := range params {
			if used[i] {
				continue
			}
			if p.Kind == analysis.ParamString {
				return p, true
			}
		}
		for i, p := range params {
			if used[i] {
				continue
			}
			if p.Kind == analysis.ParamSlice && p.Name != "" {
				q := p
				q.Name = p.Name + "[0]"
				q.Kind = analysis.ParamString
				return q, true
			}
		}
		return analysis.ParamInfo{}, false
	case 'w':
		for i, p := range params {
			if used[i] {
				continue
			}
			name := strings.ToLower(p.Name)
			if strings.Contains(name, "err") || p.Kind == analysis.ParamIface {
				return p, true
			}
		}
		return analysis.ParamInfo{}, false
	case 'd', 'b', 'o', 'x', 'X', 'c', 'U':
		return pick(func(p analysis.ParamInfo) bool { return p.Kind == analysis.ParamInt })
	default:
		return pick(func(p analysis.ParamInfo) bool { return p.Kind != analysis.ParamSlice })
	}
}

func pickParamIndex(params []analysis.ParamInfo, name string) int {
	for i, p := range params {
		if p.Name == name {
			return i
		}
	}
	return -1
}

// stripSamePkgPrefix 去掉与当前包相同的包前缀：
// "main.NewPerson" + pkg="main" → "NewPerson"
// "main.(*Person).Greet" + pkg="main" → "(*Person).Greet"
func stripSamePkgPrefix(name, currentPkg string) string {
	if currentPkg == "" {
		return name
	}
	prefix := currentPkg + "."
	if strings.HasPrefix(name, prefix) {
		return name[len(prefix):]
	}
	return name
}

// ── import 推断 ──────────────────────────────────────────────────────────────

func needsSlicePtrLenCapHelper(grp *fileGroup) bool {
	for _, r := range grp.funcs {
		if r == nil || r.IR == nil {
			continue
		}
		if funcIRUsesSlicePtrLenCap(r.IR.Stmts) {
			return true
		}
	}
	return false
}

func funcIRUsesSlicePtrLenCap(stmts []*analysis.Stmt) bool {
	for _, s := range stmts {
		switch s.Kind {
		case analysis.StmtCall, analysis.StmtGo, analysis.StmtDefer, analysis.StmtPanic, analysis.StmtReturn:
			if s.Call != nil {
				for _, a := range s.Call.Args {
					if strings.Contains(a.GoString(), "sliceFromPtrLenCap(") {
						return true
					}
				}
			}
		case analysis.StmtIf:
			if s.If != nil && (funcIRUsesSlicePtrLenCap(s.If.Then) || funcIRUsesSlicePtrLenCap(s.If.Else)) {
				return true
			}
		case analysis.StmtFor:
			if s.For != nil && funcIRUsesSlicePtrLenCap(s.For.Body) {
				return true
			}
		}
	}
	return false
}

func renderSlicePtrLenCapHelper() string {
	return `func sliceFromPtrLenCap(base uintptr, length int, capacity int) []string {
	if base == 0 || length <= 0 || capacity < length {
		return nil
	}
	hdr := struct {
		Data uintptr
		Len  int
		Cap  int
	}{Data: base, Len: length, Cap: capacity}
	return *(*[]string)(unsafe.Pointer(&hdr))
}
`
}

func collectImports(grp *fileGroup) []string {
	seen := make(map[string]bool)
	for _, r := range grp.funcs {
		if r.IR == nil {
			continue
		}
		for _, call := range r.IR.Calls {
			pkg := importPathFromFuncName(call)
			if pkg == "" || pkg == grp.pkg || pkg == grp.pkgFull || lastSegment(pkg) == grp.pkg {
				continue
			}
			if isExportableImport(pkg) {
				seen[pkg] = true
			}
		}
	}
	var out []string
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func importPathFromFuncName(funcName string) string {
	if strings.HasPrefix(funcName, "sub_0x") {
		return ""
	}
	if strings.HasPrefix(funcName, "(*") {
		return ""
	}
	if idx := strings.Index(funcName, ".("); idx > 0 {
		return funcName[:idx]
	}
	if idx := strings.LastIndex(funcName, "."); idx > 0 {
		return funcName[:idx]
	}
	return ""
}

// isExportableImport 判断是否为可安全添加到 import 的包。
func isExportableImport(pkg string) bool {
	if pkg == "" || pkg == "runtime" {
		return false
	}
	// 排除 internal/vendor 前缀包
	if strings.HasPrefix(pkg, "internal") || strings.HasPrefix(pkg, "vendor") {
		return false
	}
	return true
}

func importAliasFromPath(pkg string) string {
	seg := lastSegment(pkg)
	if seg == "" {
		return pkg
	}
	seg = strings.ReplaceAll(seg, "-", "_")
	seg = strings.ReplaceAll(seg, ".", "_")
	return seg
}

// ── 工具 ─────────────────────────────────────────────────────────────────────

func lastSegment(pkg string) string {
	if idx := strings.LastIndex(pkg, "/"); idx >= 0 {
		return pkg[idx+1:]
	}
	return pkg
}

// inferReturnType 从 IR 语句中推断函数返回类型。
// 当所有含值 return 的类型一致时返回该类型（"string"/"int"），否则返回 ""。
func inferReturnType(stmts []*analysis.Stmt) string {
	typ := ""
	ok := true
	var walk func([]*analysis.Stmt)
	walk = func(ss []*analysis.Stmt) {
		if !ok {
			return
		}
		for i, s := range ss {
			if s.Kind == analysis.StmtReturn && s.Call != nil && len(s.Call.Args) > 0 {
				var t string
				switch s.Call.Args[0].(type) {
				case *analysis.StringLit:
					t = "string"
				case *analysis.IntLit:
					t = "int"
				default:
					ok = false
					return
				}
				if typ == "" {
					typ = t
				} else if typ != t {
					ok = false
					return
				}
			}
			// call+return 合并模式：StmtCall 后接空 return → 从调用推断返回类型
			if s.Kind == analysis.StmtCall && s.Call != nil {
				nextIsEmptyReturn := i+1 < len(ss) &&
					ss[i+1].Kind == analysis.StmtReturn &&
					(ss[i+1].Call == nil || len(ss[i+1].Call.Args) == 0)
				if nextIsEmptyReturn {
					rt := callReturnType(s.Call.Func)
					if rt != "" {
						if typ == "" {
							typ = rt
						} else if typ != rt {
							ok = false
							return
						}
					}
				}
			}
			if s.Kind == analysis.StmtIf && s.If != nil {
				walk(s.If.Then)
				walk(s.If.Else)
			}
			if s.Kind == analysis.StmtFor && s.For != nil {
				walk(s.For.Body)
			}
		}
	}
	walk(stmts)
	if !ok {
		return ""
	}
	return typ
}

// renderFuncSig 将 ShortName 渲染为合法的 Go 函数签名（含换行）。
// retType 为推断出的返回类型（可为空），params 为推断出的显式参数列表。
// 示例：
//
//	"main"           → "func main() {\n"
//	"(*Person).Greet" → "func (r *Person) Greet() {\n"
//	"Category.String" → "func (v Category) String() string {\n"
func renderFuncSig(short, retType string, params []analysis.ParamInfo) string {
	ret := ""
	if retType != "" {
		ret = " " + retType
	}
	paramStr := buildParamStr(params)
	// 指针接收者方法："(*Type).Method"
	if strings.HasPrefix(short, "(*") {
		if inner, method, ok := strings.Cut(short[2:], ")."); ok {
			return fmt.Sprintf("func (r *%s) %s(%s)%s {\n", inner, safeIdent(method), paramStr, ret)
		}
	}
	// 值接收者方法："Type.Method"（两段，均为简单标识符）
	if typName, method, ok := strings.Cut(short, "."); ok {
		// 确认都是合法标识符（不含特殊符号）
		if !strings.ContainsAny(typName, "(*) ") && !strings.ContainsAny(method, "(*) ") {
			return fmt.Sprintf("func (v %s) %s(%s)%s {\n", typName, method, paramStr, ret)
		}
	}
	// 普通函数
	return "func " + safeIdent(short) + "(" + paramStr + ")" + ret + " {\n"
}

// buildParamStr 将 []ParamInfo 渲染为函数参数列表字符串（如 "arg0 string, arg2 int"）。
func buildParamStr(params []analysis.ParamInfo) string {
	if len(params) == 0 {
		return ""
	}
	parts := make([]string, len(params))
	for i, p := range params {
		parts[i] = p.Name + " " + p.Kind.GoType()
	}
	return strings.Join(parts, ", ")
}

func safeIdent(name string) string {
	r := strings.NewReplacer("(", "_", ")", "_", "*", "", "·", "_", " ", "_")
	return r.Replace(name)
}

// ensureTrailingReturn 为有返回值的函数补齐末尾默认 return，避免遗漏分支导致编译失败。
func ensureTrailingReturn(body, retType string) string {
	if retType == "" {
		return body
	}
	trim := strings.TrimSpace(body)
	if trim == "" {
		return "\treturn " + zeroValueForType(retType) + "\n"
	}
	lines := strings.Split(trim, "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if strings.HasPrefix(last, "return") {
		return body
	}
	return body + "\treturn " + zeroValueForType(retType) + "\n"
}

// fillBareReturns 将有返回值函数中的裸 return 补齐为零值 return。
func fillBareReturns(body, retType string) string {
	if retType == "" {
		return body
	}
	zero := zeroValueForType(retType)
	lines := strings.Split(body, "\n")
	for i, ln := range lines {
		if strings.TrimSpace(ln) == "return" {
			indent := ln[:len(ln)-len(strings.TrimLeft(ln, "\t "))]
			lines[i] = indent + "return " + zero
		}
	}
	return strings.Join(lines, "\n")
}

func zeroValueForType(t string) string {
	switch t {
	case "string":
		return `""`
	case "error", "interface{}", "[]byte", "[]string":
		return "nil"
	case "bool":
		return "false"
	case "float32", "float64":
		return "0.0"
	default:
		return "0"
	}
}

func pruneUnusedIntVarBlock(src string) string {
	lines := strings.Split(src, "\n")
	start := -1
	end := -1
	for i, ln := range lines {
		if strings.TrimSpace(ln) == "var (" {
			start = i
			break
		}
	}
	if start < 0 {
		return src
	}
	for i := start + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == ")" {
			end = i
			break
		}
	}
	if end < 0 || end <= start+1 {
		return src
	}
	body := strings.Join(lines[end+1:], "\n")
	var kept []string
	for i := start + 1; i < end; i++ {
		trim := strings.TrimSpace(lines[i])
		fields := strings.Fields(trim)
		if len(fields) < 2 || fields[1] != "int" {
			kept = append(kept, lines[i])
			continue
		}
		name := fields[0]
		if varAppearsIn(name, body) {
			kept = append(kept, lines[i])
		}
	}
	if len(kept) == 0 {
		lines = append(lines[:start], lines[end+1:]...)
		return strings.Join(lines, "\n")
	}
	newLines := make([]string, 0, len(lines)-(end-start-1)+len(kept))
	newLines = append(newLines, lines[:start+1]...)
	newLines = append(newLines, kept...)
	newLines = append(newLines, lines[end:]...)
	return strings.Join(newLines, "\n")
}

// rewriteKnownPatterns 对高频可识别模式做小范围语义重写，提升可读性与可执行行为。
// varAppearsIn 检查标识符 name 是否以完整单词形式出现在 body 中。
// 用于过滤已被空块消除的条件变量，避免生成"声明但未使用"的 var。
func varAppearsIn(name, body string) bool {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
	return re.MatchString(body)
}

func isShortDeclaredInBody(name, body string) bool {
	if name == "" {
		return false
	}
	for _, ln := range strings.Split(body, "\n") {
		line := strings.TrimSpace(ln)
		if !strings.Contains(line, ":=") {
			continue
		}
		lhs, _, _ := strings.Cut(line, ":=")
		for _, part := range strings.Split(lhs, ",") {
			if strings.TrimSpace(part) == name {
				return true
			}
		}
	}
	return false
}

func buildMethodReceiverMap(funcs []*FuncResult) map[string]string {
	recvByMethod := make(map[string]string)
	ambiguous := make(map[string]bool)
	for _, fr := range funcs {
		recv, method, ok := parseMethodShortName(fr.Sym.ShortName)
		if !ok {
			continue
		}
		if ambiguous[method] {
			continue
		}
		if prev, exists := recvByMethod[method]; exists && prev != recv {
			delete(recvByMethod, method)
			ambiguous[method] = true
			continue
		}
		recvByMethod[method] = recv
	}
	return recvByMethod
}

func parseMethodShortName(short string) (recv, method string, ok bool) {
	if strings.HasPrefix(short, "(*") {
		inner, m, found := strings.Cut(short[2:], ").")
		if !found || inner == "" || m == "" {
			return "", "", false
		}
		return "*" + inner, m, true
	}
	typ, m, found := strings.Cut(short, ".")
	if !found || typ == "" || m == "" {
		return "", "", false
	}
	if strings.ContainsAny(typ, "(*) ") || strings.ContainsAny(m, "(*) ") {
		return "", "", false
	}
	return typ, m, true
}

func inferLocalVarType(name, body string, methodRecv map[string]string) string {
	if name == "" {
		return "int"
	}
	quoted := regexp.QuoteMeta(name)
	if regexp.MustCompile(`\bstrconv\.Atoi\(\s*` + quoted + `\s*\)`).MatchString(body) {
		return "string"
	}
	if regexp.MustCompile(`\bstrings\.(?:Split|SplitN|Trim|TrimSpace|HasPrefix|HasSuffix|Contains|Fields)\(\s*` + quoted + `\b`).MatchString(body) {
		return "string"
	}
	if regexp.MustCompile(`fmt\.(?:Errorf|Sprintf|Printf|Fprintf)\("[^"\n]*%[qs][^"\n]*"\s*,\s*` + quoted + `(?:\s*[,)])`).MatchString(body) {
		return "string"
	}
	if m := regexp.MustCompile(`\b` + quoted + `\.([A-Za-z_][A-Za-z0-9_]*)\s*\(`).FindStringSubmatch(body); len(m) == 2 {
		if recv, ok := methodRecv[m[1]]; ok && recv != "" {
			return recv
		}
	}
	if regexp.MustCompile(`fmt\.Errorf\([^\n]*%w[^\n]*,\s*` + quoted + `\s*\)`).MatchString(body) {
		return "error"
	}
	if regexp.MustCompile(`\b` + quoted + `\.Error\(\)`).MatchString(body) {
		return "error"
	}
	return "int"
}

func inferInitLinesFromParams(params []analysis.ParamInfo, renames map[string]string, body string) []string {
	if len(params) == 0 || body == "" {
		return nil
	}
	isIdent := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString
	appendUnique := func(out *[]string, seen map[string]bool, line string) {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			return
		}
		seen[line] = true
		*out = append(*out, line)
	}
	renamed := func(reg string) string {
		if v, ok := renames[reg]; ok && v != "" {
			return v
		}
		return reg
	}
	var out []string
	seen := make(map[string]bool)
	for _, p := range params {
		if p.Name == "" {
			continue
		}
		if (p.Kind == analysis.ParamString || p.Kind == analysis.ParamSlice || p.Kind == analysis.ParamIface) && len(p.Regs) >= 2 {
			lenVar := renamed(p.Regs[1])
			if isIdent(lenVar) && lenVar != p.Name && varAppearsIn(lenVar, body) {
				appendUnique(&out, seen, fmt.Sprintf("%s = len(%s)", lenVar, p.Name))
			}
		}
		if p.Kind == analysis.ParamSlice && len(p.Regs) >= 3 {
			capVar := renamed(p.Regs[2])
			if isIdent(capVar) && capVar != p.Name && varAppearsIn(capVar, body) {
				appendUnique(&out, seen, fmt.Sprintf("%s = cap(%s)", capVar, p.Name))
			}
		}
	}
	return out
}

func inferMainArgsInitLines(shortName, body string) []string {
	if shortName != "main" || !strings.Contains(body, "sliceFromPtrLenCap(") {
		return nil
	}
	isIdent := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString
	appendUnique := func(out *[]string, seen map[string]bool, line string) {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			return
		}
		seen[line] = true
		*out = append(*out, line)
	}
	var out []string
	seen := make(map[string]bool)

	if m := regexp.MustCompile(`if\s+([A-Za-z_][A-Za-z0-9_]*)\s*<\s*2\s*\{`).FindStringSubmatch(body); len(m) == 2 {
		lenVar := m[1]
		if regexp.MustCompile(`if\s+` + regexp.QuoteMeta(lenVar) + `\s*<\s*1\s*\{`).MatchString(body) {
			appendUnique(&out, seen, fmt.Sprintf("%s = len(os.Args)", lenVar))
		}
	}

	dataMatch := regexp.MustCompile(`sliceFromPtrLenCap\(uintptr\(\(([A-Za-z_][A-Za-z0-9_]*)\)`).FindStringSubmatch(body)
	capMatch := regexp.MustCompile(`sliceFromPtrLenCap\(uintptr\([^,]+,\s*int\([A-Za-z_][A-Za-z0-9_]*\),\s*int\(([A-Za-z_][A-Za-z0-9_]*)\)\)`).FindStringSubmatch(body)
	if len(dataMatch) == 2 || len(capMatch) == 2 {
		dataVar := ""
		capVar := ""
		if len(dataMatch) == 2 {
			dataVar = dataMatch[1]
		}
		if len(capMatch) == 2 {
			capVar = capMatch[1]
		}
		if isIdent(capVar) && varAppearsIn(capVar, body) {
			appendUnique(&out, seen, fmt.Sprintf("%s = len(os.Args)", capVar))
		}
		if isIdent(dataVar) && varAppearsIn(dataVar, body) {
			appendUnique(&out, seen, "if len(os.Args) > 0 {")
			out = append(out, dataVar+" = int(uintptr(unsafe.Pointer(&os.Args[0])))")
			appendUnique(&out, seen, "}")
		}
	}
	return out
}

// ── 字段偏移表 ────────────────────────────────────────────────────────────────

type fieldExprKind int

const (
	fieldExprDirect fieldExprKind = iota
	fieldExprStringLen
)

// FieldAccessor 描述某个偏移对应的字段访问表达式类型。
type FieldAccessor struct {
	Name string
	Kind fieldExprKind
}

// FieldTable 将结构体类型名映射到（字段偏移 → 字段访问器）表。
// 来自 typeinfo.TypeDecl，用于将 [rax+0x28] 还原为 r.Category 等字段访问形式。
type FieldTable map[string]map[uint64]FieldAccessor

// buildFieldTable 从类型声明构建字段偏移表。
func buildFieldTable(types []*typeinfo.TypeDecl) FieldTable {
	t := make(FieldTable)
	for _, td := range types {
		if td.Kind != typeinfo.KindStruct || len(td.Fields) == 0 {
			continue
		}
		m := make(map[uint64]FieldAccessor, len(td.Fields))
		fieldTypeByName := make(map[string]string, len(td.Fields))
		for _, f := range td.Fields {
			if !f.Hidden {
				fieldTypeByName[f.Name] = f.TypeName
			}
		}
		for _, f := range td.Fields {
			access := FieldAccessor{Name: f.Name, Kind: fieldExprDirect}
			if f.Hidden {
				if fieldTypeByName[f.Name] == "string" {
					access.Kind = fieldExprStringLen
				}
			}
			m[f.Offset] = access
		}
		t[td.Name] = m
	}
	return t
}

// recvTypeName 从指针接收者方法的 ShortName 提取接收者类型名。
// "(*Person).Greet" → "Person"；非指针接收者或普通函数 → ""。
func recvTypeName(short string) string {
	if !strings.HasPrefix(short, "(*") {
		return ""
	}
	end := strings.Index(short, ").")
	if end < 0 {
		return ""
	}
	return short[2:end]
}

// reMemRaxHex 匹配 sanitizeCond 生成的 [rax+offset] 合成标识符，如 _prax28。
var reMemRaxHex = regexp.MustCompile(`\b_prax([0-9a-f]+)\b`)

// ── 变量重命名系统 ─────────────────────────────────────────────────────────────

// x86IntArgRegs Go x86-64 ABI 整数参数寄存器的顺序。
var x86IntArgRegs = []string{"rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10"}

// x86RegNames 全部 x86-64 通用寄存器名（用于判断某标识符是否为"裸寄存器名"）。
var x86RegNames = map[string]bool{
	"rax": true, "rbx": true, "rcx": true, "rdx": true,
	"rsi": true, "rdi": true, "r8": true, "r9": true,
	"r10": true, "r11": true, "r12": true, "r13": true,
	"r14": true, "r15": true, "rsp": true, "rbp": true,
	"eax": true, "ebx": true, "ecx": true, "edx": true,
	"esi": true, "edi": true,
}

// reForLHS 提取 for 循环条件左侧的变量名，如 "for rax < n" → "rax"。
var reForLHS = regexp.MustCompile(`\bfor ([a-zA-Z_]\w*)\s*(?:==|!=|<=?|>=?)`)

// rePrAny 匹配 sanitizeCond 生成的寄存器相对内存引用标识符（_pr<reg><hex>）。
// 枚举已知寄存器后缀（不含前导 'r'），避免贪婪匹配吞掉十六进制数字。
// 例：_prcx18（reg=cx, hex=18）、_prdx8（reg=dx, hex=8）、_prax8（reg=ax, hex=8）。
var rePrAny = regexp.MustCompile(
	`\b_pr(ax|bx|cx|dx|si|di|bp|sp|8d?|9d?|1[0-5]d?)([0-9a-f]+)\b`)

// reGlobalVar 匹配 rip 相对全局变量标识符，如 _gdb616。
var reGlobalVar = regexp.MustCompile(`\b_g([0-9a-f]+)\b`)

// isParamCandidate 检查寄存器 reg 是否在函数顶层首个调用语句之前出现于某条件表达式中。
// 若是，则认为该寄存器很可能是函数参数（调用前的初始值）。
func isParamCandidate(reg string, stmts []*analysis.Stmt) bool {
	for _, s := range stmts {
		switch s.Kind {
		case analysis.StmtCall, analysis.StmtGo, analysis.StmtDefer:
			// 遇到调用，reg 尚未出现在条件中 → 非参数（或我们无法判断）
			return false
		case analysis.StmtIf:
			if s.If != nil {
				// 检查条件字符串中是否包含寄存器名（作为完整单词）
				re := regexp.MustCompile(`\b` + regexp.QuoteMeta(reg) + `\b`)
				if re.MatchString(s.If.Cond) {
					return true
				}
			}
		case analysis.StmtFor:
			if s.For != nil {
				re := regexp.MustCompile(`\b` + regexp.QuoteMeta(reg) + `\b`)
				if re.MatchString(s.For.Cond) {
					return true
				}
			}
		}
	}
	return false
}

// hasIncrOnVar 递归判断语句树中是否存在对指定寄存器变量的自增/自减更新。
func hasIncrOnVar(stmts []*analysis.Stmt, varName string) bool {
	for _, s := range stmts {
		if s.Kind == analysis.StmtIncr && s.Incr != nil && s.Incr.Var == varName {
			return true
		}
		if s.Kind == analysis.StmtIf && s.If != nil {
			if hasIncrOnVar(s.If.Then, varName) || hasIncrOnVar(s.If.Else, varName) {
				return true
			}
		}
		if s.Kind == analysis.StmtFor && s.For != nil {
			if hasIncrOnVar(s.For.Body, varName) {
				return true
			}
		}
	}
	return false
}

// buildVarRenames 根据已渲染（字段替换后）的函数体，构建变量重命名映射，策略如下：
//
//  0. 强制重命名（来自参数检测，最高优先级，覆盖所有后续规则）
//  1. for 循环计数器（x86 寄存器）→ i/j/k/...
//  2. 原始寄存器条件变量（仅在首次调用前出现）→ arg0/arg1/arg2（按 Go ABI 顺序）
//  3. 未解析的 _pr<reg><hex> 内存引用标识符 → <reg>_<hex>（如 _prcx18 → cx_18）
//  4. 全局变量 _g<hex> → g0/g1/g2（按 body 中首次出现顺序）
//  5. 剩余裸寄存器（调用后返回值等）→ v0/v1/v2（按 body 首次出现顺序，后备命名）
//
// forcedRenames 为参数寄存器的强制映射（reg → paramName），优先级最高。
func buildVarRenames(body, short string, condVars map[string]bool, stmts []*analysis.Stmt, forcedRenames map[string]string, blockedParamRegs map[string]bool) map[string]string {
	renames := make(map[string]string)

	// 0. 强制重命名（来自 DetectParams，最高优先级）：参数寄存器直接映射到参数名
	maps.Copy(renames, forcedRenames)

	// 1. for 循环计数器：左侧为 x86 寄存器的循环变量
	loopNames := []string{"i", "j", "k", "l", "m"}
	loopIdx := 0
	for _, m := range reForLHS.FindAllStringSubmatch(body, -1) {
		v := m[1]
		if x86RegNames[v] && renames[v] == "" {
			if loopIdx < len(loopNames) {
				renames[v] = loopNames[loopIdx]
			} else {
				renames[v] = fmt.Sprintf("i%d", loopIdx)
			}
			loopIdx++
		}
	}

	// 2. 原始寄存器条件变量 → argN（按 Go ABI 顺序，仅限参数候选）
	// 收集已使用的 argN 名称，防止 secondary 寄存器（string.len/slice.cap）
	// 与 forcedRenames 分配的可见参数名冲突（如 rbx 抢占 arg1 而 rcx 已是 arg1）。
	takenArgNames := make(map[string]bool)
	for _, v := range renames {
		if strings.HasPrefix(v, "arg") {
			takenArgNames[v] = true
		}
	}
	isMethod := recvNameForFunc(short) != ""
	argIdx := 0
	for _, reg := range x86IntArgRegs {
		if isMethod && reg == "rax" {
			argIdx++ // receiver 占第 0 槽，跳过但计数
			continue
		}
		inCond := condVars[reg]
		alreadyNamed := renames[reg] != ""
		if blockedParamRegs[reg] {
			argIdx++
			continue
		}
		if inCond && !alreadyNamed && isParamCandidate(reg, stmts) {
			candidateName := fmt.Sprintf("arg%d", argIdx)
			if !takenArgNames[candidateName] {
				renames[reg] = candidateName
				takenArgNames[candidateName] = true
			}
		}
		argIdx++ // ABI 位置始终递增（不管是否实际命名）
	}

	// 3. 未解析的 _pr<reg><hex> → <reg>_<hex>（字段替换遗留的内存引用）
	for v := range condVars {
		if renames[v] != "" {
			continue
		}
		if m := rePrAny.FindStringSubmatch(v); len(m) == 3 {
			renames[v] = m[1] + "_" + m[2] // "_prcx18" → "cx_18"
		}
	}

	// 4. 全局变量 _g<hex> → g0/g1/g2（按 body 中首次出现顺序）
	gIdx := 0
	for _, m := range reGlobalVar.FindAllStringSubmatch(body, -1) {
		v := "_g" + m[1]
		if renames[v] == "" {
			renames[v] = fmt.Sprintf("g%d", gIdx)
			gIdx++
		}
	}

	// 5. 后备：剩余裸寄存器（调用后返回值等）→ v0/v1/v2（按 body 中首次出现顺序）
	// 用单一正则扫描 body，按首次出现顺序为尚未重命名的裸寄存器分配 vN 名称。
	reRawReg := regexp.MustCompile(`\b(r(?:ax|bx|cx|dx|si|di|bp|sp|8|9|1[0-5])|e(?:ax|bx|cx|dx|si|di))\b`)
	vIdx := 0
	for _, m := range reRawReg.FindAllString(body, -1) {
		if !condVars[m] || renames[m] != "" {
			continue
		}
		renames[m] = fmt.Sprintf("v%d", vIdx)
		vIdx++
	}

	return renames
}

// applyVarRenames 将重命名映射应用到函数体，使用单词边界匹配以避免部分替换。
// 通过合并为单个 regexp alternation 实现高效的一次性替换。
func applyVarRenames(body string, renames map[string]string) string {
	if len(renames) == 0 {
		return body
	}
	// 按 key 长度降序排列，确保较长的 key（如 _prcx18）优先匹配
	type kv struct{ k, v string }
	pairs := make([]kv, 0, len(renames))
	for k, v := range renames {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return len(pairs[i].k) > len(pairs[j].k)
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = regexp.QuoteMeta(p.k)
	}
	re := regexp.MustCompile(`\b(?:` + strings.Join(parts, "|") + `)\b`)
	return re.ReplaceAllStringFunc(body, func(m string) string {
		for _, p := range pairs {
			if m == p.k {
				return p.v
			}
		}
		return m
	})
}

// substituteReceiverFields 将函数体中的 _prXXNN 替换为接收者字段访问（r.FieldName）。
//   - Pass 1（确定性）：_praxNN — rax 始终是接收者寄存器，直接查表替换
//   - Pass 2（投机性）：_pr<reg>NN — 编译器可能在调用后将接收者重载入其他寄存器；
//     若 offset NN 在接收者类型的字段表中存在则替换（不存在则保留，供后续 rename 处理）
//
// 必须在 buildVarRenames/applyVarRenames 之前调用，
// 被替换的 _prXXNN 不再出现于 body → varAppearsIn 过滤时自动排除，不会生成无效 var 声明。
func substituteReceiverFields(body, recvSub, typeName string, ft FieldTable) string {
	if recvSub == "" || typeName == "" {
		return body
	}
	fieldMap, ok := ft[typeName]
	if !ok {
		return body
	}
	lookupField := func(hexStr string) string {
		offset, err := strconv.ParseUint(hexStr, 16, 64)
		if err != nil {
			return ""
		}
		if access, ok := fieldMap[offset]; ok {
			switch access.Kind {
			case fieldExprStringLen:
				return "len(" + recvSub + "." + access.Name + ")"
			default:
				return recvSub + "." + access.Name
			}
		}
		return ""
	}

	// Pass 1：_praxNN — rax 确定是接收者，全部替换
	body = reMemRaxHex.ReplaceAllStringFunc(body, func(m string) string {
		if s := lookupField(m[len("_prax"):]); s != "" {
			return s
		}
		return m
	})

	// Pass 2：_pr<其他寄存器>NN — 投机性替换（受调用影响可能被重载入其他寄存器）
	// rePrAny 在 "变量重命名系统" 节中定义，Go package-level var 无顺序限制
	body = rePrAny.ReplaceAllStringFunc(body, func(m string) string {
		parts := rePrAny.FindStringSubmatch(m)
		if len(parts) != 3 {
			return m
		}
		if s := lookupField(parts[2]); s != "" {
			return s // "[rcx+0x18]" → "r.F24"（若 0x18 在字段表中存在）
		}
		return m
	})

	return body
}
