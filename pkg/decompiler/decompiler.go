// Package decompiler 协调完整的反编译流程：
// ELF加载 → 符号恢复 → 类型恢复 → 反汇编 → CFG分析 → 代码生成。
package decompiler

import (
	"fmt"
	"log"
	"strings"

	"github.com/Yeah114/GoSpy/pkg/analysis"
	"github.com/Yeah114/GoSpy/pkg/buildinfo"
	"github.com/Yeah114/GoSpy/pkg/codegen"
	"github.com/Yeah114/GoSpy/pkg/loader"
	"github.com/Yeah114/GoSpy/pkg/symbols"
	"github.com/Yeah114/GoSpy/pkg/typeinfo"
)

// Config 反编译配置。
type Config struct {
	OutputDir   string // 输出目录
	Verbose     bool   // 详细日志
	IncludeDeps bool   // 是否包含标准库/依赖库（-deps）
	OnlyPackage string // 仅处理特定包（调试用）
	WriteGoMod  bool   // 是否写 go.mod
}

// Stats 统计结果。
type Stats struct {
	TotalFuncs  int
	OutputFuncs int
	Files       int
	Types       int
}

// Decompiler 是主反编译器。
type Decompiler struct {
	bin  *loader.Binary
	info *buildinfo.Info
	cfg  *Config
}

// New 创建反编译器。
func New(path string, cfg *Config) (*Decompiler, error) {
	bin, err := loader.Load(path)
	if err != nil {
		return nil, fmt.Errorf("load binary: %w", err)
	}

	// buildinfo 是可选的，失败不致命
	info, _ := buildinfo.Parse(path)

	return &Decompiler{bin: bin, info: info, cfg: cfg}, nil
}

// Decompile 执行完整反编译流程。
func (d *Decompiler) Decompile() (*Stats, error) {
	// ── 1. 符号表 ──────────────────────────────────────────────────────────
	d.log("解析符号表…")
	table, err := symbols.Build(d.bin)
	if err != nil {
		return nil, fmt.Errorf("build symbols: %w", err)
	}
	d.log("恢复 %d 个函数符号", len(table.Funcs))

	// ── 2. 类型恢复 ───────────────────────────────────────────────────────
	d.log("恢复类型信息…")
	typeParser := typeinfo.New(d.bin)
	allTypes, err := typeParser.ParseAll()
	if err != nil {
		d.log("类型恢复部分失败: %v", err)
	}
	d.log("恢复 %d 个类型", len(allTypes))

	// ── 3. 筛选目标函数 ───────────────────────────────────────────────────
	targets := d.selectFuncs(table)
	d.log("选中 %d 个函数进行反编译", len(targets))

	// ── 4. 逐函数分析 ─────────────────────────────────────────────────────
	analyzer := analysis.New(d.bin, table)
	var results []*codegen.FuncResult

	for _, fn := range targets {
		ir, err := analyzer.AnalyzeFunc(fn)
		if err != nil {
			d.log("警告: 分析 %s 失败: %v", fn.Name, err)
			ir = &analysis.FuncIR{Name: fn.Name}
		}
		results = append(results, &codegen.FuncResult{Sym: fn, IR: ir})
	}

	// ── 5. 从方法名推断类型 stub（用于未在 typelink 中出现的类型）───────────
	allTypes = d.inferMissingTypes(allTypes, table)
	d.log("含 stub 后共 %d 个类型", len(allTypes))

	// ── 5.5. 通过内存访问模式推断 stub 类型的字段 ─────────────────────────
	analysis.AnalyzeReceiverFields(d.bin, table, allTypes)

	// ── 6. 筛选输出类型 ───────────────────────────────────────────────────
	var outputTypes []*typeinfo.TypeDecl
	for _, td := range allTypes {
		if d.shouldOutputType(td) {
			outputTypes = append(outputTypes, td)
		}
	}

	// ── 6. 生成源码 ───────────────────────────────────────────────────────
	gen := codegen.New(d.cfg.OutputDir)

	if d.cfg.WriteGoMod && d.info != nil {
		if err := gen.WriteGoMod(d.info.GoModContent()); err != nil {
			d.log("警告: 写 go.mod 失败: %v", err)
		}
	}

	fileCount, err := gen.Generate(results, outputTypes)
	if err != nil {
		return nil, fmt.Errorf("codegen: %w", err)
	}

	return &Stats{
		TotalFuncs:  len(table.Funcs),
		OutputFuncs: len(results),
		Files:       fileCount,
		Types:       len(outputTypes),
	}, nil
}

// ModuleInfo 返回已解析的构建信息（可能为 nil）。
func (d *Decompiler) ModuleInfo() *buildinfo.Info { return d.info }

// ── 类型推断 ─────────────────────────────────────────────────────────────────

// inferMissingTypes 从 pclntab 方法名推断未被 typelink 覆盖的类型（生成 stub 声明）。
// 例如: "main.(*Team).Stats" → 推断存在 type Team struct{} （如尚未恢复）
func (d *Decompiler) inferMissingTypes(existing []*typeinfo.TypeDecl, table *symbols.Table) []*typeinfo.TypeDecl {
	// 建立已知类型集合
	known := make(map[string]bool)
	for _, td := range existing {
		known[td.Pkg+"."+td.Name] = true
	}

	result := existing
	seen := make(map[string]bool)

	for _, fn := range table.Funcs {
		pkg, typName := extractReceiverType(fn.Name)
		if pkg == "" || typName == "" {
			continue
		}
		key := pkg + "." + typName
		if known[key] || seen[key] {
			continue
		}
		// 仅为应输出的包创建 stub
		if !d.shouldOutputPkg(pkg) {
			continue
		}
		seen[key] = true
		known[key] = true
		result = append(result, &typeinfo.TypeDecl{
			Name:    typName,
			Pkg:     pkg,
			Kind:    typeinfo.KindStruct,
			Comment: "fields not recovered (type not in typelink)",
		})
	}
	return result
}

// extractReceiverType 从函数名提取接收者类型（不含 * 指针符号）。
// "main.(*Team).Stats" → ("main", "Team")
// "main.(Team).AverageAge" → ("main", "Team")
// "main.main" → ("", "")
func extractReceiverType(name string) (pkg, typName string) {
	// 查找方法接收者：形如 "pkg.(*Type).Method" 或 "pkg.(Type).Method"
	lp := strings.Index(name, ".(")
	if lp < 0 {
		return "", ""
	}
	pkg = name[:lp]
	if idx := strings.LastIndex(pkg, "/"); idx >= 0 {
		pkg = pkg[idx+1:]
	}
	rest := name[lp+2:]
	rp := strings.Index(rest, ")")
	if rp < 0 {
		return "", ""
	}
	typName = strings.TrimPrefix(rest[:rp], "*")
	return pkg, typName
}

func (d *Decompiler) shouldOutputPkg(pkg string) bool {
	if d.cfg.OnlyPackage != "" {
		return pkg == d.cfg.OnlyPackage
	}
	if d.cfg.IncludeDeps {
		return !isRuntimeInternal(pkg)
	}
	return d.isUserPackage(pkg)
}

// ── 筛选逻辑 ─────────────────────────────────────────────────────────────────

func (d *Decompiler) selectFuncs(table *symbols.Table) []*symbols.Func {
	var out []*symbols.Func
	for _, fn := range table.Funcs {
		if !d.shouldOutput(fn) {
			continue
		}
		// 跳过编译器生成的特殊函数
		if isCompilerGenerated(fn) {
			continue
		}
		out = append(out, fn)
	}
	return out
}

func (d *Decompiler) shouldOutput(fn *symbols.Func) bool {
	if d.cfg.OnlyPackage != "" {
		return fn.Package == d.cfg.OnlyPackage
	}
	if d.cfg.IncludeDeps {
		// 包含所有包，但跳过纯 runtime 内部
		return !isRuntimeInternal(fn.Package)
	}
	// 默认：仅输出用户包（main 或主模块路径）
	return d.isUserPackage(fn.Package)
}

func (d *Decompiler) shouldOutputType(td *typeinfo.TypeDecl) bool {
	if d.cfg.IncludeDeps {
		return true
	}
	return d.isUserPackage(td.Pkg)
}

func (d *Decompiler) isUserPackage(pkg string) bool {
	if pkg == "" || isRuntimeInternal(pkg) {
		return false
	}
	if pkg == "main" {
		return true
	}
	if d.info != nil && d.info.IsUserPkg(pkg) {
		return true
	}
	if d.info != nil && d.info.ModPath != "" {
		if idx := strings.LastIndex(d.info.ModPath, "/"); idx >= 0 {
			base := d.info.ModPath[idx+1:]
			if pkg == base || strings.HasPrefix(pkg, base+"/") {
				return true
			}
		}
	}
	return false
}

// ── 工具 ─────────────────────────────────────────────────────────────────────

func isRuntimeInternal(pkg string) bool {
	return pkg == "runtime" ||
		strings.HasPrefix(pkg, "runtime/") ||
		strings.HasPrefix(pkg, "internal/") ||
		strings.HasPrefix(pkg, "vendor/")
}

func isCompilerGenerated(fn *symbols.Func) bool {
	name := fn.ShortName
	// 跳过含特殊字符的生成函数
	for _, ch := range []string{"·", "«", "»", "go:linkname", "%"} {
		if strings.Contains(name, ch) {
			return true
		}
	}
	// 跳过 type..eq, type..hash 等编译器生成函数
	if strings.HasPrefix(fn.Name, "type:.") || strings.HasPrefix(fn.Name, "go:") {
		return true
	}
	return false
}

func (d *Decompiler) log(format string, args ...any) {
	if d.cfg.Verbose {
		log.Printf("[gospy] "+format, args...)
	}
}
