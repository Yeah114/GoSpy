// Package symbols 使用 debug/gosym 从 Go 二进制的 pclntab 恢复函数符号信息。
package symbols

import (
	"debug/gosym"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/Yeah114/GoSpy/pkg/loader"
)

// Func 表示从二进制中恢复的 Go 函数。
type Func struct {
	Name      string  // 完整名称，如 "main.main"
	Package   string  // 包路径，如 "main"
	ShortName string  // 函数名，如 "main"
	Entry     uint64  // 函数入口 PC
	End       uint64  // 函数结束 PC（不含）
	File      string  // 源文件路径
	Line      int     // 函数开始行号
	ArgsSize  int32   // 输入参数帧大小（字节），来自 pclntab _func.args；-1 表示未知
	PtrArgs   []bool  // 各参数槽是否为 GC 指针（来自 ArgsPointerMaps）；nil 表示未知
}

// IsRuntime 判断是否为 runtime 内部函数。
func (f *Func) IsRuntime() bool {
	return strings.HasPrefix(f.Package, "runtime") ||
		strings.HasPrefix(f.Package, "internal/")
}

// IsMain 判断是否属于 main 包。
func (f *Func) IsMain() bool { return f.Package == "main" }

// Table 保存所有恢复的函数符号。
type Table struct {
	Funcs   []*Func
	byPC    map[uint64]*Func
	goTable *gosym.Table
}

// Build 从 ELF 二进制构建符号表。
func Build(bin *loader.Binary) (*Table, error) {
	pclntab := bin.Sections[".gopclntab"]
	if pclntab == nil {
		return nil, fmt.Errorf("no .gopclntab section")
	}

	var symBytes []byte
	if sym := bin.Sections[".gosymtab"]; sym != nil {
		symBytes = sym.Data
	}

	lineTable := gosym.NewLineTable(pclntab.Data, bin.TextStart)
	goTable, err := gosym.NewTable(symBytes, lineTable)
	if err != nil {
		return nil, fmt.Errorf("parse symbol table: %w", err)
	}

	t := &Table{
		byPC:    make(map[uint64]*Func),
		goTable: goTable,
	}

	// 从 pclntab 原始数据读取每个函数的参数元数据
	// 尝试从 .noptrdata 定位 moduledata.gofunc（用于解析 ArgsPointerMaps）
	gofunc := findGofunc(bin)
	var rv *rodataView
	if rodata := bin.Sections[".rodata"]; rodata != nil {
		rv = newRodataView(rodata.Addr, rodata.Data)
	}
	funcMeta := ReadFuncMeta(pclntab.Data, bin.TextStart, gofunc, rv)

	for i := range goTable.Funcs {
		gf := &goTable.Funcs[i]
		name := gf.Name
		pkg := extractPkg(name)
		short := extractShort(name)

		file, line, _ := goTable.PCToLine(gf.Entry)

		argsSize := int32(-1)
		var ptrArgs []bool
		if meta, ok := funcMeta[gf.Entry]; ok {
			argsSize = meta.ArgsSize
			ptrArgs = meta.PtrArgs
		}

		fn := &Func{
			Name:      name,
			Package:   pkg,
			ShortName: short,
			Entry:     gf.Entry,
			End:       gf.End,
			File:      file,
			Line:      line,
			ArgsSize:  argsSize,
			PtrArgs:   ptrArgs,
		}
		t.Funcs = append(t.Funcs, fn)
		t.byPC[fn.Entry] = fn
	}

	return t, nil
}

// findGofunc 通过扫描 .noptrdata 中的 moduledata 来定位 gofunc 指针。
//
// 策略：
//  1. 在 .noptrdata 中搜索 pclntab.Addr（moduledata 首字段 = pcHeader 指针）
//  2. 从 moduledata 起始位置向后扫描，寻找形如 [types, etypes, rodata, gofunc] 的
//     四连续字段模式（types=etypes=rodata.Addr，gofunc 在 rodata 范围内且不等于 rodata.Addr）
//
// 返回 0 表示无法定位。
func findGofunc(bin *loader.Binary) uint64 {
	noptrdata := bin.Sections[".noptrdata"]
	pclntab := bin.Sections[".gopclntab"]
	rodata := bin.Sections[".rodata"]
	if noptrdata == nil || pclntab == nil || rodata == nil {
		return 0
	}

	pclntabVA := pclntab.Addr
	rodataVA := rodata.Addr
	rodataEnd := rodata.Addr + uint64(len(rodata.Data))

	data := noptrdata.Data

	// Step 1：找 moduledata（起始字为 pcHeader VA = pclntabVA）
	modStart := -1
	for i := 0; i+8 <= len(data); i += 8 {
		if binary.LittleEndian.Uint64(data[i:]) == pclntabVA {
			modStart = i
			break
		}
	}
	if modStart < 0 {
		return 0
	}

	// Step 2：从 moduledata 起始向后扫描，寻找 [types, etypes, rodata, gofunc] 模式
	//   types     = rodataVA
	//   etypes    ∈ (rodataVA, rodataEnd]
	//   rodata_f  = rodataVA（moduledata.rodata 字段，值与 types 相同）
	//   gofunc    ∈ (rodataVA, etypes)
	for i := modStart; i+32 <= len(data); i += 8 {
		v0 := binary.LittleEndian.Uint64(data[i:])    // types
		v1 := binary.LittleEndian.Uint64(data[i+8:])  // etypes
		v2 := binary.LittleEndian.Uint64(data[i+16:]) // rodata field
		v3 := binary.LittleEndian.Uint64(data[i+24:]) // gofunc candidate
		if v0 == rodataVA &&
			v1 > rodataVA && v1 <= rodataEnd &&
			v2 == rodataVA &&
			v3 > rodataVA && v3 < v1 {
			return v3
		}
	}
	return 0
}

// PCToFunc 返回包含 pc 的函数，若不存在返回 nil。
func (t *Table) PCToFunc(pc uint64) *Func {
	gf := t.goTable.PCToFunc(pc)
	if gf == nil {
		return nil
	}
	return t.byPC[gf.Entry]
}

func extractPkg(name string) string {
	// 先处理含 '/' 的模块路径
	if slashIdx := strings.LastIndex(name, "/"); slashIdx >= 0 {
		rest := name[slashIdx+1:]
		dot := strings.Index(rest, ".")
		if dot < 0 {
			return name
		}
		return name[:slashIdx+1+dot]
	}
	if lp := strings.Index(name, ".("); lp >= 0 {
		return name[:lp]
	}
	if dot := strings.Index(name, "."); dot >= 0 {
		return name[:dot]
	}
	return name
}

func extractShort(name string) string {
	pkg := extractPkg(name)
	if pkg == "" || len(pkg) >= len(name) {
		return name
	}
	short := name[len(pkg):]
	if len(short) > 0 && short[0] == '.' {
		short = short[1:]
	}
	return short
}
