// Package typeinfo 从 Go 二进制的 .typelink 节区恢复类型声明。
// 支持 Go 1.20+ (abi.Type 布局)。
package typeinfo

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/Yeah114/GoSpy/pkg/loader"
)

// Kind 对应 Go runtime 的类型 Kind。
type Kind uint8

const (
	KindInvalid       Kind = 0
	KindBool          Kind = 1
	KindInt           Kind = 2
	KindInt8          Kind = 3
	KindInt16         Kind = 4
	KindInt32         Kind = 5
	KindInt64         Kind = 6
	KindUint          Kind = 7
	KindUint8         Kind = 8
	KindUint16        Kind = 9
	KindUint32        Kind = 10
	KindUint64        Kind = 11
	KindUintptr       Kind = 12
	KindFloat32       Kind = 13
	KindFloat64       Kind = 14
	KindComplex64     Kind = 15
	KindComplex128    Kind = 16
	KindArray         Kind = 17
	KindChan          Kind = 18
	KindFunc          Kind = 19
	KindInterface     Kind = 20
	KindMap           Kind = 21
	KindPointer       Kind = 22
	KindSlice         Kind = 23
	KindString        Kind = 24
	KindStruct        Kind = 25
	KindUnsafePointer Kind = 26
)

func (k Kind) String() string {
	names := []string{"Invalid", "bool", "int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
		"float32", "float64", "complex64", "complex128",
		"Array", "chan", "func", "interface", "map", "*", "[]",
		"string", "struct", "unsafe.Pointer"}
	if int(k) < len(names) {
		return names[k]
	}
	return fmt.Sprintf("kind(%d)", k)
}

// ── 类型声明 IR ──────────────────────────────────────────────────────────────

// TypeDecl 是从二进制中恢复的一个类型声明。
type TypeDecl struct {
	Name    string      // 类型名（不含包名）
	Pkg     string      // 所属包路径
	Kind    Kind        // 类型 Kind
	Fields  []FieldDecl // Struct 类型的字段
	Methods []MethodDecl // Interface 的方法
	Elem    string      // Slice/Array/Ptr/Chan 的元素类型名
	Comment string      // 额外注释
}

// IsUserType 判断是否为用户包类型（非 runtime/internal）。
func (d *TypeDecl) IsUserType() bool {
	if d.Pkg == "" {
		return false
	}
	skip := []string{"runtime", "internal/", "sync", "reflect",
		"fmt", "os", "io", "syscall", "math", "strconv",
		"unicode", "errors", "sort", "time", "bufio",
		"bytes", "strings", "encoding", "atomic", "abi"}
	for _, s := range skip {
		if d.Pkg == s || strings.HasPrefix(d.Pkg, s) {
			return false
		}
	}
	return true
}

// GoDecl 生成 Go 类型声明代码。
func (d *TypeDecl) GoDecl() string {
	switch d.Kind {
	case KindStruct:
		return d.structDecl()
	case KindInterface:
		return d.ifaceDecl()
	default:
		// 命名基础类型，如 type Category int
		if d.Elem != "" {
			return fmt.Sprintf("type %s %s", d.Name, d.Elem)
		}
		return fmt.Sprintf("// type %s %s", d.Name, d.Kind)
	}
}

func (d *TypeDecl) structDecl() string {
	var b strings.Builder
	if d.Comment != "" {
		b.WriteString("// " + d.Comment + "\n")
	}
	b.WriteString("type " + d.Name + " struct {\n")
	for _, f := range d.Fields {
		if f.Hidden {
			continue
		}
		if f.Tag != "" {
			fmt.Fprintf(&b, "\t%s %s `%s`\n", f.Name, f.TypeName, f.Tag)
		} else {
			fmt.Fprintf(&b, "\t%s %s\n", f.Name, f.TypeName)
		}
	}
	b.WriteString("}")
	return b.String()
}

func (d *TypeDecl) ifaceDecl() string {
	var b strings.Builder
	b.WriteString("type " + d.Name + " interface {\n")
	for _, m := range d.Methods {
		b.WriteString("\t" + m.Name + m.Sig + "\n")
	}
	b.WriteString("}")
	return b.String()
}

// FieldDecl 结构体字段。
type FieldDecl struct {
	Name     string
	TypeName string
	Tag      string
	Offset   uint64
	Hidden   bool // 不输出到 struct 声明，仅用于偏移替换（如分组字段的子偏移）
}

// MethodDecl 接口方法。
type MethodDecl struct {
	Name string
	Sig  string // "(arg) ret"
}

// ── 解析器 ──────────────────────────────────────────────────────────────────

// abiTypeSize 是 abi.Type 结构体的大小（amd64 = 48 bytes）。
const abiTypeSize = 48

// Parser 从二进制解析类型信息。
type Parser struct {
	bin        *loader.Binary
	rodataAddr uint64
	rodataEnd  uint64
	rodataData []byte
	order      binary.ByteOrder
}

// New 创建类型解析器。
func New(bin *loader.Binary) *Parser {
	p := &Parser{bin: bin, order: bin.Order}
	if r := bin.Sections[".rodata"]; r != nil {
		p.rodataAddr = r.Addr
		p.rodataEnd = r.Addr + uint64(len(r.Data))
		p.rodataData = r.Data
	}
	return p
}

// Go 1.20+ TFlag 位定义（internal/abi/type.go）。
const (
	tflagExtraStar = uint8(1 << 1) // Str 字段携带额外的 '*' 前缀（需去除）
	tflagNamed     = uint8(1 << 2) // 有名称的类型（非匿名）
)

// ParseAll 解析 .typelink 中的所有类型。
func (p *Parser) ParseAll() ([]*TypeDecl, error) {
	tl := p.bin.Sections[".typelink"]
	if tl == nil {
		return nil, nil
	}

	n := len(tl.Data) / 4
	var decls []*TypeDecl
	seen := make(map[uint64]bool)

	for i := range n {
		off32 := int32(p.order.Uint32(tl.Data[i*4:]))
		// typelink 中的偏移量相对于 .rodata 起始地址，应为非负值
		taddr := p.rodataAddr + uint64(off32)

		absOff := p.rodataOff(taddr)
		if absOff < 0 || absOff+abiTypeSize > int64(len(p.rodataData)) {
			continue
		}

		d := p.rodataData[absOff:]
		kind := Kind(d[23] & 0x1f)

		// 指针类型（kind=22）：跟随 Elem *Type 指针到实际类型
		typeAddr := taddr
		if kind == KindPointer {
			if absOff+int64(abiTypeSize)+8 > int64(len(p.rodataData)) {
				continue
			}
			elemVA := p.order.Uint64(d[abiTypeSize:])
			if !p.inRodata(elemVA) {
				continue
			}
			typeAddr = elemVA
		}

		if seen[typeAddr] {
			continue
		}
		seen[typeAddr] = true

		decl, err := p.parseType(typeAddr)
		if err != nil || decl == nil {
			continue
		}
		decls = append(decls, decl)
	}
	return decls, nil
}

// parseType 解析位于 va 处的 abi.Type 并返回 TypeDecl（若感兴趣）。
func (p *Parser) parseType(va uint64) (*TypeDecl, error) {
	off := p.rodataOff(va)
	if off < 0 || off+abiTypeSize > int64(len(p.rodataData)) {
		return nil, nil
	}
	d := p.rodataData[off:]

	// abi.Type 布局 (Go 1.20+ amd64)
	// [0]  Size_       uintptr  (8)
	// [8]  PtrBytes    uintptr  (8)
	// [16] Hash        uint32   (4)
	// [20] Tflag       uint8    (1)
	// [21] Align_      uint8    (1)
	// [22] FieldAlign_ uint8    (1)
	// [23] Kind_       uint8    (1, low 5 bits = kind)
	// [24] Equal       ptr      (8)
	// [32] GCData      ptr      (8)
	// [40] Str         int32    (4) ← nameOff relative to rodata base
	// [44] PtrToThis   int32    (4)
	kind := Kind(d[23] & 0x1f)
	tflag := d[20]
	strOff := int32(p.order.Uint32(d[40:]))

	typeName, _, _ := p.readName(p.rodataAddr + uint64(strOff))
	if typeName == "" {
		return nil, nil
	}

	// TFlagExtraStar（bit 1）：Str 字段携带了额外的 '*' 前缀，需要去除。
	// Go 编译器用此技巧让指针类型和基础类型共享同一个名称字符串。
	if tflag&tflagExtraStar != 0 && len(typeName) > 0 && typeName[0] == '*' {
		typeName = typeName[1:]
	}

	// 解析 "pkg.TypeName" 格式的限定名（如 "main.Person" → pkg="main", name="Person"）
	var pkg string
	if dot := strings.LastIndex(typeName, "."); dot >= 0 {
		pkg = typeName[:dot]
		// 去掉 vendor/ 等前缀
		if idx := strings.LastIndex(pkg, "/"); idx >= 0 {
			pkg = pkg[idx+1:]
		}
		typeName = typeName[dot+1:]
	}

	if typeName == "" {
		return nil, nil
	}

	// 只保留 TFlagNamed 标记的命名类型（或 struct/interface）
	isNamed := tflag&tflagNamed != 0
	if !isNamed && kind != KindStruct && kind != KindInterface {
		return nil, nil
	}

	// 跳过匿名复合类型
	if strings.HasPrefix(typeName, "struct {") ||
		strings.HasPrefix(typeName, "interface {") ||
		strings.HasPrefix(typeName, "func(") ||
		strings.HasPrefix(typeName, "map[") ||
		strings.HasPrefix(typeName, "[]") ||
		strings.HasPrefix(typeName, "[") ||
		strings.HasPrefix(typeName, "chan ") {
		return nil, nil
	}

	decl := &TypeDecl{Name: typeName, Pkg: pkg, Kind: kind}

	switch kind {
	case KindStruct:
		if err := p.parseStructFields(va, decl); err != nil {
			decl.Comment = "fields not recovered: " + err.Error()
		}
	case KindInterface:
		p.parseIfaceMethods(va, decl)
	default:
		// 命名的基础类型（如 type Category int）：记录底层类型
		decl.Elem = kind.String()
	}

	return decl, nil
}

// parseStructFields 解析 StructType 的字段列表。
// StructType 布局（紧接 abi.Type 之后）：
//
//	+48: PkgPath Name (8 bytes = ptr to name bytes)
//	+56: Fields  []StructField (ptr=8, len=8, cap=8 = 24 bytes)
//
// StructField：Name_(8) + Typ*(8) + Offset(8) = 24 bytes
func (p *Parser) parseStructFields(va uint64, decl *TypeDecl) error {
	off := p.rodataOff(va)
	if off < 0 || off+80 > int64(len(p.rodataData)) {
		return fmt.Errorf("out of bounds")
	}
	d := p.rodataData[off:]

	// PkgPath @ +48 (ptr to name)
	pkgPtr := p.order.Uint64(d[48:])
	if pkgPtr != 0 && p.inRodata(pkgPtr) {
		pkgName, _, _ := p.readName(pkgPtr)
		if pkgName != "" {
			decl.Pkg = pkgName
		}
	}

	// Fields slice @ +56
	fieldsPtr := p.order.Uint64(d[56:])
	fieldsLen := int(p.order.Uint64(d[64:]))

	if fieldsPtr == 0 || fieldsLen <= 0 || fieldsLen > 512 || !p.inRodata(fieldsPtr) {
		return nil // 空 struct 或无法解析
	}

	fieldBase := p.rodataOff(fieldsPtr)
	if fieldBase < 0 || fieldBase+int64(fieldsLen)*24 > int64(len(p.rodataData)) {
		return fmt.Errorf("fields out of rodata bounds")
	}

	for i := range fieldsLen {
		fd := p.rodataData[fieldBase+int64(i)*24:]
		namePtr := p.order.Uint64(fd[0:])
		typPtr := p.order.Uint64(fd[8:])
		offset := p.order.Uint64(fd[16:])

		fname := ""
		if p.inRodata(namePtr) {
			fname, _, _ = p.readName(namePtr)
		}
		if fname == "" {
			fname = fmt.Sprintf("_field%d", i)
		}

		ftypName := "interface{}" // 默认
		if p.inRodata(typPtr) {
			ftypName = p.typeName(typPtr)
		}
		// 去除同包前缀（如 "main.Category" → "Category"）
		if decl.Pkg != "" {
			prefix := decl.Pkg + "."
			ftypName = strings.TrimPrefix(ftypName, prefix)
			// 处理指针类型 "*main.Category" → "*Category"
			if strings.HasPrefix(ftypName, "*"+prefix) {
				ftypName = "*" + ftypName[1+len(prefix):]
			}
		}

		decl.Fields = append(decl.Fields, FieldDecl{
			Name:     fname,
			TypeName: ftypName,
			Offset:   offset,
		})
	}
	return nil
}

// parseIfaceMethods 解析 InterfaceType 的方法列表。
// InterfaceType 布局：
//
//	+48: PkgPath Name (8 bytes)
//	+56: Methods []Imethod (ptr=8, len=8, cap=8)
//
// Imethod: Name NameOff(4) + Typ TypeOff(4) = 8 bytes
func (p *Parser) parseIfaceMethods(va uint64, decl *TypeDecl) {
	off := p.rodataOff(va)
	if off < 0 || off+80 > int64(len(p.rodataData)) {
		return
	}
	d := p.rodataData[off:]

	methodsPtr := p.order.Uint64(d[56:])
	methodsLen := int(p.order.Uint64(d[64:]))

	if methodsPtr == 0 || methodsLen <= 0 || methodsLen > 512 || !p.inRodata(methodsPtr) {
		return
	}

	mbase := p.rodataOff(methodsPtr)
	if mbase < 0 || mbase+int64(methodsLen)*8 > int64(len(p.rodataData)) {
		return
	}

	for i := range methodsLen {
		md := p.rodataData[mbase+int64(i)*8:]
		nameOff := int32(p.order.Uint32(md[0:]))
		mname, _, _ := p.readName(p.rodataAddr + uint64(nameOff))
		if mname == "" {
			continue
		}
		decl.Methods = append(decl.Methods, MethodDecl{
			Name: mname,
			Sig:  "()",
		})
	}
}

// typeName 尝试获取指针所指向的 abi.Type 的类型名称字符串（用于字段类型）。
func (p *Parser) typeName(va uint64) string {
	off := p.rodataOff(va)
	if off < 0 || off+abiTypeSize > int64(len(p.rodataData)) {
		return "interface{}"
	}
	d := p.rodataData[off:]
	kind := Kind(d[23] & 0x1f)
	tflag := d[20]
	strOff := int32(p.order.Uint32(d[40:]))
	name, _, _ := p.readName(p.rodataAddr + uint64(strOff))
	if name == "" {
		return kind.String()
	}
	// 去除 TFlagExtraStar 多余的 '*' 前缀
	if tflag&tflagExtraStar != 0 && len(name) > 0 && name[0] == '*' {
		name = name[1:]
	}
	// 把 "pkg.Name" 中的包名部分提取为更短的形式
	if dot := strings.LastIndex(name, "."); dot >= 0 {
		pkg := name[:dot]
		if idx := strings.LastIndex(pkg, "/"); idx >= 0 {
			pkg = pkg[idx+1:]
		}
		name = pkg + "." + name[dot+1:]
	}
	return name
}

// readName 从 .rodata 中读取 Go 内部名称编码。
// 格式：1byte flags | varint length | name bytes [ | varint tag_len | tag | pkg_path ]
// 返回 (name, pkg, exported)。
func (p *Parser) readName(va uint64) (name, pkg string, exported bool) {
	if !p.inRodata(va) {
		return "", "", false
	}
	off := p.rodataOff(va)
	data := p.rodataData[off:]
	if len(data) < 2 {
		return "", "", false
	}

	flags := data[0]
	exported = flags&1 != 0
	hasTag := flags&2 != 0
	hasPkg := flags&4 != 0

	// varint length
	b := 1
	nameLen := 0
	for shift := 0; b < len(data); shift += 7 {
		x := data[b]
		b++
		nameLen |= int(x&0x7f) << shift
		if x&0x80 == 0 {
			break
		}
	}
	if b+nameLen > len(data) {
		return "", "", false
	}
	name = string(data[b : b+nameLen])
	b += nameLen

	// 跳过 tag
	if hasTag && b < len(data) {
		tagLen := 0
		for shift := 0; b < len(data); shift += 7 {
			x := data[b]
			b++
			tagLen |= int(x&0x7f) << shift
			if x&0x80 == 0 {
				break
			}
		}
		b += tagLen
	}

	// 读取包路径指针（4 bytes，int32 nameOff）
	if hasPkg && b+4 <= len(data) {
		pkgOff := int32(p.order.Uint32(data[b:]))
		pkg, _, _ = p.readName(p.rodataAddr + uint64(pkgOff))
	}

	return name, pkg, exported
}

func (p *Parser) inRodata(va uint64) bool {
	return va >= p.rodataAddr && va < p.rodataEnd
}

func (p *Parser) rodataOff(va uint64) int64 {
	if va < p.rodataAddr || va >= p.rodataEnd {
		return -1
	}
	return int64(va - p.rodataAddr)
}
