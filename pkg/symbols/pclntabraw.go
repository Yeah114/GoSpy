// pclntabraw.go：解析 .gopclntab 原始二进制，提取每个函数的元数据。
//
// Go 1.20+ pclntab（magic = 0xfffffff1）头部布局（从字节 0 起）：
//
//	[0:4]   magic = 0xfffffff1
//	[4]     minLC
//	[5]     quantumSize
//	[6]     quantum (x86 = 1)
//	[7]     ptrSize = 8
//	[8:16]  field[0] = nfunctab (uint64)
//	[16:24] field[1] = nfiletab (uint64)
//	[24:32] field[2] = textStart（与 gosym.NewLineTable 的 textBase 相同）
//	[32:40] field[3] = funcnametabOff
//	[40:48] field[4] = cutabOff
//	[48:56] field[5] = filetabOff
//	[56:64] field[6] = pctabOff
//	[64:72] field[7] = funcdataOff（同时也是 functabOff）
//
// functab 与 funcdata 指向同一区域（pclntab[funcdataOff:]），
// 其中 functab 由 (nfunctab*2+1) 条 {pcval uint32, funcOff uint32} 组成，
// funcentry（_func struct）位于 funcdata[funcOff]：
//
//	[0:4]  entryOff uint32
//	[4:8]  nameOff  int32
//	[8:12] args     int32   ← 输入参数帧大小（字节）
//	[28:32] npcdata uint32
//	[40]   funcID   uint8
//	[41]   flag     uint8
//	[43]   nfuncdata uint8
//	[44 + npcdata*4 + i*4] funcdata[i] uint32  ← 相对 gofunc 的偏移
//
// ArgsPointerMaps（funcdata[0]）指向一个 stackmap：
//
//	[0:4]   n    int32   ← 位图数量（生命周期状态数）
//	[4:8]   nbit int32   ← 每个位图中的位数（≤ argsSize/8，省略末尾标量）
//	[8:...]        bitmap[0], bitmap[1], ...（各 ceil(nbit/8) 字节）
//
// bitmap[0] = 函数入口时各参数寄存器槽的 GC 指针标志：bit i=1 表示第 i 个槽为指针。
package symbols

import "encoding/binary"

// FuncMeta 保存从 pclntab 原始数据中提取的单个函数元数据。
type FuncMeta struct {
	// ArgsSize 是 _func.args 字段的值：输入参数帧字节数。
	// Go 1.17+ 寄存器 ABI 下，此值等于所有输入参数寄存器槽的总大小（8 bytes/slot）。
	// -1 表示无法解析。
	ArgsSize int32

	// PtrArgs 记录每个 ABI 输入参数寄存器槽是否为 GC 指针（来自 ArgsPointerMaps）。
	// nil 表示无法获取该信息（gofunc 未知或 funcdata[0] 不存在）。
	// 长度 = argsSize/8，bit i=true 表示第 i 个寄存器槽持有指针。
	PtrArgs []bool
}

// ReadFuncMeta 从 .gopclntab 原始字节读取每个函数的元数据。
//
//   - pclntabData: .gopclntab 节区完整字节
//   - textStart:   .text 起始虚拟地址
//   - gofunc:      moduledata.gofunc 指针（funcdata 偏移量的基准 VA）；
//     0 表示未知，将跳过 PtrArgs 解析
//   - rodata:      .rodata 节区（用于读取 stackmap）；nil 表示不可用
func ReadFuncMeta(pclntabData []byte, textStart uint64, gofunc uint64, rodata *rodataView) map[uint64]FuncMeta {
	if len(pclntabData) < 72 {
		return nil
	}
	// 仅支持 Go 1.20+ 格式（magic = 0xfffffff1）
	magic := binary.LittleEndian.Uint32(pclntabData[0:])
	if magic != 0xfffffff1 {
		return nil
	}

	readField := func(n int) uint64 {
		off := 8 + n*8
		if off+8 > len(pclntabData) {
			return 0
		}
		return binary.LittleEndian.Uint64(pclntabData[off:])
	}

	nfunctab := uint32(readField(0))
	funcdataOff := readField(7) // functab = funcdata，两者起始相同

	if int(funcdataOff) >= len(pclntabData) {
		return nil
	}
	funcdata := pclntabData[funcdataOff:]
	functabBytes := (int(nfunctab)*2 + 1) * 8

	result := make(map[uint64]FuncMeta, nfunctab)

	for i := uint32(0); i < nfunctab; i++ {
		ftOff := int(i) * 8
		if ftOff+8 > functabBytes || ftOff+8 > len(funcdata) {
			break
		}
		pcval := binary.LittleEndian.Uint32(funcdata[ftOff:])
		funcOff := binary.LittleEndian.Uint32(funcdata[ftOff+4:])

		if int(funcOff)+44 > len(funcdata) {
			continue
		}
		fe := funcdata[funcOff:]
		argsSize := int32(binary.LittleEndian.Uint32(fe[8:]))

		var ptrArgs []bool
		if gofunc != 0 && rodata != nil && argsSize > 0 {
			npcdata := int(binary.LittleEndian.Uint32(fe[28:]))
			nfuncdata := int(fe[43])
			if nfuncdata > 0 {
				fdBase := 44 + npcdata*4
				if fdBase+4 <= len(fe) {
					fd0 := binary.LittleEndian.Uint32(fe[fdBase:])
					if fd0 != 0 && fd0 != 0xffffffff {
						ptrArgs = parseArgsPtrMap(fd0, gofunc, int(argsSize/8), rodata)
					}
				}
			}
		}

		entryVA := textStart + uint64(pcval)
		result[entryVA] = FuncMeta{ArgsSize: argsSize, PtrArgs: ptrArgs}
	}

	return result
}

// parseArgsPtrMap 从 ArgsPointerMaps stackmap 中解析各参数槽的指针标志。
// fd0 = funcdata[0] 相对 gofunc 的偏移；nSlots = argsSize/8。
func parseArgsPtrMap(fd0 uint32, gofunc uint64, nSlots int, rv *rodataView) []bool {
	va := gofunc + uint64(fd0)
	data, ok := rv.read(va, 9) // 至少需要头部 8 字节 + 1 字节 bytedata
	if !ok {
		return nil
	}
	n := int32(binary.LittleEndian.Uint32(data[0:]))
	nbit := int32(binary.LittleEndian.Uint32(data[4:]))
	if n <= 0 || nbit <= 0 || nbit > 256 {
		return nil
	}
	// bitmap[0] 数据：ceil(nbit/8) 字节，从 data[8] 开始
	byteLen := int((nbit + 7) / 8)
	bitmapData, ok := rv.read(va+8, byteLen)
	if !ok {
		return nil
	}
	ptrArgs := make([]bool, nSlots)
	for slot := 0; slot < nSlots && slot < int(nbit); slot++ {
		if bitmapData[slot/8]&(1<<uint(slot%8)) != 0 {
			ptrArgs[slot] = true
		}
	}
	return ptrArgs
}

// rodataView 提供对 .rodata 节区的虚拟地址读取视图。
type rodataView struct {
	addr uint64
	data []byte
}

func newRodataView(addr uint64, data []byte) *rodataView {
	return &rodataView{addr: addr, data: data}
}

func (rv *rodataView) read(va uint64, n int) ([]byte, bool) {
	if va < rv.addr || va >= rv.addr+uint64(len(rv.data)) {
		return nil, false
	}
	off := int(va - rv.addr)
	if off+n > len(rv.data) {
		return nil, false
	}
	return rv.data[off : off+n], true
}
