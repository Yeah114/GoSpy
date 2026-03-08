// Package loader 负责加载 ELF 二进制文件并提取相关节区。
package loader

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
)

// Section 表示已加载的 ELF 节区。
type Section struct {
	Name string
	Addr uint64 // 虚拟地址
	Data []byte // 原始字节
}

// Binary 表示已加载的 Go ELF 二进制。
type Binary struct {
	Path      string
	Arch      string
	Entry     uint64
	TextStart uint64
	Sections  map[string]*Section
	Order     binary.ByteOrder
}

// Load 加载 ELF 二进制文件并提取关键节区。
func Load(path string) (*Binary, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ELF: %w", err)
	}
	defer f.Close()

	if f.Machine != elf.EM_X86_64 {
		return nil, fmt.Errorf("unsupported arch: %v (only amd64 supported)", f.Machine)
	}

	b := &Binary{
		Path:     path,
		Arch:     "amd64",
		Entry:    f.Entry,
		Sections: make(map[string]*Section),
		Order:    binary.LittleEndian,
	}

	wanted := []string{
		".text", ".rodata", ".gopclntab", ".gosymtab",
		".typelink", ".itablink", ".go.buildinfo",
		".data",     // 全局对象/静态值（用于恢复 error 等全局实参来源）
		".noptrdata", // 用于定位 moduledata（gofunc 指针）
	}
	for _, name := range wanted {
		s := f.Section(name)
		if s == nil {
			continue
		}
		data, err := s.Data()
		if err != nil {
			return nil, fmt.Errorf("read section %s: %w", name, err)
		}
		b.Sections[name] = &Section{Name: name, Addr: s.Addr, Data: data}
	}

	if text, ok := b.Sections[".text"]; ok {
		b.TextStart = text.Addr
	}

	return b, nil
}

// AddrToOffset 将虚拟地址转换为某节区内的偏移，返回节区和偏移量。
func (b *Binary) AddrToOffset(addr uint64) (*Section, uint64, bool) {
	for _, s := range b.Sections {
		if addr >= s.Addr && addr < s.Addr+uint64(len(s.Data)) {
			return s, addr - s.Addr, true
		}
	}
	return nil, 0, false
}

// ReadAt 从指定虚拟地址读取 n 字节。
func (b *Binary) ReadAt(addr uint64, n int) ([]byte, bool) {
	s, off, ok := b.AddrToOffset(addr)
	if !ok {
		return nil, false
	}
	end := off + uint64(n)
	if end > uint64(len(s.Data)) {
		end = uint64(len(s.Data))
	}
	out := make([]byte, end-off)
	copy(out, s.Data[off:end])
	return out, true
}
