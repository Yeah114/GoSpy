// Package buildinfo 从 Go 二进制的 .go.buildinfo 节区读取模块元数据。
package buildinfo

import (
	"debug/buildinfo"
	"fmt"
	rdbg "runtime/debug"
)

// Info 保存从二进制读取的构建信息。
type Info struct {
	GoVersion string // 编译所用 Go 版本，如 "go1.25.1"
	ModPath   string // 主模块路径，如 "github.com/foo/bar"
	ModVer    string // 主模块版本
	Deps      []*Dep // 依赖列表
}

// Dep 表示一个模块依赖。
type Dep struct {
	Path    string
	Version string
	Replace *Dep // replace 指令（若有）
}

// IsUserPkg 判断 pkg 是否属于主模块（用户代码）。
func (info *Info) IsUserPkg(pkg string) bool {
	if info == nil || info.ModPath == "" {
		return false
	}
	return pkg == info.ModPath || len(pkg) > len(info.ModPath) && pkg[:len(info.ModPath)] == info.ModPath
}

// Parse 从已编译的 Go 二进制读取 BuildInfo。
func Parse(binPath string) (*Info, error) {
	bi, err := buildinfo.ReadFile(binPath)
	if err != nil {
		return nil, fmt.Errorf("read buildinfo: %w", err)
	}

	info := &Info{
		GoVersion: bi.GoVersion,
		ModPath:   bi.Path,
	}
	if bi.Main.Path != "" {
		info.ModPath = bi.Main.Path
		info.ModVer = bi.Main.Version
	}
	for _, dep := range bi.Deps {
		d := &Dep{Path: dep.Path, Version: dep.Version}
		if dep.Replace != nil {
			d.Replace = &Dep{Path: dep.Replace.Path, Version: dep.Replace.Version}
		}
		info.Deps = append(info.Deps, d)
	}
	return info, nil
}

// GoModContent 生成对应的 go.mod 文件内容。
func (info *Info) GoModContent() string {
	if info == nil {
		return "module decompiled\n\ngo 1.21\n"
	}
	ver := info.GoVersion
	if len(ver) > 2 && ver[:2] == "go" {
		ver = ver[2:]
	}
	s := fmt.Sprintf("module %s\n\ngo %s\n", info.ModPath, ver)
	if len(info.Deps) > 0 {
		s += "\nrequire (\n"
		for _, d := range info.Deps {
			s += fmt.Sprintf("\t%s %s\n", d.Path, d.Version)
		}
		s += ")\n"
	}
	return s
}

// BuildSettings 返回构建设置列表（可选）。
func (info *Info) BuildSettings(bi *rdbg.BuildInfo) []rdbg.BuildSetting {
	if bi == nil {
		return nil
	}
	return bi.Settings
}
