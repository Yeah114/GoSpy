// GoSpy —— Go 二进制反编译器
//
// 支持 Linux amd64，使用 -s -w 编译的 stripped Go 程序。
// 从 gopclntab + typelink + 反汇编中恢复 Go 源码结构。
//
// 用法:
//
//	gospy [选项] <binary>
//
// 示例:
//
//	gospy -o output example/1/main
//	gospy -deps -gomod -o out ./myapp
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Yeah114/GoSpy/pkg/decompiler"
)

func main() {
	outDir := flag.String("o", "output", "反编译输出目录")
	verbose := flag.Bool("v", false, "详细日志")
	deps := flag.Bool("deps", false, "同时还原标准库和依赖库代码")
	gomod := flag.Bool("gomod", false, "在输出目录生成 go.mod")
	pkg := flag.String("pkg", "", "仅输出指定包（调试用，如 main）")

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "GoSpy - Go 二进制反编译器 (Linux amd64, -s -w)")
		fmt.Fprintln(os.Stderr, "\n用法: gospy [选项] <binary>")
		fmt.Fprintln(os.Stderr, "\n选项:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\n示例:")
		fmt.Fprintln(os.Stderr, "  gospy -o output example/1/main          # 还原用户代码")
		fmt.Fprintln(os.Stderr, "  gospy -deps -gomod -o out ./myapp        # 含依赖库 + go.mod")
		fmt.Fprintln(os.Stderr, "  gospy -pkg main -v -o out ./myapp        # 仅还原 main 包")
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	cfg := &decompiler.Config{
		OutputDir:   *outDir,
		Verbose:     *verbose,
		IncludeDeps: *deps,
		OnlyPackage: *pkg,
		WriteGoMod:  *gomod,
	}

	d, err := decompiler.New(flag.Arg(0), cfg)
	if err != nil {
		log.Fatalf("错误: %v", err)
	}

	// 打印模块信息
	if info := d.ModuleInfo(); info != nil {
		fmt.Printf("模块: %s (%s)  Go: %s  依赖: %d 个\n",
			info.ModPath, info.ModVer, info.GoVersion, len(info.Deps))
	}

	stats, err := d.Decompile()
	if err != nil {
		log.Fatalf("反编译失败: %v", err)
	}

	fmt.Printf("\n完成！扫描 %d 函数  →  输出 %d 函数 / %d 类型 / %d 文件  →  %s\n",
		stats.TotalFuncs, stats.OutputFuncs, stats.Types, stats.Files, *outDir)
}
