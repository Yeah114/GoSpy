# GoSpy 开发指南：如何继续完善代码

> 本文档面向想要深入理解并持续改进 GoSpy 反编译器的开发者。

---

## 目录

1. [项目背景与架构](#1-项目背景与架构)
2. [开发环境搭建](#2-开发环境搭建)
3. [完整数据流程](#3-完整数据流程)
4. [各模块详解](#4-各模块详解)
5. [已知问题与改进方向（按优先级排序）](#5-已知问题与改进方向)
6. [测试方法](#6-测试方法)
7. [代码规范](#7-代码规范)

---

## 1. 项目背景与架构

GoSpy 是一个针对 **Linux amd64**、使用 `-s -w`（剥离调试信息）编译的 Go 二进制文件的静态反编译器。

### 核心挑战

Go 二进制即使经过 `-s -w` 剥离，仍保留关键元数据：

| 节区 | 保留内容 | 用途 |
|------|---------|------|
| `.gopclntab` | 函数名、源文件路径、行号 | 恢复函数签名 |
| `.rodata` | 字符串字面量、类型信息 | 恢复字符串和类型 |
| `.typelink` | 类型偏移数组（`int32[]`） | 恢复 struct/interface 声明 |
| `.text` | 机器码 | 反汇编 → 控制流分析 |

### 项目文件结构

```
GoSpy/
├── cmd/gospy/main.go               # CLI 入口（-o, -v, -pkg, -deps, -gomod）
├── pkg/
│   ├── loader/elf.go               # ELF 文件加载，提取各节区数据
│   ├── symbols/
│   │   ├── table.go                # 通过 pclntab 恢复函数符号表
│   │   └── pclntabraw.go           # pclntab 原始解析（参数位图）
│   ├── disasm/disasm.go            # x86-64 反汇编封装（golang.org/x/arch）
│   ├── analysis/
│   │   ├── ir.go                   # 中间表示（Stmt/Expr/IncrStmt 等类型）
│   │   ├── cfg.go                  # 控制流图构建 + 结构化控制流提升
│   │   ├── analyzer.go             # 指令模式分析（字符串、调用、自增检测）
│   │   ├── fields.go               # stub 结构体字段推断（内存访问模式）
│   │   └── params.go               # 函数参数类型检测
│   ├── typeinfo/parser.go          # 从 .typelink 节区恢复类型声明
│   ├── buildinfo/parser.go         # 提取构建信息（Go 版本、模块路径）
│   ├── codegen/gen.go              # 将 IR 翻译为 Go 源代码
│   └── decompiler/decompiler.go    # 总协调器，串联全部流程
├── example/
│   ├── 1/main.go                   # 简单示例（hello world）
│   └── 2/main.go                   # 复杂示例（struct/interface/goroutine）
└── output/                         # 默认反编译输出目录
```

---

## 2. 开发环境搭建

```bash
# 克隆并进入项目
cd /root/GoSpy

# 构建反编译器
go build -o gospy ./cmd/gospy

# 编译 example/2（用于测试）
cd example/2 && go build -ldflags="-s -w" -o main . && cd ../..

# 运行反编译
./gospy -pkg main -o output example/2/main

# 查看结果
cat output/main/main.go

# 静态检查（每次改动后运行）
staticcheck ./...
go vet ./...
```

**推荐工作流**：每次改动后 `go build -o gospy ./cmd/gospy && ./gospy -pkg main -o /tmp/test example/2/main && cat /tmp/test/main/main.go`

---

## 3. 完整数据流程

```
ELF 二进制
    │
    ▼
loader.Load()
    │  提取 .text / .rodata / .typelink / .gopclntab 等节区
    ▼
symbols.Build()
    │  解析 .gopclntab → Func{Name, Entry, End, ArgsSize, PtrArgs}
    ▼
typeinfo.Parser.ParseAll()        buildinfo.Parse()
    │  从 .typelink 恢复：                │
    │  - struct 字段（abi.Type 布局）     │  Go 版本、模块路径、依赖
    │  - interface 方法                   │
    ▼                                     ▼
decompiler.inferMissingTypes()     ← 合并 →
    │  从方法名推断 typelink 未覆盖的类型（如 Team）
    ▼
analysis.AnalyzeReceiverFields()
    │  通过 [RAX+offset] 内存访问模式推断 stub 结构体字段
    ▼
analysis.Analyzer.AnalyzeFunc()  ← 对每个目标函数
    │  1. disasm.Func() 反汇编机器码 → []*Inst
    │  2. analysis.Build() 构建 CFG
    │  3. CFG.Lift() 结构化控制流提升 → []*Stmt（if/for/call 等）
    │  4. DetectParams() 检测参数类型
    ▼
codegen.Generate()
    │  IR → Go 源代码：
    │  - 变量重命名（寄存器名 → 有意义名称）
    │  - 字段替换（[rax+0x28] → r.Category）
    │  - stdlib 调用修正（fmt.Fprintln → fmt.Println）
    │  - import 收集与整理
    ▼
输出 .go 文件
```

---

## 4. 各模块详解

### 4.1 `pkg/analysis/ir.go` — 中间表示

IR 是连接反汇编与代码生成的核心桥梁。目前支持的语句类型：

```go
StmtCall    // 普通函数调用
StmtReturn  // return 语句
StmtGo      // go 关键字（runtime.newproc）
StmtDefer   // defer 关键字（runtime.deferproc）
StmtPanic   // panic（runtime.gopanic）
StmtIf      // if/if-else 语句
StmtFor     // for 循环
StmtIncr    // i++/i-- 自增
StmtAsm     // 无法结构化的汇编（降级到注释）
```

**如何添加新语句类型**：在 `ir.go` 中新增 `StmtXxx` 常量和对应字段，在 `cfg.go` 的 `liftFrom` 或 `analyzer.go` 的 `extractBlock` 中产生它，在 `codegen/gen.go` 的 `renderStmts` 中渲染它。

---

### 4.2 `pkg/analysis/cfg.go` — 控制流图

**CFG 构建三步骤**（`Build` 函数）：

1. **找 leader**：跳转目标地址和跳转后下一条指令都是基本块起点
2. **切分基本块**：按 leader 边界将指令序列切分为 `Block`
3. **连接边**：`TermCond` 产生 fall-through 和 branch-taken 两条边

**结构化控制流提升**（`liftFrom` 函数，第 168 行）的决策树：

```
TermCond 块（有条件跳转）
    │
    ├─ 是否为回边（IsBackEdge）？
    │      是 → for 循环：liftFrom(jmpBlk, stopAt=当前块)
    │
    └─ 前向分支 → if / if-else
           │
           ├─ mergeBlock(fallBlk, jmpBlk) 找到 merge 点？
           │      是 → if-else（两路路径均到 merge 点）
           │
           ├─ jmpBlk 快速终止（quicklyTerminates）？
           │      是 → if cond { jmpBlk_stmts }（早期出口）
           │
           ├─ fallBlk 快速终止？
           │      是 → if negCond { fallBlk_stmts }（否定早期出口）
           │
           ├─ mergeBlockExtended 找到共享出口？
           │      是 → if-else（含后向 JMP 跳转的汇合）
           │
           └─ 降级 → 输出 `// if cond { goto 0x... }` 注释
```

**扩展建议**：`switch` 语句目前未识别。Go 编译器将 `switch` 编译为一组 `CMP + JE/JL` 序列或跳转表。可以在 `TermIndirect` 处（间接跳转）检测跳转表模式，识别并提升为 `StmtSwitch`。

---

### 4.3 `pkg/analysis/analyzer.go` — 指令分析

核心函数 `extractBlock` 对基本块的每条指令进行模式匹配：

| 指令类型 | 处理逻辑 |
|---------|---------|
| `CALL` | 查符号表得到函数名；收集字符串候选作为参数；整数候选匹配 ABI 槽位 |
| `LEA [rip+N]` | 检查目标是否在 .rodata；Pattern B：向后找配对立即数 |
| `MOV reg, imm` | 若目标是 ABI 参数寄存器，记录为整数候选（intCandidates） |
| `INC/DEC/ADD/SUB` | 检测自增模式，生成 StmtIncr |
| `RET` | 尝试把字符串候选附加到 return |

**字符串检测两种模式**：

```
Pattern A（字符串结构体）：
  LEA RAX, [rip+0x1234]   ← rodata 地址
  → tryStringStruct(va)：读取 {ptr uint64, len int64}，验证 ptr 指向可读字符串

Pattern B（立即数长度）：
  LEA RAX, [rip+0x1234]   ← 字符串数据地址
  MOV RDI, 5              ← 字符串长度（在后续 4 条指令内）
  → 直接读取 rodata[addr:addr+5]
  注意：遇到第二个 LEA 立即中止搜索（防止不同参数的 LEA 互相干扰）
```

---

### 4.4 `pkg/analysis/params.go` — 参数检测

参数检测有两条路径：

**路径 A（精确，pclntab 位图）**：读取 `ArgsPointerMaps` stackmap，每个 bit 对应一个参数寄存器槽位，1=指针，0=标量。再用 `lenLike`（在 CMP/算术指令中出现的寄存器）区分 string（ptr+scalar）和 slice（ptr+scalar+scalar）。

**路径 B（启发式）**：扫描函数前段指令，检测：
- `ptrLike`：被用作内存地址（出现在 `Mem.Base`）的寄存器 → 指针参数
- `lenLike`：出现在 `CMP/TEST/ADD/SUB` 操作数中的寄存器 → 长度/整数参数

分组规则（Go ABI 寄存器顺序：rax, rbx, rcx, rdx, rsi, rdi, r8, r9）：
- `(ptr, scalar)` 相邻 → `string`（2个寄存器槽）
- `(ptr, scalar, scalar)` 相邻 → `[]byte` slice（3个寄存器槽）
- 单 `scalar` → `int`
- 单 `ptr` → `*T`

---

### 4.5 `pkg/typeinfo/parser.go` — 类型恢复

从 `.typelink` 恢复类型。关键布局（Go 1.20+ amd64）：

```
abi.Type（48 字节）：
  [0]  Size_       uintptr (8)
  [8]  PtrBytes    uintptr (8)
  [16] Hash        uint32  (4)
  [20] Tflag       uint8   (1)  ← bit1=ExtraStar, bit2=Named
  [21] Align_      uint8   (1)
  [22] FieldAlign_ uint8   (1)
  [23] Kind_       uint8   (1)  ← low 5 bits = Kind
  [24] Equal       ptr     (8)
  [32] GCData      ptr     (8)
  [40] Str         int32   (4)  ← nameOff，相对 .rodata 起始的偏移
  [44] PtrToThis   int32   (4)

StructType（紧接 abi.Type 之后）：
  [48] PkgPath Name  (8 = ptr to name bytes)
  [56] Fields  []StructField (ptr=8, len=8, cap=8)

StructField（24 字节）：
  [0]  Name_ Name ptr (8)
  [8]  Typ   *Type   (8)
  [16] Offset uintptr(8)
```

**名称编码格式**（`readName` 函数）：
```
byte[0]: flags（bit0=exported, bit1=hasTag, bit2=hasPkg）
varint:  name length
bytes:   name string
[varint: tag length]
[bytes:  tag]
[4 bytes: pkgPath nameOff（若 hasPkg）]
```

---

### 4.6 `pkg/codegen/gen.go` — 代码生成

代码生成分 6 个阶段（`renderFunc` 函数）：

```
1. buildFieldTable(types)          → offset→fieldName 映射表
2. renderStmts(stmts)              → IR 翻译为 Go 语法字符串
3. substituteReceiverFields(body)  → [rax+0x28] → r.Category
4. buildVarRenames(body, stmts)    → 寄存器名 → 有意义变量名
5. applyVarRenames(body, renames)  → 批量替换
6. 收集 var 声明 + import
```

**变量重命名五条规则**（按优先级）：

| 优先级 | 规则 | 示例 |
|--------|------|------|
| 0 | 强制（函数参数） | `rax` → `arg0` |
| 1 | for 循环计数器（首次写入 < 比较） | `rax` → `i`, `rbx` → `j` |
| 2 | 参数候选（通用命名） | `rdx` → `arg1` |
| 3 | `_pr<reg><hex>` → `<reg>_<hex>` | `_prax18` → `ax_18` |
| 4 | `_g<hex>` → `g0`, `g1`... | `_gdb61` → `g0` |
| 5 | 裸寄存器 → `v0`, `v1`... | `rax` → `v0` |

**stdlib 调用修正**（`stdlibCallFix` 映射表）：

修正 Go 编译器常见的内部调用形式，例如：
- `fmt.Fprintln(os.Stdout, s)` → `fmt.Println(s)`
- `fmt.Fprintf(os.Stderr, s)` → `fmt.Fprintf(os.Stderr, s)`（保留，因为是标准用法）
- `strings.Repeat(s, n)` → 检测整数候选 n
- `strings.genSplit(s, sep, n)` → `strings.SplitN(s, sep, n)` 或 `strings.Split(s, sep)`

---

## 5. 已知问题与改进方向

以下问题按实现难度和改进效益综合排序，**从易到难**：

---

### 🟢 难度：低（1-2天）

#### 5.1 扩展 `stdlibCallFix` 映射表

**问题**：许多标准库内部函数名未被映射，输出中出现原始函数名。

**文件**：`pkg/codegen/gen.go`，查找 `stdlibCallFix` 变量（约第 650 行）

**实现**：
```go
// 在 stdlibCallFix 中添加更多条目，例如：
"fmt.Sprint": func(a []string) string {
    return "fmt.Sprint(" + strings.Join(a, ", ") + ")"
},
"os.WriteString": func(a []string) string {
    if len(a) >= 2 { return a[0] + ".WriteString(" + a[1] + ")" }
    return `os.Stdout.WriteString("")`
},
"runtime.slicebytetostring": func(a []string) string {
    return "string(" + first(a, "nil") + ")"
},
"runtime.stringtoslicebyte": func(a []string) string {
    return "[]byte(" + first(a, `""`) + ")"
},
```

**测试**：编译一个使用 `os.WriteString`、`string(b)` 的程序，确认输出正确。

---

#### 5.2 完善格式化字符串参数占位符

**问题**：`fmt.Sprintf("Hi! I'm %s, I'm %d years old.")` 缺少参数，不是合法 Go 代码。

**文件**：`pkg/codegen/gen.go`，`formatCallExpr` 函数（约第 703 行）

**实现**：
```go
// 在 formatCallExpr 中，当调用 fmt.Sprintf/Printf/Errorf 时，
// 统计格式字符串中的 %verb 数量（排除 %%），
// 若实际参数数少于预期，追加注释型占位符。

func countFormatVerbs(s string) int {
    n := 0
    for i := 0; i < len(s)-1; i++ {
        if s[i] == '%' {
            if s[i+1] == '%' { i++ } else { n++ }
        }
    }
    return n
}

// 在 fmt.Sprintf 调用时：
// 格式串在 args[0]，去掉两端引号后 countFormatVerbs
// 若 len(args)-1 < verbs，追加 "/* arg_N */" 样式注释
```

---

#### 5.3 改进 `isSkippableRuntime` 覆盖范围

**问题**：部分 runtime 辅助函数未被过滤，出现在输出中影响可读性；另一些有语义价值的调用被误过滤。

**文件**：`pkg/analysis/analyzer.go`，`isSkippableRuntime` 函数（约第 346 行）

**实现**：
```go
// 补充跳过列表：
"runtime.deferreturn",     // defer 返回，用户不感知
"runtime.gopanic",         // 已通过 classifyCall 处理，可跳过重复
"runtime.efaceeq",         // interface 相等比较
"runtime.ifaceeq",
"runtime.cmpstring",       // 字符串比较内部实现
"runtime.intstring",       // int → string 转换
"runtime.concatstring2",   // 字符串拼接（2个）
"runtime.concatstring3",   // 字符串拼接（3个）
// ...
```

---

#### 5.4 为 stub 类型添加语义注释

**问题**：`Team` 的字段名为 `F0`, `F16`，用户无法知道这些是推断出的。

**文件**：`pkg/analysis/fields.go`，`offsetsToFields` 函数；`pkg/typeinfo/parser.go`，`structDecl` 函数

**实现**：在 hidden 字段旁添加行内注释，表示原始偏移：
```go
// 在 structDecl 中，为分组字段添加注释：
fmt.Fprintf(&b, "\t%s %s // +0x%x\n", f.Name, f.TypeName, f.Offset)
```

---

### 🟡 难度：中（3-7天）

#### 5.5 receiver 寄存器跨 CALL 边界追踪

**问题**：`analyzeReceiverAccesses` 在遇到 `CALL` 后删除 `RAX`，导致 `(*Team).Stats` 调用 `AverageAge()` 后无法追踪 receiver，丢失字段访问信息。

**根本原因**：Go 编译器通常将 receiver 保存到栈（`MOVQ AX, disp(SP)`），CALL 后从栈恢复（`MOVQ disp(SP), AX`）。当前代码只追踪寄存器别名，不追踪栈槽。

**文件**：`pkg/analysis/fields.go`，`analyzeReceiverAccesses` 函数

**实现**：
```go
func analyzeReceiverAccesses(insts []*disasm.Inst) []int64 {
    receiverRegs := map[x86asm.Reg]bool{x86asm.RAX: true}
    // 新增：记录 receiver 被保存到的栈槽（SP 相对偏移）
    savedSlots := make(map[int64]bool)
    seenOffsets := make(map[int64]bool)

    for _, inst := range insts {
        args := inst.Op.Args

        if inst.IsCall() {
            delete(receiverRegs, x86asm.RAX)
            // 不清除 savedSlots，栈槽在 CALL 后仍有效
            continue
        }

        if inst.Op.Op == x86asm.MOV && len(args) >= 2 {
            dst, src := args[0], args[1]
            switch {
            case isDstReg(dst) && isSrcReg(src):
                // 寄存器→寄存器别名（已有逻辑）
                handleRegAlias(dst, src, receiverRegs)

            case isDstStackMem(dst) && isSrcReceiverReg(src, receiverRegs):
                // MOVQ receiver, disp(SP) → 保存到栈
                savedSlots[stackDisp(dst)] = true

            case isDstReg(dst) && isSrcStackMem(src):
                // MOVQ disp(SP), reg → 从栈恢复
                if savedSlots[stackDisp(src)] && is64BitReg(dst.(x86asm.Reg)) {
                    receiverRegs[dst.(x86asm.Reg)] = true
                }
            }
        }

        // 检测 [receiver+offset] 访问（已有逻辑）
        for _, arg := range args { ... }
    }
}
```

**预期效果**：`Team` 的字段偏移将包含来自 `Add()` 方法的 offset=32（Members.cap），使三元组分组成功，`F16` 能正确识别为 `[]byte` slice 类型。

---

#### 5.6 `switch` 语句识别

**问题**：Go 的 `switch` 语句编译后变为一系列条件跳转，当前被拆成多个独立的 `if`，可读性差。

**根本原因**：`cfg.go` 的 `TermCond` 处理只认识 if/for，不识别 switch 模式。

**识别条件**：
```
模式1（线性搜索，少量 case）：
  CMP rax, $val1; JE case1
  CMP rax, $val2; JE case2
  CMP rax, $val3; JE case3
  ; fallthrough: default

模式2（跳转表，大量 case）：
  CMP rax, $max; JA default
  MOVQ [rip+rax*8+table_base], rcx
  JMP rcx   ← TermIndirect
```

**文件**：`pkg/analysis/cfg.go`，`liftFrom` 的 `TermCond` 分支

**实现思路**：
```go
// 在 TermCond 处理前，检测 switch 模式：
// 1. 扫描后续基本块，若多个块都从同一个寄存器 CMP 同一个常量派生
// 2. 或检测 TermIndirect 后接跳转表
// 新增 StmtSwitch 类型到 ir.go
type SwitchStmt struct {
    Var   string
    Cases []CaseClause  // {Value string, Body []*Stmt}
    Default []*Stmt
}
```

---

#### 5.7 格式化字符串参数类型恢复

**问题**：`fmt.Sprintf("Hi! I'm %s, I'm %d years old.")` 的两个参数（`p.Name`, `p.Age`）完全丢失。

**根本原因**：Go 的变参函数（`...interface{}`）参数通过栈上的接口切片传递，不经过 ABI 寄存器，当前无法追踪。

**可行的近似方案**：
```
1. 识别 fmt.Sprintf 等格式化调用
2. 解析格式字符串中的 %verb：
   %s → 字符串类型参数
   %d → 整数类型参数
   %v → 任意类型参数
3. 在调用前扫描寄存器，用 buildRegMap 的追踪信息生成占位符变量
4. 不能确定时，生成注释：/* arg: string */
```

**文件**：`pkg/codegen/gen.go`，`formatCallExpr` 和 `stdlibCallFix`

---

#### 5.8 跨函数调用链参数传播

**问题**：`NewPerson` 的返回值被调用方使用，但被识别为 `{}`（无返回类型）。

**根本原因**：返回类型推断（`inferReturnType`）仅靠 IR 中的 `StmtReturn` 语句，不分析调用方如何使用返回值。

**实现**：
```go
// 在 codegen 生成阶段，收集调用图（callgraph）：
// 若 f() 的结果被 `if err != nil` 检测 → f 返回 error
// 若 f() 的结果被解构赋值 → f 可能返回多值

// 也可以反向推断：
// NewPerson 调用 fmt.Errorf + 返回非 nil → 推断返回 (*T, error)
```

---

#### 5.9 改进接收者字段的 Pass 2 精确性

**问题**：`substituteReceiverFields` 的 Pass 2（投机性替换其他寄存器的字段访问）可能错误匹配不相关的内存访问。

**文件**：`pkg/codegen/gen.go`，第 1147-1188 行

**改进**：Pass 2 只在寄存器确认为接收者别名时才替换（结合 `cfg.go` 的 `buildRegMap` 信息）。需要将 `buildRegMap` 的结果从 CFG 分析阶段传递到代码生成阶段。

---

### 🔴 难度：高（1-2周+）

#### 5.10 ARM64 支持

**问题**：GoSpy 仅支持 x86-64，无法处理 ARM64（Apple Silicon、移动设备）的 Go 二进制。

**所需改动**：
1. `pkg/loader/elf.go`：已使用 `debug/elf`，支持多架构读取节区
2. `pkg/disasm/`：新增 `disasm_arm64.go`，使用 `golang.org/x/arch/arm64/arm64asm`
3. `pkg/analysis/cfg.go`：`Build` 函数的跳转指令判断需改为接口，按架构分派
4. `pkg/analysis/analyzer.go`：字符串检测（`LEA`）和 ABI 寄存器顺序需重写
5. `pkg/analysis/params.go`：ABI 参数寄存器（ARM64 为 `r0`-`r7`）需更换
6. `pkg/analysis/fields.go`：receiver 寄存器（ARM64 方法中 receiver 在 `r0`）需更换

**关键差异**：
- ARM64 使用 `ADRP + ADD` 两条指令加载 rodata 地址（非单一 `LEA [rip+N]`）
- 参数寄存器：`x0-x7`（整数），`v0-v7`（浮点）
- Go ARM64 ABI 中 receiver 在 `x0`

---

#### 5.11 栈上参数/变量追踪

**问题**：当函数参数超过 8 个寄存器，或局部变量溢出到栈，当前代码完全忽略这些值。

**实现**：
```
1. 追踪 SP 相对地址访问：MOVQ [SP+N], AX → 记录栈变量
2. 与函数入口的栈帧布局结合（可从 pclntab 的 LocalsSize 获取）
3. 生成 _sp_N 形式的变量名，后续通过重命名系统优化
```

---

#### 5.12 类型推断：区分 `int` / `*T` / `float64` / `uint64`

**问题**：8 字节字段当前统一猜测为 `int`，实际可能是指针、浮点数等。

**实现思路**：
```
1. 若字段出现在 MOV 后紧接解引用（如 [rcx+0] ← rcx 来自该字段） → *T
2. 若字段出现在 MOVSD/ADDSD（SSE 浮点指令）→ float64
3. 若字段与 0x8000000000000000 做 AND/OR → uint64
4. 否则 → int
```

---

#### 5.13 方法体内全局变量识别

**问题**：`os.Args`、`os.Stdout` 等全局变量当前显示为 `_g<hex>` 形式，无法关联到实际变量名。

**根本原因**：这些变量存储在 `.data`/`.bss` 节，通过 `LEAQ [rip+N]` 或 `MOVQ [rip+N], AX` 访问。

**实现**：
```
1. 构建全局变量地址表：从 .gopclntab 的变量符号（若存在）或反向分析初始化函数
2. 在 buildRegMap 中，若 [rip+N] 的地址命中已知全局变量，记录变量名
3. 在代码生成时替换 _g<hex> → 实际变量名
```

---

## 6. 测试方法

### 6.1 编译测试目标

```bash
# example/2 是主要测试目标（包含 struct/方法/条件/循环）
cd example/2 && go build -ldflags="-s -w" -o main . && cd ../..

# 可以添加更多复杂场景：
# example/3: goroutine + channel
# example/4: interface + map
# example/5: 递归 + 闭包
```

### 6.2 回归测试

```bash
# 构建并运行
go build -o gospy ./cmd/gospy
./gospy -pkg main -o /tmp/test_out example/2/main 2>/dev/null

# 检查关键输出
cat /tmp/test_out/main/main.go

# 验证输出是合法 Go（尝试编译）
cp /tmp/test_out/main/main.go /tmp/test_compile.go
# 手动修正明显占位符后：
# go build /tmp/test_compile.go
```

### 6.3 静态检查（必须通过）

```bash
staticcheck ./...   # 必须无输出
go vet ./...        # 必须无输出
```

### 6.4 针对具体功能的快速测试

```bash
# 测试字符串检测
cat > /tmp/t.go << 'EOF'
package main
import "fmt"
func main() {
    fmt.Println("hello world")
    fmt.Printf("count: %d\n", 42)
    s := fmt.Sprintf("name=%s", "alice")
    _ = s
}
EOF
go build -ldflags="-s -w" -o /tmp/t /tmp/t.go
./gospy -pkg main -o /tmp/t_out /tmp/t
cat /tmp/t_out/main/main.go

# 测试 struct 字段推断
# 使用 example/2（包含 Team 的字段访问模式）
```

---

## 7. 代码规范

### 7.1 Go 现代化写法

项目使用 Go 1.25+，优先使用新特性：

```go
// ✅ 推荐
for i := range n { ... }           // 范围整数
slices.Sort(s)                      // 代替 sort.Slice
slices.Contains(ss, s)              // 代替循环查找
before, after, ok := strings.Cut(s, sep)  // 代替 strings.Index
s, ok := strings.CutPrefix(s, pfx) // 代替 strings.HasPrefix + [len:]
fmt.Fprintf(&b, "...", args...)     // 代替 b.WriteString(fmt.Sprintf(...))
end := min(a, b)                    // 内置 min/max

// ❌ 避免
sort.Slice(s, func(i, j int) bool { ... })
strings.Index(s, sep)
strings.HasPrefix(s, pfx); s = s[len(pfx):]
b.WriteString(fmt.Sprintf("..."))
```

### 7.2 错误处理

```go
// 解析类函数：无法解析时返回 nil/空，不返回 error（调用方过滤即可）
func (p *Parser) parseType(va uint64) (*TypeDecl, error) {
    if !p.inRodata(va) {
        return nil, nil  // 正常情况，不是错误
    }
    ...
}

// 外部 I/O：返回 error
func Generate(...) error { ... }
```

### 7.3 性能考虑

- 反汇编和 CFG 构建是热路径，避免大量内存分配
- `buildRegMap` 每个条件块都调用，保持 O(n) 复杂度
- `substituteReceiverFields` 使用字符串替换，在长函数体上可能很慢——若成为瓶颈，考虑使用 `strings.NewReplacer`

### 7.4 添加新的 stdlib 调用修正

在 `pkg/codegen/gen.go` 的 `stdlibCallFix` 中添加：

```go
"pkg.InternalFuncName": func(args []string) string {
    // args 是检测到的字符串/整数参数列表
    // 返回最终的 Go 代码字符串
    s := first(args, `""`)
    return "pkg.PublicFunc(" + s + ")"
},
```

注意：`args` 中的字符串参数已经是带引号的字符串字面量（如 `"\"hello\""`），整数参数是数字字符串（如 `"42"`）。

### 7.5 调试技巧

```go
// 在 extractBlock 中临时打印每条指令的处理结果：
for idx, inst := range blk.Insts {
    fmt.Fprintf(os.Stderr, "  [%d] 0x%x: %s\n", idx, inst.Addr, inst.Text())
}

// 在 liftFrom 中打印每个基本块的提升结果：
fmt.Fprintf(os.Stderr, "Block %d (%s): %d stmts\n", b.ID, b.Term, len(stmts))
```

---

## 附录：关键数据结构速查

### IR 语句渲染映射

| StmtKind | 渲染结果 |
|---------|---------|
| `StmtCall` | `funcName(args...)` |
| `StmtReturn` | `return [value]` |
| `StmtGo` | `go funcName(args...)` |
| `StmtDefer` | `defer funcName(args...)` |
| `StmtPanic` | `panic(args...)` |
| `StmtIf` | `if cond { ... } [else { ... }]` |
| `StmtFor` | `for cond { ... }` |
| `StmtIncr` | `i++` / `i--` / `i += N` / `i -= N` |
| `StmtAsm` | `// comment` |

### 控制流术语

| 术语 | 含义 |
|------|------|
| `fallBlk` | 条件不成立时顺序执行的块（`b.Succs[0]`） |
| `jmpBlk` | 条件成立时跳转的块（`b.Succs[1]`） |
| `merge` 点 | 两条路径汇合的块（最近公共后继） |
| 早期出口 | 某路径快速终止（含 `RET`/`panic`），主流继续 |
| 回边 | 跳转到地址更低的块（循环标志） |

### Go ABI 寄存器顺序（amd64）

```
整数参数：RAX, RBX, RCX, RDX, RSI, RDI, R8, R9
浮点参数：X0, X1, X2, X3, X4, X5, X6, X7
返回值：  RAX（整数），X0（浮点）

string 参数：(ptr=RAXᵢ, len=RBXᵢ)  占 2 个寄存器槽
slice  参数：(ptr=RAXᵢ, len=RBXᵢ, cap=RCXᵢ)  占 3 个寄存器槽
调用者保存（CALL 后无效）：RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11
被调用者保存（跨 CALL 有效）：RBX, R12, R13, R14, R15
```

---

*最后更新：2026-03-08*
