// Package analysis 定义反编译中间表示（IR）。
package analysis

import (
	"fmt"
	"strings"
)

// ── 表达式 ──────────────────────────────────────────────────────────────────

// Expr 是表达式接口。
type Expr interface {
	GoString() string
}

// StringLit 字符串字面量。
type StringLit struct{ Value string }

func (s *StringLit) GoString() string { return fmt.Sprintf("%q", s.Value) }

// IntLit 整数字面量。
type IntLit struct{ Value int64 }

func (i *IntLit) GoString() string { return fmt.Sprintf("%d", i.Value) }

// Ident 标识符。
type Ident struct{ Name string }

func (i *Ident) GoString() string { return i.Name }

// RawExpr 原始 Go 表达式片段（用于无法归类为字面量/标识符的场景）。
type RawExpr struct{ Code string }

func (r *RawExpr) GoString() string { return r.Code }

// CallExpr 函数调用。
type CallExpr struct {
	Func string
	Args []Expr
}

func (c *CallExpr) GoString() string {
	args := make([]string, len(c.Args))
	for i, a := range c.Args {
		args[i] = a.GoString()
	}
	name := FormatCallName(c.Func)
	return fmt.Sprintf("%s(%s)", name, strings.Join(args, ", "))
}

// FormatCallName 将函数全名转换为可读的调用形式（已导出，供 codegen 使用）。
// 规则：
//   - "pkg/path/sub.Func" → "/*pkg/path*/ sub.Func"
//   - "pkg.(*Type).Method" → "(*Type).Method"  (直接方法调用，去掉单段包名)
//   - "pkg.Func" → "pkg.Func"  (保留包名)
func FormatCallName(name string) string {
	if strings.Contains(name, "/") {
		// 第三方/多段包路径：以注释形式显示路径前缀
		idx := strings.LastIndex(name, "/")
		return fmt.Sprintf("/*%s*/ %s", name[:idx], name[idx+1:])
	}
	// 单段包名的方法调用："main.(*Person).Greet" → "(*Person).Greet"
	// 形如 "pkg.(..." 的去掉包名前缀
	if idx := strings.Index(name, ".("); idx >= 0 {
		return name[idx+1:] // 保留 "(*Type).Method" 部分
	}
	return name
}

// ── 语句 ────────────────────────────────────────────────────────────────────

// StmtKind 语句类型。
type StmtKind int

const (
	StmtCall   StmtKind = iota // 函数调用
	StmtReturn                 // return
	StmtGo                     // goroutine
	StmtDefer                  // defer
	StmtPanic                  // panic
	StmtIf                     // if/else
	StmtFor                    // for 循环
	StmtAsm                    // 无法识别（注释）
	StmtIncr                   // 变量自增/自减/加法 (i++, i--, i+=N)
)

// IfStmt 表示 if/else 语句。
type IfStmt struct {
	Cond string  // 条件描述
	Then []*Stmt // then 分支
	Else []*Stmt // else 分支（nil=无 else）
	PC   uint64
}

// ForStmt 表示 for 循环。
type ForStmt struct {
	Cond string  // 循环条件（空=无限循环）
	Body []*Stmt // 循环体
	PC   uint64
}

// IncrStmt 表示变量增量赋值（如 i++, i--, i+=8）。
type IncrStmt struct {
	Var   string // 变量名（寄存器名，如 "rax"）
	Delta int64  // 增量（+1=自增, -1=自减, 其他=显式加减）
}

// Stmt 表示一条语句（可嵌套）。
type Stmt struct {
	Kind    StmtKind
	Call    *CallExpr // StmtCall/StmtGo/StmtDefer/StmtPanic
	Comment string    // StmtAsm
	If      *IfStmt   // StmtIf
	For     *ForStmt  // StmtFor
	Incr    *IncrStmt // StmtIncr
	PC      uint64
}

// GoString 生成该语句对应的 Go 代码（不含缩进）。
func (s *Stmt) GoString() string {
	switch s.Kind {
	case StmtReturn:
		if s.Call != nil && len(s.Call.Args) > 0 {
			args := make([]string, len(s.Call.Args))
			for i, a := range s.Call.Args {
				args[i] = a.GoString()
			}
			return "return " + strings.Join(args, ", ")
		}
		return "return"
	case StmtCall:
		if s.Call != nil {
			return s.Call.GoString()
		}
	case StmtGo:
		if s.Call != nil {
			return "go " + s.Call.GoString()
		}
	case StmtDefer:
		if s.Call != nil {
			return "defer " + s.Call.GoString()
		}
	case StmtPanic:
		if s.Call != nil && len(s.Call.Args) > 0 {
			return fmt.Sprintf("panic(%s)", s.Call.Args[0].GoString())
		}
		return "panic(nil)"
	case StmtAsm:
		return "// " + s.Comment
	case StmtIncr:
		if s.Incr == nil {
			return ""
		}
		switch s.Incr.Delta {
		case 1:
			return s.Incr.Var + "++"
		case -1:
			return s.Incr.Var + "--"
		default:
			if s.Incr.Delta > 0 {
				return fmt.Sprintf("%s += %d", s.Incr.Var, s.Incr.Delta)
			}
			return fmt.Sprintf("%s -= %d", s.Incr.Var, -s.Incr.Delta)
		}
	}
	return ""
}

// ── 函数 IR ──────────────────────────────────────────────────────────────────

// FuncIR 保存一个函数的中间表示。
type FuncIR struct {
	Name    string      // 完整函数名
	Stmts   []*Stmt     // 语句列表（可嵌套 if/for）
	Calls   []string    // 调用的函数名列表
	Strings []string    // 字符串字面量
	Params  []ParamInfo // 推断的显式参数列表（不含接收者）
}
