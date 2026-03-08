package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ErrInvalidAge 是无效年龄错误
var ErrInvalidAge = errors.New("age must be between 0 and 150")

// Category 人员类别
type Category int

const (
	CategoryMinor  Category = iota // 未成年
	CategoryAdult                  // 成年
	CategorySenior                 // 老年
)

func (c Category) String() string {
	switch c {
	case CategoryMinor:
		return "minor"
	case CategoryAdult:
		return "adult"
	case CategorySenior:
		return "senior"
	default:
		return "unknown"
	}
}

// Person 表示一个人
type Person struct {
	Name     string
	Age      int
	Email    string
	Category Category
}

// NewPerson 创建 Person，验证年龄合法性
func NewPerson(name string, age int, email string) (*Person, error) {
	if age < 0 || age > 150 {
		return nil, fmt.Errorf("person %q: %w", name, ErrInvalidAge)
	}
	var cat Category
	if age < 18 {
		cat = CategoryMinor
	} else if age < 65 {
		cat = CategoryAdult
	} else {
		cat = CategorySenior
	}
	return &Person{
		Name:     name,
		Age:      age,
		Email:    email,
		Category: cat,
	}, nil
}

// Greet 返回问候语
func (p *Person) Greet() string {
	switch p.Category {
	case CategoryMinor:
		return fmt.Sprintf("Hi! I'm %s, I'm %d years old.", p.Name, p.Age)
	case CategoryAdult:
		return fmt.Sprintf("Hello, I'm %s (%d).", p.Name, p.Age)
	default:
		return fmt.Sprintf("Good day, I'm %s, %d years of wisdom.", p.Name, p.Age)
	}
}

// String 实现 Stringer 接口
func (p *Person) String() string {
	return fmt.Sprintf("Person{Name:%q Age:%d Email:%q Category:%s}",
		p.Name, p.Age, p.Email, p.Category)
}

// Team 表示一组人
type Team struct {
	Name    string
	Members []*Person
}

// Add 添加成员
func (t *Team) Add(p *Person) {
	t.Members = append(t.Members, p)
}

// AverageAge 计算平均年龄
func (t *Team) AverageAge() float64 {
	if len(t.Members) == 0 {
		return 0
	}
	sum := 0
	for _, m := range t.Members {
		sum += m.Age
	}
	return float64(sum) / float64(len(t.Members))
}

// Stats 打印统计信息
func (t *Team) Stats() {
	fmt.Printf("Team %q: %d members, avg age %.1f\n",
		t.Name, len(t.Members), t.AverageAge())
	for i, m := range t.Members {
		fmt.Printf("  [%d] %s\n", i, m)
	}
}

// parseArgs 解析命令行参数（格式: name:age:email ...）
func parseArgs(args []string) ([]*Person, error) {
	if len(args) == 0 {
		return nil, errors.New("no arguments provided")
	}
	var people []*Person
	for _, arg := range args {
		parts := strings.SplitN(arg, ":", 3)
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid format %q: expected name:age[:email]", arg)
		}
		age, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid age in %q: %w", arg, err)
		}
		email := ""
		if len(parts) >= 3 {
			email = parts[2]
		}
		p, err := NewPerson(parts[0], age, email)
		if err != nil {
			return nil, err
		}
		people = append(people, p)
	}
	return people, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: program name:age[:email] ...")
		fmt.Fprintln(os.Stderr, "Example: program Alice:30:alice@example.com Bob:17")
		os.Exit(1)
	}

	people, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	team := &Team{Name: "GoSpy Test Team"}
	for _, p := range people {
		team.Add(p)
		fmt.Println(p.Greet())
	}

	fmt.Println(strings.Repeat("-", 40))
	team.Stats()
}
