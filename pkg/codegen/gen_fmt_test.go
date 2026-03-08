package codegen

import (
	"strings"
	"testing"

	"github.com/Yeah114/GoSpy/pkg/analysis"
)

func TestRefineFmtCallArgsFallbackParam(t *testing.T) {
	args := []string{`"person %q: %w"`, "sp_30", "g0"}
	params := []analysis.ParamInfo{
		{Name: "arg0", Kind: analysis.ParamString},
		{Name: "arg1", Kind: analysis.ParamInt},
	}
	got := refineFmtCallArgs("fmt.Errorf", args, params)
	if got[1] != "arg0" {
		t.Fatalf("expected arg0 for %%q, got %s", got[1])
	}
}

func TestFormatCallExprMethodUsesRecoveredReceiver(t *testing.T) {
	got := formatCallExpr("main.(*Person).Greet", []string{"p"})
	if got != "p.Greet()" {
		t.Fatalf("unexpected method call: %s", got)
	}
}

func TestFormatCallExprMethodFallbackNoNil(t *testing.T) {
	got := formatCallExpr("main.(*Team).Stats", nil)
	if got != "new(Team).Stats()" {
		t.Fatalf("unexpected fallback receiver: %s", got)
	}
}

func TestFormatCallExprMethodRejectScalarTempReceiver(t *testing.T) {
	got := formatCallExpr("main.(*Team).Stats", []string{"v4"})
	if got != "new(Team).Stats()" {
		t.Fatalf("unexpected receiver rewrite: %s", got)
	}
}

func TestFormatCallExprMethodGlobalPlaceholderReceiver(t *testing.T) {
	got := formatCallExpr("flag.(*FlagSet).Parse", []string{"_g1234", "nil"})
	if got != "flag.Parse()" {
		t.Fatalf("unexpected global receiver rewrite: %s", got)
	}
}

func TestFormatCallExprGrpcNewServerNilOption(t *testing.T) {
	got := formatCallExpr("google.golang.org/grpc.NewServer", []string{"nil"})
	if got != "/*google.golang.org*/ grpc.NewServer()" {
		t.Fatalf("unexpected grpc newserver rewrite: %s", got)
	}
}

func TestFormatCallExprPathMethodFallbackReceiver(t *testing.T) {
	got := formatCallExpr("github.com/gorilla/websocket.(*Conn).ReadMessage", []string{"nil"})
	if got != "new(websocket.Conn).ReadMessage()" {
		t.Fatalf("unexpected path method rewrite: %s", got)
	}
}

func TestFormatCallExprRejectCallAsReceiver(t *testing.T) {
	got := formatCallExpr("main.(*WSManager).SendQQMessage", []string{"fmt.Sprint(nil)", "v2"})
	if got != "new(WSManager).SendQQMessage(v2)" {
		t.Fatalf("unexpected call receiver rewrite: %s", got)
	}
}

func TestFormatCallExprBareMethodRewrite(t *testing.T) {
	got := formatCallExpr("(*WSManager).SendQQMessage", []string{"fmt.Sprint(nil)", "v2"})
	if got != "new(WSManager).SendQQMessage(v2)" {
		t.Fatalf("unexpected bare method rewrite: %s", got)
	}
}

func TestImportPathFromFuncName(t *testing.T) {
	if got := importPathFromFuncName("google.golang.org/grpc.(*Server).Serve"); got != "google.golang.org/grpc" {
		t.Fatalf("unexpected method import path: %s", got)
	}
	if got := importPathFromFuncName("FateArk/network_api/listener.RegisterListenerServiceServer"); got != "FateArk/network_api/listener" {
		t.Fatalf("unexpected function import path: %s", got)
	}
}

func TestFormatCallExprParseIntFix(t *testing.T) {
	got := formatCallExpr("strconv.ParseInt", []string{"nil", "64"})
	if got != "_, _ = strconv.ParseInt(\"\", 10, 64)" {
		t.Fatalf("unexpected strconv.ParseInt rewrite: %s", got)
	}
}

func TestFormatCallExprFprintlnTrimTrailingNil(t *testing.T) {
	got := formatCallExpr("fmt.Fprintln", []string{"g0", "g1", "nil"})
	if got != "fmt.Println(g0, g1)" {
		t.Fatalf("unexpected fmt.Fprintln rewrite: %s", got)
	}
}

func TestFormatCallExprOpenFileNilPath(t *testing.T) {
	got := formatCallExpr("os.OpenFile", []string{"nil", "420"})
	if got != "os.OpenFile(\"\", 0, 420)" {
		t.Fatalf("unexpected os.OpenFile rewrite: %s", got)
	}
}

func TestFormatCallExprUnexportedExternalMethodCommented(t *testing.T) {
	got := formatCallExpr("net/http.(*Client).do", []string{"nil"})
	if got != "// /*net*/ http.(*Client).do(nil)" {
		t.Fatalf("unexpected unexported method handling: %s", got)
	}
}

func TestIsShortDeclaredInBody(t *testing.T) {
	body := "age, err := strconv.Atoi(parts[1])\nif err != nil {\n\treturn err\n}"
	if !isShortDeclaredInBody("err", body) {
		t.Fatalf("expected err to be detected as short-declared")
	}
	if isShortDeclaredInBody("sp_88", body) {
		t.Fatalf("unexpected detection for unrelated name")
	}
}

func TestFormatCallExprStillProducesOutput(t *testing.T) {
	got := formatCallExpr("fmt.Sprintf", []string{`"x=%d"`, "1"})
	if !strings.Contains(got, "fmt.Sprintf") {
		t.Fatalf("unexpected output: %s", got)
	}
}

func TestPickParamForVerbSliceFallback(t *testing.T) {
	params := []analysis.ParamInfo{{Name: "arg0", Kind: analysis.ParamSlice}}
	p, ok := pickParamForVerb('q', params, map[int]bool{})
	if !ok {
		t.Fatalf("expected slice fallback for %%q")
	}
	if p.Name != "arg0[0]" {
		t.Fatalf("unexpected picked param: %s", p.Name)
	}
}

func TestCoerceCallArgsByParamKindsKeepsIndexedString(t *testing.T) {
	args := []string{"parts[0]", "1", `""`}
	params := []analysis.ParamInfo{
		{Name: "name", Kind: analysis.ParamString},
		{Name: "age", Kind: analysis.ParamInt},
		{Name: "email", Kind: analysis.ParamString},
	}
	got := coerceCallArgsByParamKinds(args, params)
	if got[0] != "parts[0]" {
		t.Fatalf("indexed string arg should be kept, got %s", got[0])
	}
}

func TestIsPrintProxyArgsWithWriterAndPlaceholders(t *testing.T) {
	args := []string{"_g4ecc08", "_g57a4a8", "nil"}
	if !isPrintProxyArgs(args) {
		t.Fatalf("expected print proxy args to be recognized")
	}
}
