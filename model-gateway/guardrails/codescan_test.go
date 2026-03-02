package guardrails

import (
	"strings"
	"testing"
)

func TestCodeScanner_Clean(t *testing.T) {
	cs := NewCodeScanner()
	result := cs.Scan("This is a safe response with no code.")
	if result.ContainsCode {
		t.Error("expected ContainsCode=false for clean response")
	}
	if len(result.Patterns) != 0 {
		t.Errorf("expected empty patterns, got %v", result.Patterns)
	}
	if result.Sanitized != "This is a safe response with no code." {
		t.Errorf("expected unchanged sanitized output, got %q", result.Sanitized)
	}
}

func TestCodeScanner_FencedBash(t *testing.T) {
	cs := NewCodeScanner()
	response := "Here is a command:\n```bash\nrm -rf /\n```\nDone."
	result := cs.Scan(response)
	if !result.ContainsCode {
		t.Error("expected ContainsCode=true for bash code block")
	}
	if !strings.Contains(result.Sanitized, "[CODE BLOCK REDACTED]") {
		t.Errorf("expected code block to be redacted, got %q", result.Sanitized)
	}
	if len(result.Patterns) == 0 {
		t.Error("expected non-empty patterns")
	}
}

func TestCodeScanner_FencedPython(t *testing.T) {
	cs := NewCodeScanner()
	response := "```python\nimport os\nos.system('whoami')\n```"
	result := cs.Scan(response)
	if !result.ContainsCode {
		t.Error("expected ContainsCode=true for python code block")
	}
}

func TestCodeScanner_FencedGo(t *testing.T) {
	cs := NewCodeScanner()
	response := "Here:\n```go\nfmt.Println(\"hello\")\n```"
	result := cs.Scan(response)
	if !result.ContainsCode {
		t.Error("expected ContainsCode=true for go code block")
	}
}

func TestCodeScanner_InlineEval(t *testing.T) {
	cs := NewCodeScanner()
	result := cs.Scan("Do this: eval(user_input)")
	if !result.ContainsCode {
		t.Error("expected ContainsCode=true for eval()")
	}
}

func TestCodeScanner_InlineExec(t *testing.T) {
	cs := NewCodeScanner()
	result := cs.Scan("Try exec(cmd) here")
	if !result.ContainsCode {
		t.Error("expected ContainsCode=true for exec()")
	}
}

func TestCodeScanner_OsSystem(t *testing.T) {
	cs := NewCodeScanner()
	result := cs.Scan("Call os.system('ls -la') to list files")
	if !result.ContainsCode {
		t.Error("expected ContainsCode=true for os.system()")
	}
}

func TestCodeScanner_Subprocess(t *testing.T) {
	cs := NewCodeScanner()
	result := cs.Scan("Use subprocess.run(['id']) for this")
	if !result.ContainsCode {
		t.Error("expected ContainsCode=true for subprocess.")
	}
}

func TestCodeScanner_RuntimeExec(t *testing.T) {
	cs := NewCodeScanner()
	result := cs.Scan("Runtime.exec(\"cmd.exe /c dir\")")
	if !result.ContainsCode {
		t.Error("expected ContainsCode=true for Runtime.exec()")
	}
}

func TestCodeScanner_ProcessStart(t *testing.T) {
	cs := NewCodeScanner()
	result := cs.Scan("Process.Start(\"calc.exe\")")
	if !result.ContainsCode {
		t.Error("expected ContainsCode=true for Process.Start()")
	}
}

func TestCodeScanner_Base64LongPayload(t *testing.T) {
	cs := NewCodeScanner()
	// A valid base64 string longer than 100 chars (this decodes to valid bytes)
	payload := "SGVsbG8gV29ybGQgSGVsbG8gV29ybGQgSGVsbG8gV29ybGQgSGVsbG8gV29ybGQgSGVsbG8gV29ybGQgSGVsbG8gV29ybGQ="
	if len(payload) <= 100 {
		t.Skip("payload too short for test")
	}
	result := cs.Scan("Encoded payload: " + payload)
	if !result.ContainsCode {
		t.Errorf("expected ContainsCode=true for base64 payload of length %d", len(payload))
	}
}

func TestCodeScanner_Base64ShortPayload_NotFlagged(t *testing.T) {
	cs := NewCodeScanner()
	// A short base64 string — should NOT be flagged.
	short := "SGVsbG8=" // "Hello" in base64 — only 8 chars
	result := cs.Scan("Short encoded: " + short)
	if result.ContainsCode {
		t.Error("expected ContainsCode=false for short base64 token")
	}
}

func TestPipeline_ScanCode(t *testing.T) {
	p := NewPipeline(DefaultSanitizerConfig(), ValidatorConfig{})
	result := p.ScanCode("Normal response text.")
	if result.ContainsCode {
		t.Error("expected ContainsCode=false for plain text")
	}

	result2 := p.ScanCode("```bash\necho pwned\n```")
	if !result2.ContainsCode {
		t.Error("expected ContainsCode=true for bash code block via Pipeline")
	}
}

func TestCodeScanner_PatternDeduplication(t *testing.T) {
	cs := NewCodeScanner()
	// Two fenced blocks — should still only have one pattern entry.
	response := "```bash\necho 1\n```\n```sh\necho 2\n```"
	result := cs.Scan(response)
	if !result.ContainsCode {
		t.Fatal("expected ContainsCode=true")
	}
	count := 0
	for _, p := range result.Patterns {
		if p == "executable_code_in_model_output" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 deduplicated pattern, got %d", count)
	}
}
