// codescan.go — Stage 5 of the OpenGuard model gateway pipeline.
// It inspects model response text for executable code patterns and redacts them.
package guardrails

import (
	"encoding/base64"
	"regexp"
)

// minBase64PayloadLen is the minimum length (in characters) of a base64 string
// that triggers a potential encoded-shellcode detection. Strings shorter than
// this are common in legitimate content (e.g. short tokens, IDs).
const minBase64PayloadLen = 101

// codeFencePattern matches fenced code blocks for dangerous language tags.
var codeFencePattern = regexp.MustCompile(
	"(?i)```\\s*(bash|sh|python|ruby|perl|powershell|cmd|javascript|js|go|c|cpp|rust|php)[\\s\\S]*?```",
)

// inlineExecPatterns lists regex patterns that identify inline execution calls.
var inlineExecPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\beval\s*\(`),
	regexp.MustCompile(`\bexec\s*\(`),
	regexp.MustCompile(`\bos\.system\s*\(`),
	regexp.MustCompile(`\bsubprocess\.`),
	regexp.MustCompile(`\bRuntime\.exec\s*\(`),
	regexp.MustCompile(`\bProcess\.Start\s*\(`),
}

// base64PayloadPattern matches base64-encoded strings of at least minBase64PayloadLen characters
// (potential encoded shellcode payloads).
var base64PayloadPattern = regexp.MustCompile(`[A-Za-z0-9+/]{101,}={0,2}`)

// CodeScanResult is the result of scanning a model response for executable code.
type CodeScanResult struct {
	// ContainsCode is true if any executable code pattern was detected.
	ContainsCode bool
	// Patterns is the list of indicator names that matched.
	Patterns []string
	// Sanitized is the response with code blocks replaced by [CODE BLOCK REDACTED].
	Sanitized string
}

// CodeScanner inspects model response strings for executable code patterns.
type CodeScanner struct{}

// NewCodeScanner constructs a CodeScanner.
func NewCodeScanner() *CodeScanner { return &CodeScanner{} }

// Scan inspects response for executable code patterns.
// If any pattern matches it returns a CodeScanResult with ContainsCode=true,
// the matched Patterns, and a Sanitized version of the response.
func (cs *CodeScanner) Scan(response string) CodeScanResult {
	result := CodeScanResult{Sanitized: response}
	seen := map[string]bool{}

	addPattern := func(p string) {
		if !seen[p] {
			seen[p] = true
			result.Patterns = append(result.Patterns, p)
		}
	}

	// Check fenced code blocks.
	if codeFencePattern.MatchString(response) {
		addPattern("executable_code_in_model_output")
		result.Sanitized = codeFencePattern.ReplaceAllString(result.Sanitized, "[CODE BLOCK REDACTED]")
	}

	// Check inline execution patterns.
	for _, re := range inlineExecPatterns {
		if re.MatchString(response) {
			addPattern("executable_code_in_model_output")
		}
	}

	// Check for base64-encoded payloads (potential encoded shellcode).
	if matches := base64PayloadPattern.FindAllString(response, -1); len(matches) > 0 {
		for _, m := range matches {
			// Only flag if it decodes to printable/binary content (i.e. is valid base64).
			if _, err := base64.StdEncoding.DecodeString(padBase64(m)); err == nil {
				addPattern("executable_code_in_model_output")
				break
			}
		}
	}

	result.ContainsCode = len(result.Patterns) > 0
	if result.Patterns == nil {
		result.Patterns = []string{}
	}
	return result
}

// padBase64 pads a base64 string to a multiple-of-4 length.
func padBase64(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		return s
	}
}

// ScanCode runs the CodeScanner on the model response and returns the result.
// This method is added to Pipeline to complete Stage 5 of the pipeline.
func (p *Pipeline) ScanCode(response string) CodeScanResult {
	return p.codeScanner.Scan(response)
}
