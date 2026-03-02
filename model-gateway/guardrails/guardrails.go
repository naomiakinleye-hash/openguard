// Package guardrails provides prompt sanitization and output validation
// for the OpenGuard model gateway pipeline.
//
// It composes a Sanitizer (Stage 1 of the 5-stage policy pipeline) and a
// Validator (Stage 4) into a single Pipeline that callers can use without
// managing the two components separately.
package guardrails

import (
	mg "github.com/DiniMuhd7/openguard/model-gateway/interfaces"
)

// Pipeline composes a Sanitizer, Validator, and CodeScanner for use in the model gateway.
type Pipeline struct {
	sanitizer   *Sanitizer
	validator   *Validator
	codeScanner *CodeScanner
}

// NewPipeline constructs a Pipeline with the given sanitizer and validator configs.
func NewPipeline(sanitizerCfg SanitizerConfig, validatorCfg ValidatorConfig) *Pipeline {
	return &Pipeline{
		sanitizer:   NewSanitizer(sanitizerCfg),
		validator:   NewValidator(validatorCfg),
		codeScanner: NewCodeScanner(),
	}
}

// SanitizePrompt delegates to the Sanitizer.
// It returns the sanitized prompt, a list of redaction reason codes, and
// ErrPromptInjection if the prompt was blocked.
func (p *Pipeline) SanitizePrompt(prompt string) (string, []string, error) {
	return p.sanitizer.Sanitize(prompt)
}

// ValidateAnalysis delegates to the Validator.
func (p *Pipeline) ValidateAnalysis(r *mg.AnalysisResult) error {
	return p.validator.ValidateAnalysis(r)
}

// ValidateClassification delegates to the Validator.
func (p *Pipeline) ValidateClassification(r *mg.ClassificationResult) error {
	return p.validator.ValidateClassification(r)
}

// ValidateActions delegates to the Validator.
func (p *Pipeline) ValidateActions(proposals []mg.ActionProposal) error {
	return p.validator.ValidateActions(proposals)
}

// ValidateExplanation delegates to the Validator.
func (p *Pipeline) ValidateExplanation(e *mg.Explanation) error {
	return p.validator.ValidateExplanation(e)
}
