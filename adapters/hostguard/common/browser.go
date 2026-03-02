// Package hostguardcommon provides shared types and utilities for the HostGuard sensor.
package hostguardcommon

import (
	"strings"
	"time"
)

// browserNames is the list of known browser process names.
var browserNames = []string{"chrome", "firefox", "msedge", "safari", "brave", "opera"}

// standardBrowserPaths is the list of path prefixes where browsers are normally installed.
var standardBrowserPaths = []string{
	"/usr/bin/",
	"/opt/",
	"C:\\Program Files\\",
	"/Applications/",
}

// knownBrowserParents is the set of process names that are known browser launchers or parents.
var knownBrowserParents = map[string]bool{
	"systemd":         true,
	"launchd":         true,
	"init":            true,
	"explorer.exe":    true,
	"loginwindow":     true,
	"chrome":          true,
	"firefox":         true,
	"msedge":          true,
	"safari":          true,
	"brave":           true,
	"opera":           true,
}

// BrowserActivityAnalyzer analyzes process metadata for browser-related security anomalies.
// It operates on process-level heuristics only — no code injection.
type BrowserActivityAnalyzer struct{}

// NewBrowserActivityAnalyzer creates a new BrowserActivityAnalyzer.
func NewBrowserActivityAnalyzer() *BrowserActivityAnalyzer {
	return &BrowserActivityAnalyzer{}
}

// isBrowserName returns true if the process name matches a known browser.
func isBrowserName(name string) bool {
	lower := strings.ToLower(name)
	for _, b := range browserNames {
		if strings.Contains(lower, b) {
			return true
		}
	}
	return false
}

// isStandardBrowserPath returns true if the exe path is in a standard browser install location.
func isStandardBrowserPath(exePath string) bool {
	for _, prefix := range standardBrowserPaths {
		if strings.HasPrefix(exePath, prefix) {
			return true
		}
	}
	return false
}

// AnalyzeProcess inspects a ProcessInfo for browser-related anomalies and returns
// any triggered indicator strings. Returns nil if no indicators are triggered.
func (a *BrowserActivityAnalyzer) AnalyzeProcess(proc *ProcessInfo) []string {
	if proc == nil {
		return nil
	}
	if !isBrowserName(proc.Name) && !isBrowserName(proc.ExePath) {
		return nil
	}

	var indicators []string

	// 1. High CPU sustained for more than 30 seconds.
	if proc.CPUPercent > 80 && !proc.StartTime.IsZero() &&
		time.Since(proc.StartTime) > 30*time.Second {
		indicators = append(indicators, "browser_high_cpu")
	}

	// 2. Browser with unusual parent: handled by AnalyzeProcessWithParent when
	// the caller provides the parent process name.

	// 3. Browser exe path is not in a standard location but the name indicates a browser.
	if isBrowserName(proc.Name) && proc.ExePath != "" && !isStandardBrowserPath(proc.ExePath) {
		indicators = append(indicators, "browser_suspicious_path")
	}

	// 4. Remote debugging port flag in command line.
	if strings.Contains(proc.CmdLine, "--remote-debugging-port") {
		indicators = append(indicators, "browser_remote_debugging_enabled")
	}

	// 5. Security-disabling flags in command line.
	if strings.Contains(proc.CmdLine, "--disable-web-security") ||
		strings.Contains(proc.CmdLine, "--allow-running-insecure-content") {
		indicators = append(indicators, "browser_security_disabled")
	}

	return indicators
}

// AnalyzeProcessWithParent inspects a ProcessInfo for browser anomalies, accepting the parent
// process name for unusual-parent detection.
func (a *BrowserActivityAnalyzer) AnalyzeProcessWithParent(proc *ProcessInfo, parentName string) []string {
	indicators := a.AnalyzeProcess(proc)

	// Check for unusual parent only when we have the parent name.
	if isBrowserName(proc.Name) && parentName != "" {
		lower := strings.ToLower(parentName)
		if !knownBrowserParents[lower] {
			// Parent is not a known launcher; flag as unusual.
			indicators = append(indicators, "browser_unusual_parent")
		}
	}

	return indicators
}
