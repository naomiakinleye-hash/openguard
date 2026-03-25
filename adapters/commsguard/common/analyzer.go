// Package commsguardcommon provides shared types and utilities for the CommsGuard sensor.
package commsguardcommon

import (
	"encoding/base64"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	// urlRegex matches http(s) URLs in message content.
	urlRegex = regexp.MustCompile(`https?://[^\s<>"']+`)
	// ipURLRegex detects URLs using IP addresses instead of hostnames.
	ipURLRegex = regexp.MustCompile(`https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	// base64Regex detects base64-encoded blobs (long sequences of base64 chars).
	base64Regex = regexp.MustCompile(`[A-Za-z0-9+/]{100,}={0,2}`)
)

// suspiciousTLDs are top-level domains commonly used in phishing and abuse.
var suspiciousTLDs = []string{".xyz", ".tk", ".ml", ".ga", ".cf"}

// urlShorteners are common URL shortening services.
var urlShorteners = []string{"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "tiny.cc"}

// phishingKeywords are urgency/action phrases commonly found in phishing messages.
var phishingKeywords = []string{
	// Account / login urgency
	"verify your account",
	"click here",
	"click the link",
	"confirm your identity",
	"your account will be suspended",
	"login immediately",
	"urgent action required",
	"account verification required",
	// Reward / prize / lottery scams
	"claim your reward",
	"claim your prize",
	"claim your winnings",
	"you have won",
	"you've won",
	"you were selected",
	"you have been selected",
	"congratulations you",
	"lottery winner",
	"prize winner",
	"selected winner",
	"unclaimed prize",
	"unclaimed reward",
	"collect your reward",
	"collect your prize",
	"you are a winner",
	// Financial lure phrases
	"million dollar",
	"1 million",
	"$1,000,000",
	"wire transfer",
	"send us your",
	"send your details",
}

// rewardScamKeywords are prize/lottery/reward phrases that signal a scam
// even without a URL present (the link often comes in a follow-up message).
var rewardScamKeywords = []string{
	"claim your reward",
	"claim your prize",
	"claim your winnings",
	"you have won",
	"you've won",
	"you were selected",
	"you have been selected",
	"congratulations you",
	"lottery winner",
	"prize winner",
	"selected winner",
	"unclaimed prize",
	"unclaimed reward",
	"collect your reward",
	"collect your prize",
	"you are a winner",
	"1million",
	"1 million",
	"million reward",
	"million prize",
}

// credentialKeywords are terms associated with credential harvesting.
var credentialKeywords = []string{
	"password",
	"username",
	"ssn",
	"credit card",
	"bank account",
	"otp",
	"verification code",
}

// socialEngineeringPatterns are phrases used in social engineering attacks.
var socialEngineeringPatterns = []string{
	"i am from",
	"i'm from",
	"calling from",
	"this is your bank",
	"this is support",
	"this is admin",
	"from the it department",
	"from technical support",
	"from customer support",
}

// suspiciousExtensions are file extensions associated with malware.
var suspiciousExtensions = []string{".exe", ".bat", ".ps1", ".sh", ".vbs", ".cmd", ".scr", ".msi"}

// senderRecord tracks per-sender message history for bulk/spam detection.
type senderRecord struct {
	timestamps []time.Time
	contents   []string
}

// ThreatAnalyzer performs heuristic threat analysis on CommsEvent messages.
type ThreatAnalyzer struct {
	mu                   sync.Mutex
	senderHistory        map[string]*senderRecord
	bulkThreshold        int
	bulkWindow           time.Duration
	enableContentAnalysis bool
}

// NewThreatAnalyzer creates a new ThreatAnalyzer with the given configuration.
func NewThreatAnalyzer(bulkThreshold int, bulkWindow time.Duration, enableContentAnalysis bool) *ThreatAnalyzer {
	if bulkThreshold <= 0 {
		bulkThreshold = 20
	}
	if bulkWindow <= 0 {
		bulkWindow = 60 * time.Second
	}
	return &ThreatAnalyzer{
		senderHistory:        make(map[string]*senderRecord),
		bulkThreshold:        bulkThreshold,
		bulkWindow:           bulkWindow,
		enableContentAnalysis: enableContentAnalysis,
	}
}

// Analyze inspects a CommsEvent and returns a slice of matched indicator strings.
func (a *ThreatAnalyzer) Analyze(event *CommsEvent) []string {
	var indicators []string

	// Always track sender activity for metadata-based checks.
	bulkIndicators := a.checkBulkMessaging(event)
	indicators = append(indicators, bulkIndicators...)

	if !a.enableContentAnalysis || event.Content == "" {
		return indicators
	}

	content := strings.ToLower(event.Content)
	urls := urlRegex.FindAllString(content, -1)
	hasURL := len(urls) > 0

	// Check for suspicious links.
	suspLinkIndicators := checkSuspiciousLinks(urls)
	indicators = append(indicators, suspLinkIndicators...)

	// Check for phishing patterns:
	//  - With a URL:  any phishing keyword suffices (classic click-bait pattern)
	//  - Without URL: reward/prize/lottery scam phrases are flagged immediately
	//    because the URL arrives in a follow-up message after victim engagement.
	if containsAnyPhishingKeyword(content) {
		if hasURL || containsAnyRewardScamKeyword(content) {
			indicators = append(indicators, "phishing")
		}
	} else if containsAnyRewardScamKeyword(content) {
		// Reward scam with no generic phishing keyword still deserves a flag.
		indicators = append(indicators, "phishing")
	}

	// Check for credential harvesting (credential keywords + URL).
	if hasURL && containsAnyCredentialKeyword(content) {
		indicators = append(indicators, "credential_harvesting")
	}

	// Check for social engineering patterns.
	if containsAnySocialEngineeringPattern(content) {
		indicators = append(indicators, "social_engineering")
	}

	// Check for data exfiltration patterns (also catches malware attachments by extension).
	dataExfilIndicators := checkDataExfiltration(event)
	indicators = append(indicators, dataExfilIndicators...)

	// Check for spam (repeated identical or near-identical content).
	spamIndicators := a.checkSpam(event)
	indicators = append(indicators, spamIndicators...)

	return indicators
}

// checkBulkMessaging detects when a sender sends more than the threshold messages within the window.
func (a *ThreatAnalyzer) checkBulkMessaging(event *CommsEvent) []string {
	if event.SenderID == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	now := event.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	cutoff := now.Add(-a.bulkWindow)

	rec := a.senderHistory[event.SenderID]
	if rec == nil {
		rec = &senderRecord{}
		a.senderHistory[event.SenderID] = rec
	}

	// Add current message timestamp.
	rec.timestamps = append(rec.timestamps, now)

	// Prune timestamps outside the window.
	pruned := rec.timestamps[:0]
	for _, ts := range rec.timestamps {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}
	rec.timestamps = pruned

	if len(rec.timestamps) > a.bulkThreshold {
		return []string{"bulk_message"}
	}
	return nil
}

// checkSpam detects repeated identical or near-identical messages from the same sender.
func (a *ThreatAnalyzer) checkSpam(event *CommsEvent) []string {
	if event.SenderID == "" || event.Content == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	rec := a.senderHistory[event.SenderID]
	if rec == nil {
		return nil
	}

	// Track recent unique contents (last 10).
	rec.contents = append(rec.contents, event.Content)
	if len(rec.contents) > 20 {
		rec.contents = rec.contents[len(rec.contents)-20:]
	}

	// Count duplicates.
	count := 0
	for _, c := range rec.contents {
		if c == event.Content {
			count++
		}
	}
	if count >= 5 {
		return []string{"spam"}
	}
	return nil
}

// checkSuspiciousLinks scans URLs for suspicious TLDs, shorteners, and IP addresses.
func checkSuspiciousLinks(urls []string) []string {
	if len(urls) == 0 {
		return nil
	}
	for _, u := range urls {
		ul := strings.ToLower(u)
		for _, tld := range suspiciousTLDs {
			// Check that TLD appears at end or before path/query.
			if strings.Contains(ul, tld+"/") || strings.Contains(ul, tld+"?") ||
				strings.Contains(ul, tld+"#") || strings.HasSuffix(ul, tld) {
				return []string{"suspicious_link"}
			}
		}
		for _, shortener := range urlShorteners {
			if strings.Contains(ul, shortener) {
				return []string{"suspicious_link"}
			}
		}
		if ipURLRegex.MatchString(ul) {
			return []string{"suspicious_link"}
		}
	}
	return nil
}

// checkDataExfiltration detects large messages, base64 blobs, and suspicious file patterns.
func checkDataExfiltration(event *CommsEvent) []string {
	// Large message size > 10KB.
	if utf8.RuneCountInString(event.Content) > 10*1024 {
		return []string{"data_exfiltration"}
	}

	// Base64-encoded blobs.
	if matches := base64Regex.FindAllString(event.Content, -1); len(matches) > 0 {
		// Verify it actually decodes as valid base64.
		for _, m := range matches {
			if _, err := base64.StdEncoding.DecodeString(m); err == nil {
				return []string{"data_exfiltration"}
			}
		}
	}

	// Check for suspicious attachment extensions in RawData.
	if event.RawData != nil {
		if fileName, ok := event.RawData["attachment_filename"].(string); ok {
			fileNameLower := strings.ToLower(fileName)
			for _, ext := range suspiciousExtensions {
				if strings.HasSuffix(fileNameLower, ext) {
					return []string{"malware_attachment"}
				}
			}
		}
	}

	return nil
}

// checkMalwareAttachment checks for suspicious attachment extensions in event metadata.
func checkMalwareAttachment(event *CommsEvent) []string {
	if event.RawData == nil {
		return nil
	}
	if fileName, ok := event.RawData["attachment_filename"].(string); ok {
		fileNameLower := strings.ToLower(fileName)
		for _, ext := range suspiciousExtensions {
			if strings.HasSuffix(fileNameLower, ext) {
				return []string{"malware_attachment"}
			}
		}
	}
	return nil
}

// containsAnyPhishingKeyword returns true if content contains any phishing keyword.
func containsAnyPhishingKeyword(content string) bool {
	for _, kw := range phishingKeywords {
		if strings.Contains(content, kw) {
			return true
		}
	}
	return false
}

// containsAnyRewardScamKeyword returns true if content contains a reward/prize/lottery scam phrase.
// These phrases are high-confidence phishing indicators even without a URL in the message,
// because prize scam workflows deliver the malicious link only after the victim responds.
func containsAnyRewardScamKeyword(content string) bool {
	for _, kw := range rewardScamKeywords {
		if strings.Contains(content, kw) {
			return true
		}
	}
	return false
}

// containsAnyCredentialKeyword returns true if content contains any credential keyword.
func containsAnyCredentialKeyword(content string) bool {
	for _, kw := range credentialKeywords {
		if strings.Contains(content, kw) {
			return true
		}
	}
	return false
}

// containsAnySocialEngineeringPattern returns true if content contains social engineering patterns.
func containsAnySocialEngineeringPattern(content string) bool {
	for _, pattern := range socialEngineeringPatterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}
	return false
}
