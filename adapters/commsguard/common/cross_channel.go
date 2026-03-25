// Package commsguardcommon provides shared types and utilities for the CommsGuard sensor.
package commsguardcommon

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// crossChannelEntry records the channels on which a particular threat fingerprint
// has been observed within the configured look-back window.
type crossChannelEntry struct {
	firstSeen time.Time
	lastSeen  time.Time
	channels  map[string]struct{} // set of channel identifiers
}

// CrossChannelTracker detects coordinated threat campaigns that appear across
// multiple communication channels (e.g. the same phishing sender on both
// WhatsApp and Telegram within a 24-hour window).
//
// It is safe for concurrent use. Stale entries are pruned lazily on every
// call to Track.
type CrossChannelTracker struct {
	mu     sync.Mutex
	window time.Duration
	sigs   map[string]*crossChannelEntry // key = threat fingerprint
	logger *zap.Logger
}

// NewCrossChannelTracker creates a CrossChannelTracker with the given look-back
// window. If window is zero or negative, 24 hours is used.
func NewCrossChannelTracker(window time.Duration, logger *zap.Logger) *CrossChannelTracker {
	if window <= 0 {
		window = 24 * time.Hour
	}
	return &CrossChannelTracker{
		window: window,
		sigs:   make(map[string]*crossChannelEntry),
		logger: logger,
	}
}

// Track records that threat indicators were observed for the given event and
// returns true if the same threat fingerprint has already been seen on at least
// one other channel within the look-back window.
//
// The fingerprint is a hash of (normalised_sender_id + primary_indicator), so
// the same sender mounting the same attack type on two channels triggers a hit.
// If indicators is empty the call is a no-op and returns false.
func (t *CrossChannelTracker) Track(event *CommsEvent, indicators []string) bool {
	if len(indicators) == 0 || event.Channel == "" {
		return false
	}

	fp := threatFingerprint(event.SenderID, indicators[0])
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	t.prune(now)

	entry, exists := t.sigs[fp]
	if !exists {
		t.sigs[fp] = &crossChannelEntry{
			firstSeen: now,
			lastSeen:  now,
			channels:  map[string]struct{}{event.Channel: {}},
		}
		return false
	}

	entry.lastSeen = now
	entry.channels[event.Channel] = struct{}{}

	// Cross-channel confirmed when the same threat is seen on 2+ distinct channels.
	isMultiChannel := len(entry.channels) >= 2
	if isMultiChannel {
		t.logger.Info("commsguard: cross-channel threat detected",
			zap.String("sender_id", event.SenderID),
			zap.String("current_channel", event.Channel),
			zap.Int("channel_count", len(entry.channels)),
			zap.String("primary_indicator", indicators[0]),
		)
	}
	return isMultiChannel
}

// prune removes entries whose lastSeen timestamp is older than the look-back window.
// Must be called with t.mu held.
func (t *CrossChannelTracker) prune(now time.Time) {
	cutoff := now.Add(-t.window)
	for k, e := range t.sigs {
		if e.lastSeen.Before(cutoff) {
			delete(t.sigs, k)
		}
	}
}

// threatFingerprint returns a compact hex fingerprint that combines the sender
// identity and the primary threat indicator type.
func threatFingerprint(senderID, primaryIndicator string) string {
	h := sha256.Sum256([]byte(senderID + "\x00" + primaryIndicator))
	// Use first 16 bytes (32 hex chars) — collision-resistant for this use case.
	return fmt.Sprintf("%x", h[:16])
}
