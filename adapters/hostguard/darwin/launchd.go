//go:build darwin

// Package hostguarddarwin implements the HostGuard sensor for macOS.
package hostguarddarwin

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// launchdWatchDirs are the directories monitored for LaunchAgent/Daemon plist changes.
var launchdWatchDirs = []string{
	"/Library/LaunchDaemons",
	"/Library/LaunchAgents",
}

// LaunchdMonitor watches LaunchAgent and LaunchDaemon directories for plist changes.
type LaunchdMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	watcher  *fsnotify.Watcher
	baseline map[string]time.Time
	mu       sync.Mutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newLaunchdMonitor creates a LaunchdMonitor that sends events to eventCh.
func newLaunchdMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *LaunchdMonitor {
	return &LaunchdMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		baseline: make(map[string]time.Time),
	}
}

// Start begins watching LaunchAgent/Daemon directories.
func (m *LaunchdMonitor) Start(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("darwin: launchd watcher: %w", err)
	}
	m.watcher = watcher

	for _, dir := range launchdWatchDirs {
		if err := watcher.Add(dir); err != nil {
			m.logger.Debug("darwin: launchd watch dir unavailable",
				zap.String("dir", dir), zap.Error(err))
		} else {
			m.logger.Debug("darwin: watching launchd dir", zap.String("dir", dir))
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	m.wg.Add(1)
	go m.run(ctx)
	return nil
}

// Stop gracefully shuts down the LaunchdMonitor.
func (m *LaunchdMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	if m.watcher != nil {
		m.watcher.Close() //nolint:errcheck
	}
	m.wg.Wait()
}

// run processes fsnotify events.
func (m *LaunchdMonitor) run(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			if filepath.Ext(event.Name) == ".plist" {
				m.handleFSEvent(ctx, event)
			}
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			m.logger.Warn("darwin: launchd watcher error", zap.Error(err))
		}
	}
}

// handleFSEvent processes a plist filesystem event.
func (m *LaunchdMonitor) handleFSEvent(ctx context.Context, event fsnotify.Event) {
	m.mu.Lock()
	_, known := m.baseline[event.Name]
	m.baseline[event.Name] = time.Now()
	m.mu.Unlock()

	eventType := "startup_item_modified"
	if !known && (event.Op&fsnotify.Create != 0) {
		eventType = "startup_item_added"
	}

	indicators := inspectPlistPath(event.Name)

	item := &common.StartupItem{
		ID:           event.Name,
		Name:         filepath.Base(event.Name),
		Type:         "launch_agent",
		Source:       event.Name,
		Enabled:      true,
		LastModified: time.Now(),
	}
	if strings.Contains(event.Name, "LaunchDaemon") {
		item.Type = "launch_daemon"
	}

	m.emit(ctx, eventType, item, indicators)
}

// inspectPlistPath returns suspicious indicators for a plist file path.
func inspectPlistPath(path string) []string {
	var indicators []string
	lower := strings.ToLower(path)
	for _, s := range []string{"/tmp", "/var/folders", "downloads"} {
		if strings.Contains(lower, s) {
			indicators = append(indicators, "suspicious_persistence_path")
		}
	}
	return indicators
}

// emit sends a startup item event onto the event channel.
func (m *LaunchdMonitor) emit(ctx context.Context, eventType string, item *common.StartupItem, indicators []string) {
	event := &common.HostEvent{
		EventType:   eventType,
		Platform:    "darwin",
		Hostname:    m.cfg.Hostname,
		Timestamp:   time.Now(),
		StartupItem: item,
		Indicators:  indicators,
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}
