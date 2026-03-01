//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

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

// systemdWatchDirs are directories watched for unit file changes.
var systemdWatchDirs = []string{
	"/etc/systemd/system/",
	"/usr/lib/systemd/system/",
}

// SystemdMonitor watches systemd unit directories for new or modified units.
type SystemdMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	watcher  *fsnotify.Watcher
	baseline map[string]time.Time // path → mtime
	mu       sync.Mutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newSystemdMonitor creates a SystemdMonitor that sends events to eventCh.
func newSystemdMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *SystemdMonitor {
	return &SystemdMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		baseline: make(map[string]time.Time),
	}
}

// Start begins watching systemd unit directories.
func (m *SystemdMonitor) Start(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("linux: systemd watcher: %w", err)
	}
	m.watcher = watcher

	for _, dir := range systemdWatchDirs {
		if err := watcher.Add(dir); err != nil {
			m.logger.Debug("linux: systemd watch dir unavailable",
				zap.String("dir", dir), zap.Error(err))
		} else {
			m.logger.Debug("linux: watching systemd dir", zap.String("dir", dir))
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	m.wg.Add(1)
	go m.run(ctx)
	return nil
}

// Stop gracefully shuts down the SystemdMonitor.
func (m *SystemdMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	if m.watcher != nil {
		m.watcher.Close() //nolint:errcheck
	}
	m.wg.Wait()
}

// run processes fsnotify events.
func (m *SystemdMonitor) run(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			m.handleFSEvent(ctx, event)
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			m.logger.Warn("linux: systemd watcher error", zap.Error(err))
		}
	}
}

// handleFSEvent processes a single filesystem event.
func (m *SystemdMonitor) handleFSEvent(ctx context.Context, event fsnotify.Event) {
	if filepath.Ext(event.Name) != ".service" &&
		filepath.Ext(event.Name) != ".timer" &&
		filepath.Ext(event.Name) != ".socket" &&
		filepath.Ext(event.Name) != ".mount" {
		return
	}

	m.mu.Lock()
	_, known := m.baseline[event.Name]
	m.baseline[event.Name] = time.Now()
	m.mu.Unlock()

	eventType := "startup_item_modified"
	if !known && (event.Op&fsnotify.Create != 0) {
		eventType = "startup_item_added"
	}

	indicators := m.inspectUnitFile(event.Name)

	item := &common.StartupItem{
		ID:           event.Name,
		Name:         filepath.Base(event.Name),
		Type:         "systemd_unit",
		Source:       event.Name,
		Enabled:      true,
		LastModified: time.Now(),
	}

	m.emit(ctx, eventType, item, indicators)
}

// inspectUnitFile checks a unit file for suspicious content.
func (m *SystemdMonitor) inspectUnitFile(path string) []string {
	var indicators []string
	// Flag units whose path points to suspicious directories.
	suspiciousDirs := []string{"/tmp", "/dev/shm", "/var/tmp"}
	pathLower := strings.ToLower(path)
	for _, s := range suspiciousDirs {
		if strings.Contains(pathLower, s) {
			indicators = append(indicators, "suspicious_persistence_path")
		}
	}
	return indicators
}

// emit sends a startup item event onto the event channel.
func (m *SystemdMonitor) emit(ctx context.Context, eventType string, item *common.StartupItem, indicators []string) {
	event := &common.HostEvent{
		EventType:   eventType,
		Platform:    "linux",
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
