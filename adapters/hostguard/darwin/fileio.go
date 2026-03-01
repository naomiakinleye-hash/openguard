//go:build darwin

// Package hostguarddarwin implements the HostGuard sensor for macOS.
package hostguarddarwin

import (
	"context"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// FileMonitor watches sensitive paths for file I/O events using fsnotify,
// which uses kqueue vnode events (NOTE_WRITE, NOTE_DELETE, NOTE_RENAME, NOTE_ATTRIB)
// on macOS.
type FileMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newFileMonitor creates a FileMonitor that sends events to eventCh.
func newFileMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *FileMonitor {
	return &FileMonitor{
		cfg:     cfg,
		eventCh: eventCh,
		logger:  logger,
	}
}

// Start begins watching all configured sensitive paths.
func (m *FileMonitor) Start(ctx context.Context) error {
	if len(m.cfg.SensitivePathPrefixes) == 0 {
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	for _, path := range m.cfg.SensitivePathPrefixes {
		if err := watcher.Add(path); err != nil {
			m.logger.Warn("darwin fileio: watch path", zap.String("path", path), zap.Error(err))
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	m.wg.Add(1)
	go m.watchLoop(ctx, watcher)
	return nil
}

// Stop gracefully shuts down the FileMonitor.
func (m *FileMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// watchLoop processes fsnotify events.
func (m *FileMonitor) watchLoop(ctx context.Context, watcher *fsnotify.Watcher) {
	defer m.wg.Done()
	defer watcher.Close() //nolint:errcheck
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			m.handleFSEvent(ctx, event)
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			m.logger.Warn("darwin fileio: watcher error", zap.Error(err))
		}
	}
}

// handleFSEvent converts an fsnotify event to a HostEvent.
func (m *FileMonitor) handleFSEvent(ctx context.Context, event fsnotify.Event) {
	op, eventType := fsnotifyOpToStrings(event.Op)

	fileIO := &common.FileIOEvent{
		Path:      event.Name,
		Operation: op,
	}

	hostEvent := &common.HostEvent{
		EventType: eventType,
		Platform:  "darwin",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		FileIO:    fileIO,
	}
	select {
	case m.eventCh <- hostEvent:
	case <-ctx.Done():
		return
	}

	// Emit suspicious_file_access for sensitive paths.
	if m.isSensitivePath(event.Name) {
		suspicious := &common.HostEvent{
			EventType:  "suspicious_file_access",
			Platform:   "darwin",
			Hostname:   m.cfg.Hostname,
			Timestamp:  time.Now(),
			FileIO:     fileIO,
			Indicators: []string{"sensitive_path_access"},
		}
		select {
		case m.eventCh <- suspicious:
		case <-ctx.Done():
		}
	}
}

// fsnotifyOpToStrings maps an fsnotify Op to a file operation string and HostEvent type.
func fsnotifyOpToStrings(op fsnotify.Op) (string, string) {
	switch {
	case op&fsnotify.Create != 0:
		return "create", "file_created"
	case op&fsnotify.Remove != 0:
		return "delete", "file_deleted"
	case op&fsnotify.Rename != 0:
		return "rename", "file_modified"
	case op&fsnotify.Write != 0:
		return "write", "file_modified"
	case op&fsnotify.Chmod != 0:
		return "chmod", "file_modified"
	default:
		return "read", "file_access"
	}
}

// isSensitivePath returns true if the path starts with any configured sensitive prefix.
func (m *FileMonitor) isSensitivePath(path string) bool {
	for _, prefix := range m.cfg.SensitivePathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
