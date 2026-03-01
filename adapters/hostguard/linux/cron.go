//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// cronWatchPaths are the individual files and directories to monitor for cron changes.
var cronWatchPaths = []string{
	"/etc/crontab",
	"/etc/cron.d",
	"/etc/cron.hourly",
	"/etc/cron.daily",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
	"/var/spool/cron/crontabs",
}

// cronEntry represents a single crontab entry.
type cronEntry struct {
	Schedule string
	Command  string
	User     string
}

// CronMonitor watches crontab files for changes.
type CronMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	watcher  *fsnotify.Watcher
	baseline map[string][]cronEntry // file path → entries
	mu       sync.Mutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newCronMonitor creates a CronMonitor that sends events to eventCh.
func newCronMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *CronMonitor {
	return &CronMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		baseline: make(map[string][]cronEntry),
	}
}

// Start begins watching crontab directories.
func (m *CronMonitor) Start(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("linux: cron watcher: %w", err)
	}
	m.watcher = watcher

	for _, path := range cronWatchPaths {
		if err := watcher.Add(path); err != nil {
			m.logger.Debug("linux: cron watch path unavailable",
				zap.String("path", path), zap.Error(err))
		} else {
			m.snapshotFile(path)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	m.wg.Add(1)
	go m.run(ctx)
	return nil
}

// Stop gracefully shuts down the CronMonitor.
func (m *CronMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	if m.watcher != nil {
		m.watcher.Close() //nolint:errcheck
	}
	m.wg.Wait()
}

// run processes fsnotify events.
func (m *CronMonitor) run(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				m.handleChange(ctx, event.Name)
			}
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			m.logger.Warn("linux: cron watcher error", zap.Error(err))
		}
	}
}

// handleChange re-parses a crontab file and emits diff events.
func (m *CronMonitor) handleChange(ctx context.Context, path string) {
	newEntries, err := parseCrontab(path)
	if err != nil {
		m.logger.Debug("linux: parse crontab", zap.String("path", path), zap.Error(err))
		return
	}

	m.mu.Lock()
	oldEntries := m.baseline[path]
	m.baseline[path] = newEntries
	m.mu.Unlock()

	oldMap := make(map[string]cronEntry)
	for _, e := range oldEntries {
		key := e.Schedule + "|" + e.Command
		oldMap[key] = e
	}

	for _, entry := range newEntries {
		key := entry.Schedule + "|" + entry.Command
		eventType := "startup_item_modified"
		if _, existed := oldMap[key]; !existed {
			eventType = "startup_item_added"
		}
		indicators := checkCronIndicators(entry.Command)
		item := &common.StartupItem{
			ID:           fmt.Sprintf("%s:%s", path, entry.Command),
			Name:         filepath.Base(path),
			Type:         "cron",
			Command:      entry.Command,
			User:         entry.User,
			Source:       path,
			Enabled:      true,
			LastModified: time.Now(),
		}
		m.emit(ctx, eventType, item, indicators)
	}
}

// snapshotFile baselines a crontab file.
func (m *CronMonitor) snapshotFile(path string) {
	entries, err := parseCrontab(path)
	if err != nil {
		return
	}
	m.mu.Lock()
	m.baseline[path] = entries
	m.mu.Unlock()
}

// parseCrontab reads and parses a crontab file, returning its entries.
func parseCrontab(path string) ([]cronEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck

	var entries []cronEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") {
			continue
		}
		fields := strings.Fields(line)
		// Standard crontab: 5 time fields + command (possibly user in /etc/crontab format).
		if len(fields) >= 6 {
			entries = append(entries, cronEntry{
				Schedule: strings.Join(fields[:5], " "),
				Command:  strings.Join(fields[5:], " "),
			})
		}
	}
	return entries, nil
}

// checkCronIndicators returns suspicious indicators for a cron command.
func checkCronIndicators(command string) []string {
	var indicators []string
	lower := strings.ToLower(command)
	if strings.Contains(lower, "/tmp") || strings.Contains(lower, "/dev/shm") {
		indicators = append(indicators, "suspicious_persistence_path")
	}
	if strings.Contains(lower, "base64") {
		indicators = append(indicators, "encoded_command")
	}
	if strings.Contains(lower, "curl") && strings.Contains(lower, "| sh") ||
		strings.Contains(lower, "curl") && strings.Contains(lower, "|sh") ||
		strings.Contains(lower, "wget") && strings.Contains(lower, "| sh") {
		indicators = append(indicators, "curl_pipe_sh")
	}
	return indicators
}

// emit sends a startup item event onto the event channel.
func (m *CronMonitor) emit(ctx context.Context, eventType string, item *common.StartupItem, indicators []string) {
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
