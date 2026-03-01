//go:build windows

// Package hostguardwindows implements the HostGuard sensor for Windows.
package hostguardwindows

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"github.com/StackExchange/wmi"
	"go.uber.org/zap"
)

// schedulerPollMultiplier controls how much longer the scheduler polls vs. process.
const schedulerPollMultiplier = 6

// win32ScheduledJob maps to WMI Win32_ScheduledJob (legacy scheduled jobs).
type win32ScheduledJob struct {
	JobId   string
	Command string
	Name    string
}

// scheduledTaskSnapshot holds a snapshot of a scheduled task.
type scheduledTaskSnapshot struct {
	item common.StartupItem
}

// SchedulerMonitor polls Windows Task Scheduler for new or modified tasks.
type SchedulerMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	baseline map[string]scheduledTaskSnapshot
	mu       sync.Mutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newSchedulerMonitor creates a SchedulerMonitor that sends events to eventCh.
func newSchedulerMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *SchedulerMonitor {
	return &SchedulerMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		baseline: make(map[string]scheduledTaskSnapshot),
	}
}

// Start takes an initial baseline and begins polling.
func (m *SchedulerMonitor) Start(ctx context.Context) error {
	if err := m.snapshot(); err != nil {
		m.logger.Debug("windows: scheduler baseline", zap.Error(err))
	}

	pollInterval := m.cfg.PollInterval * schedulerPollMultiplier
	if pollInterval < 30*time.Second {
		pollInterval = 30 * time.Second
	}

	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.poll(ctx)
			}
		}
	}()
	return nil
}

// Stop gracefully shuts down the SchedulerMonitor.
func (m *SchedulerMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// snapshot records the current tasks as the baseline.
func (m *SchedulerMonitor) snapshot() error {
	tasks, err := queryScheduledJobs()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range tasks {
		m.baseline[t.item.ID] = t
	}
	return nil
}

// poll checks for new or modified scheduled tasks.
func (m *SchedulerMonitor) poll(ctx context.Context) {
	tasks, err := queryScheduledJobs()
	if err != nil {
		m.logger.Warn("windows: scheduler poll", zap.Error(err))
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, task := range tasks {
		existing, known := m.baseline[task.item.ID]
		eventType := "startup_item_modified"
		if !known {
			eventType = "startup_item_added"
		} else if existing.item.Command == task.item.Command {
			continue
		}
		m.baseline[task.item.ID] = task

		indicators := inspectTaskCommand(task.item.Command)
		item := task.item
		m.emit(ctx, eventType, &item, indicators)
	}
}

// queryScheduledJobs retrieves scheduled jobs via WMI.
func queryScheduledJobs() ([]scheduledTaskSnapshot, error) {
	var jobs []win32ScheduledJob
	query := "SELECT JobId, Command, Name FROM Win32_ScheduledJob"
	if err := wmi.Query(query, &jobs); err != nil {
		return nil, fmt.Errorf("windows: WMI scheduled jobs: %w", err)
	}

	var result []scheduledTaskSnapshot
	for _, j := range jobs {
		result = append(result, scheduledTaskSnapshot{
			item: common.StartupItem{
				ID:      j.JobId,
				Name:    j.Name,
				Type:    "scheduled_task",
				Command: j.Command,
				Enabled: true,
				Source:  "Win32_ScheduledJob",
			},
		})
	}
	return result, nil
}

// inspectTaskCommand checks a task command for suspicious indicators.
func inspectTaskCommand(command string) []string {
	var indicators []string
	lower := strings.ToLower(command)
	if strings.Contains(lower, "%temp%") || strings.Contains(lower, "%appdata%") {
		indicators = append(indicators, "suspicious_persistence_path")
	}
	if strings.Contains(lower, "-encodedcommand") || strings.Contains(lower, "-enc ") {
		indicators = append(indicators, "encoded_command")
	}
	return indicators
}

// emit sends a startup item event onto the event channel.
func (m *SchedulerMonitor) emit(ctx context.Context, eventType string, item *common.StartupItem, indicators []string) {
	event := &common.HostEvent{
		EventType:   eventType,
		Platform:    "windows",
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


