//go:build darwin

// Package hostguarddarwin implements the HostGuard sensor for macOS.
package hostguarddarwin

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// LoginItemsMonitor watches for new macOS login items.
type LoginItemsMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	baseline map[string]struct{}
	mu       sync.Mutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newLoginItemsMonitor creates a LoginItemsMonitor that sends events to eventCh.
func newLoginItemsMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *LoginItemsMonitor {
	return &LoginItemsMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		baseline: make(map[string]struct{}),
	}
}

// Start baselines existing login items and starts polling every 60 seconds.
func (m *LoginItemsMonitor) Start(ctx context.Context) error {
	items, err := listLoginItems()
	if err != nil {
		m.logger.Debug("darwin: login items baseline", zap.Error(err))
	} else {
		m.mu.Lock()
		for _, item := range items {
			m.baseline[item] = struct{}{}
		}
		m.mu.Unlock()
	}

	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(60 * time.Second)
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

// Stop gracefully shuts down the LoginItemsMonitor.
func (m *LoginItemsMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll checks for newly added login items.
func (m *LoginItemsMonitor) poll(ctx context.Context) {
	items, err := listLoginItems()
	if err != nil {
		m.logger.Debug("darwin: list login items", zap.Error(err))
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, item := range items {
		if _, known := m.baseline[item]; !known {
			m.baseline[item] = struct{}{}
			startupItem := &common.StartupItem{
				ID:           item,
				Name:         item,
				Type:         "launch_agent",
				Command:      item,
				Enabled:      true,
				LastModified: time.Now(),
				Source:       "login_items",
			}
			event := &common.HostEvent{
				EventType:   "startup_item_added",
				Platform:    "darwin",
				Hostname:    m.cfg.Hostname,
				Timestamp:   time.Now(),
				StartupItem: startupItem,
				Indicators:  []string{},
			}
			select {
			case m.eventCh <- event:
			case <-ctx.Done():
				return
			}
		}
	}
}

// listLoginItems retrieves the current login items via osascript.
func listLoginItems() ([]string, error) {
	script := `tell application "System Events" to get the name of every login item`
	cmd := exec.Command("osascript", "-e", script)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("darwin: osascript login items: %w", err)
	}
	raw := strings.TrimSpace(string(bytes.TrimSpace(out)))
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ", ")
	var items []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			items = append(items, p)
		}
	}
	return items, nil
}
