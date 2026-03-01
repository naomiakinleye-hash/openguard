//go:build windows

// Package hostguardwindows implements the HostGuard sensor for Windows.
package hostguardwindows

import (
	"context"
	"fmt"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"golang.org/x/sys/windows/registry"
	"go.uber.org/zap"
)

// registryRunKeys are the registry paths monitored for persistence entries.
var registryRunKeys = []struct {
	root registry.Key
	path string
}{
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
	{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.LOCAL_MACHINE, `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`},
}

// registryValueSnapshot holds a snapshot of a single registry value.
type registryValueSnapshot struct {
	name    string
	data    string
	keyPath string
}

// RegistryMonitor monitors Windows registry run keys for persistence changes.
type RegistryMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	baseline map[string]registryValueSnapshot // key: keyPath+":"+name
	mu       sync.Mutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newRegistryMonitor creates a RegistryMonitor that sends events to eventCh.
func newRegistryMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *RegistryMonitor {
	return &RegistryMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		baseline: make(map[string]registryValueSnapshot),
	}
}

// Start baselines the registry keys and begins polling.
func (m *RegistryMonitor) Start(ctx context.Context) error {
	if err := m.snapshot(); err != nil {
		m.logger.Debug("windows: registry baseline", zap.Error(err))
	}

	pollInterval := m.cfg.PollInterval * 2
	if pollInterval < 10*time.Second {
		pollInterval = 10 * time.Second
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

// Stop gracefully shuts down the RegistryMonitor.
func (m *RegistryMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// snapshot records all current registry run key values as the baseline.
func (m *RegistryMonitor) snapshot() error {
	values, err := readAllRunKeys()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range values {
		m.baseline[k] = v
	}
	return nil
}

// poll checks for new, modified, or deleted registry values.
func (m *RegistryMonitor) poll(ctx context.Context) {
	current, err := readAllRunKeys()
	if err != nil {
		m.logger.Warn("windows: registry poll", zap.Error(err))
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for key, val := range current {
		existing, known := m.baseline[key]
		if !known {
			m.baseline[key] = val
			item := buildRegistryStartupItem(val)
			m.emit(ctx, "startup_item_added", &item, nil)
		} else if existing.data != val.data {
			m.baseline[key] = val
			item := buildRegistryStartupItem(val)
			m.emit(ctx, "startup_item_modified", &item, nil)
		}
	}
	for key, val := range m.baseline {
		if _, exists := current[key]; !exists {
			delete(m.baseline, key)
			item := buildRegistryStartupItem(val)
			m.emit(ctx, "startup_item_removed", &item, nil)
		}
	}
}

// readAllRunKeys reads all monitored registry run keys and returns a map of key→snapshot.
func readAllRunKeys() (map[string]registryValueSnapshot, error) {
	result := make(map[string]registryValueSnapshot)
	for _, rk := range registryRunKeys {
		k, err := registry.OpenKey(rk.root, rk.path, registry.QUERY_VALUE)
		if err != nil {
			continue // key may not exist
		}
		names, err := k.ReadValueNames(-1)
		k.Close() //nolint:errcheck
		if err != nil {
			continue
		}

		k2, err := registry.OpenKey(rk.root, rk.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		for _, name := range names {
			val, _, err := k2.GetStringValue(name)
			if err != nil {
				continue
			}
			keyFull := fmt.Sprintf("%s\\%s", rk.path, name)
			result[keyFull] = registryValueSnapshot{
				name:    name,
				data:    val,
				keyPath: rk.path,
			}
		}
		k2.Close() //nolint:errcheck
	}
	return result, nil
}

// buildRegistryStartupItem constructs a StartupItem from a registry value snapshot.
func buildRegistryStartupItem(v registryValueSnapshot) common.StartupItem {
	return common.StartupItem{
		ID:      fmt.Sprintf("%s:%s", v.keyPath, v.name),
		Name:    v.name,
		Type:    "registry_run",
		Command: v.data,
		Enabled: true,
		Source:  v.keyPath,
	}
}

// emit sends a startup item event onto the event channel.
func (m *RegistryMonitor) emit(ctx context.Context, eventType string, item *common.StartupItem, indicators []string) {
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


