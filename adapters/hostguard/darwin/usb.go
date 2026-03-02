//go:build darwin

// Package hostguarddarwin implements the HostGuard sensor for macOS.
package hostguarddarwin

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// darwinUSBItem represents a USB device entry from system_profiler JSON output.
type darwinUSBItem struct {
	Name         string `json:"_name"`
	VendorID     string `json:"vendor_id"`
	ProductID    string `json:"product_id"`
	Manufacturer string `json:"manufacturer"`
	DeviceClass  string `json:"bcd_device"`
}

// USBMonitor periodically parses system_profiler SPUSBDataType output to detect
// USB device insertions and removals on macOS.
type USBMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	baseline map[string]darwinUSBItem // keyed by VendorID+ProductID+Name
	mu       sync.Mutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newUSBMonitor creates a USBMonitor that sends events to eventCh.
func newUSBMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *USBMonitor {
	return &USBMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		baseline: make(map[string]darwinUSBItem),
	}
}

// Start begins polling system_profiler at the configured interval.
func (m *USBMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	interval := m.cfg.PollInterval
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}

	// Establish initial baseline without emitting events.
	initial, err := m.snapshot(ctx)
	if err != nil {
		m.logger.Warn("darwin: usb monitor: initial snapshot", zap.Error(err))
	}
	m.mu.Lock()
	for k, v := range initial {
		m.baseline[k] = v
	}
	m.mu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(interval)
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

// Stop gracefully shuts down the USBMonitor.
func (m *USBMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll takes a snapshot and diffs against the baseline.
func (m *USBMonitor) poll(ctx context.Context) {
	current, err := m.snapshot(ctx)
	if err != nil {
		m.logger.Warn("darwin: usb monitor: snapshot", zap.Error(err))
		return
	}

	m.mu.Lock()
	last := m.baseline
	m.baseline = current
	m.mu.Unlock()

	for key, dev := range current {
		if _, existed := last[key]; !existed {
			m.emitInsertEvent(ctx, dev)
		}
	}
	for key, dev := range last {
		if _, exists := current[key]; !exists {
			m.emitRemoveEvent(ctx, dev)
		}
	}
}

// snapshot runs system_profiler and returns a map of USB devices.
func (m *USBMonitor) snapshot(ctx context.Context) (map[string]darwinUSBItem, error) {
	out, err := exec.CommandContext(ctx, "system_profiler", "SPUSBDataType", "-json").Output()
	if err != nil {
		return nil, err
	}
	devices := make(map[string]darwinUSBItem)
	m.parseProfilerOutput(out, devices)
	return devices, nil
}

// parseProfilerOutput parses system_profiler JSON and populates devices map.
func (m *USBMonitor) parseProfilerOutput(data []byte, devices map[string]darwinUSBItem) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}
	spData, ok := raw["SPUSBDataType"]
	if !ok {
		return
	}
	var items []json.RawMessage
	if err := json.Unmarshal(spData, &items); err != nil {
		return
	}
	for _, item := range items {
		var dev darwinUSBItem
		if err := json.Unmarshal(item, &dev); err != nil {
			continue
		}
		key := strings.Join([]string{dev.VendorID, dev.ProductID, dev.Name}, ":")
		if key == "::" {
			continue
		}
		devices[key] = dev
	}
}

// emitInsertEvent emits a USB insertion event.
func (m *USBMonitor) emitInsertEvent(ctx context.Context, dev darwinUSBItem) {
	event := &common.HostEvent{
		EventType: "usb_device_inserted",
		Platform:  "darwin",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		RawData: map[string]interface{}{
			"vendor_id":    dev.VendorID,
			"product_id":   dev.ProductID,
			"manufacturer": dev.Manufacturer,
			"product_name": dev.Name,
			"device_class": dev.DeviceClass,
			"device_path":  "",
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// emitRemoveEvent emits a USB removal event.
func (m *USBMonitor) emitRemoveEvent(ctx context.Context, dev darwinUSBItem) {
	event := &common.HostEvent{
		EventType: "usb_device_removed",
		Platform:  "darwin",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		RawData: map[string]interface{}{
			"vendor_id":    dev.VendorID,
			"product_id":   dev.ProductID,
			"manufacturer": dev.Manufacturer,
			"product_name": dev.Name,
			"device_class": dev.DeviceClass,
			"device_path":  "",
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}
