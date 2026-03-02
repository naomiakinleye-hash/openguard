//go:build windows

// Package hostguardwindows implements the HostGuard sensor for Windows.
package hostguardwindows

import (
	"context"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"github.com/StackExchange/wmi"
	"go.uber.org/zap"
)

// win32USBControllerDevice maps to a WMI Win32_USBControllerDevice entry.
type win32USBControllerDevice struct {
	Dependent string
}

// win32PnPEntity maps to a WMI Win32_PnPEntity entry used for USB device enumeration.
type win32PnPEntity struct {
	DeviceID    string
	Name        string
	Manufacturer string
	ClassGuid   string
	PNPClass    string
}

// usbDeviceKey is a stable identifier for a USB device.
type usbDeviceKey struct {
	DeviceID string
}

// USBMonitor polls WMI to detect USB device insertions and removals on Windows.
type USBMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	baseline map[string]win32PnPEntity // keyed by DeviceID
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
		baseline: make(map[string]win32PnPEntity),
	}
}

// Start begins polling WMI at the configured interval.
func (m *USBMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	interval := m.cfg.PollInterval
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}

	// Establish initial baseline without emitting events.
	initial, err := m.snapshot()
	if err != nil {
		m.logger.Warn("windows: usb monitor: initial snapshot", zap.Error(err))
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

// poll takes a WMI snapshot and diffs against the baseline.
func (m *USBMonitor) poll(ctx context.Context) {
	current, err := m.snapshot()
	if err != nil {
		m.logger.Warn("windows: usb monitor: snapshot", zap.Error(err))
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

// snapshot queries WMI for USB-related PnP entities.
func (m *USBMonitor) snapshot() (map[string]win32PnPEntity, error) {
	var entities []win32PnPEntity
	query := `SELECT DeviceID, Name, Manufacturer, ClassGuid, PNPClass FROM Win32_PnPEntity WHERE PNPClass = 'USB' OR PNPClass = 'DiskDrive'`
	if err := wmi.Query(query, &entities); err != nil {
		return nil, err
	}
	result := make(map[string]win32PnPEntity, len(entities))
	for _, e := range entities {
		result[e.DeviceID] = e
	}
	return result, nil
}

// emitInsertEvent emits a USB insertion event.
func (m *USBMonitor) emitInsertEvent(ctx context.Context, dev win32PnPEntity) {
	eventType := "usb_device_inserted"
	indicators := []string{}

	// USB Mass Storage ClassGuid: {4d36e967-e325-11ce-bfc1-08002be10318}
	// USB HID ClassGuid: {745a17a0-74d3-11d0-b6fe-00a0c90f57da}
	lowerGuid := strings.ToLower(dev.ClassGuid)
	switch lowerGuid {
	case "{4d36e967-e325-11ce-bfc1-08002be10318}":
		eventType = "usb_mass_storage_inserted"
		indicators = append(indicators, "usb_mass_storage_inserted")
	case "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}":
		eventType = "usb_hid_inserted"
		indicators = append(indicators, "usb_hid_inserted")
	}

	event := &common.HostEvent{
		EventType:  eventType,
		Platform:   "windows",
		Hostname:   m.cfg.Hostname,
		Timestamp:  time.Now(),
		Indicators: indicators,
		RawData: map[string]interface{}{
			"vendor_id":    "",
			"product_id":   "",
			"manufacturer": dev.Manufacturer,
			"product_name": dev.Name,
			"device_class": dev.ClassGuid,
			"device_path":  dev.DeviceID,
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// emitRemoveEvent emits a USB removal event.
func (m *USBMonitor) emitRemoveEvent(ctx context.Context, dev win32PnPEntity) {
	event := &common.HostEvent{
		EventType: "usb_device_removed",
		Platform:  "windows",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		RawData: map[string]interface{}{
			"vendor_id":    "",
			"product_id":   "",
			"manufacturer": dev.Manufacturer,
			"product_name": dev.Name,
			"device_class": dev.ClassGuid,
			"device_path":  dev.DeviceID,
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}
