//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// usbDeviceInfo holds information about a USB device read from sysfs.
type usbDeviceInfo struct {
	DevicePath  string
	VendorID    string
	ProductID   string
	Manufacturer string
	ProductName string
	DeviceClass string
}

// USBMonitor polls /sys/bus/usb/devices/ to detect USB device insertions and removals.
type USBMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	baseline map[string]usbDeviceInfo // keyed by device path
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
		baseline: make(map[string]usbDeviceInfo),
	}
}

// Start begins polling /sys/bus/usb/devices/ at the configured interval.
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
		m.logger.Warn("linux: usb monitor: initial snapshot unavailable", zap.Error(err))
	}
	m.mu.Lock()
	for _, dev := range initial {
		m.baseline[dev.DevicePath] = dev
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
	current, err := m.snapshot()
	if err != nil {
		m.logger.Warn("linux: usb monitor: snapshot", zap.Error(err))
		return
	}

	currentMap := make(map[string]usbDeviceInfo, len(current))
	for _, dev := range current {
		currentMap[dev.DevicePath] = dev
	}

	m.mu.Lock()
	last := m.baseline
	m.baseline = currentMap
	m.mu.Unlock()

	// Detect new devices.
	for path, dev := range currentMap {
		if _, existed := last[path]; !existed {
			m.emitInsertEvent(ctx, dev)
		}
	}

	// Detect removed devices.
	for path, dev := range last {
		if _, exists := currentMap[path]; !exists {
			m.emitRemoveEvent(ctx, dev)
		}
	}
}

// snapshot reads /sys/bus/usb/devices/ and returns current USB devices.
func (m *USBMonitor) snapshot() ([]usbDeviceInfo, error) {
	const usbDevicesPath = "/sys/bus/usb/devices"
	entries, err := os.ReadDir(usbDevicesPath)
	if err != nil {
		return nil, err
	}

	var devices []usbDeviceInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		devPath := filepath.Join(usbDevicesPath, entry.Name())
		dev := usbDeviceInfo{DevicePath: devPath}
		dev.VendorID = readSysAttr(devPath, "idVendor")
		dev.ProductID = readSysAttr(devPath, "idProduct")
		dev.Manufacturer = readSysAttr(devPath, "manufacturer")
		dev.ProductName = readSysAttr(devPath, "product")
		dev.DeviceClass = readSysAttr(devPath, "bDeviceClass")
		if dev.DeviceClass == "" {
			dev.DeviceClass = readSysAttr(devPath, "bInterfaceClass")
		}
		// Only include entries that look like real devices (have a vendor ID).
		if dev.VendorID == "" {
			continue
		}
		devices = append(devices, dev)
	}
	return devices, nil
}

// emitInsertEvent emits a USB insertion event, potentially with class-specific indicators.
func (m *USBMonitor) emitInsertEvent(ctx context.Context, dev usbDeviceInfo) {
	indicators := []string{}
	eventType := "usb_device_inserted"

	class := strings.TrimSpace(dev.DeviceClass)
	switch class {
	case "08": // USB Mass Storage
		eventType = "usb_mass_storage_inserted"
		indicators = append(indicators, "usb_mass_storage_inserted")
	case "03": // HID
		eventType = "usb_hid_inserted"
		indicators = append(indicators, "usb_hid_inserted")
	}

	event := &common.HostEvent{
		EventType:  eventType,
		Platform:   "linux",
		Hostname:   m.cfg.Hostname,
		Timestamp:  time.Now(),
		Indicators: indicators,
		RawData: map[string]interface{}{
			"vendor_id":    dev.VendorID,
			"product_id":   dev.ProductID,
			"manufacturer": dev.Manufacturer,
			"product_name": dev.ProductName,
			"device_class": dev.DeviceClass,
			"device_path":  dev.DevicePath,
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// emitRemoveEvent emits a USB removal event.
func (m *USBMonitor) emitRemoveEvent(ctx context.Context, dev usbDeviceInfo) {
	event := &common.HostEvent{
		EventType: "usb_device_removed",
		Platform:  "linux",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		RawData: map[string]interface{}{
			"vendor_id":    dev.VendorID,
			"product_id":   dev.ProductID,
			"manufacturer": dev.Manufacturer,
			"product_name": dev.ProductName,
			"device_class": dev.DeviceClass,
			"device_path":  dev.DevicePath,
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// readSysAttr reads a sysfs attribute file and returns its trimmed content.
func readSysAttr(devPath, attr string) string {
	data, err := os.ReadFile(filepath.Join(devPath, attr))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
