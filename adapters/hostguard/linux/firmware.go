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

	"github.com/fsnotify/fsnotify"
	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// FirmwareMonitor checks Secure Boot status, firmware setup mode, EFI variable
// changes, and kernel hardening settings.
type FirmwareMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newFirmwareMonitor creates a FirmwareMonitor that sends events to eventCh.
func newFirmwareMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *FirmwareMonitor {
	return &FirmwareMonitor{
		cfg:     cfg,
		eventCh: eventCh,
		logger:  logger,
	}
}

// Start performs one-shot checks on startup and then watches the EFI variable
// directory for changes via inotify/fsnotify.
func (m *FirmwareMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	m.checkSecureBoot(ctx)
	m.checkKernelHardening(ctx)

	// Start fsnotify watcher for EFI variable directory.
	efiVarsDir := "/sys/firmware/efi/efivars"
	if _, err := os.Stat(efiVarsDir); err != nil {
		// Not a UEFI system; skip watcher.
		m.logger.Debug("linux: firmware monitor: EFI vars directory not available; firmware monitoring limited")
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		m.logger.Warn("linux: firmware monitor: create fsnotify watcher", zap.Error(err))
		return nil
	}
	if err := watcher.Add(efiVarsDir); err != nil {
		m.logger.Warn("linux: firmware monitor: watch efi vars dir", zap.Error(err))
		watcher.Close() //nolint:errcheck
		return nil
	}

	m.wg.Add(1)
	go func() {
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
				m.emitEFIVariableModified(ctx, event.Name)
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				m.logger.Debug("linux: firmware monitor: fsnotify error", zap.Error(err))
			}
		}
	}()
	return nil
}

// Stop gracefully shuts down the FirmwareMonitor.
func (m *FirmwareMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// checkSecureBoot reads /sys/firmware/efi/efivars/SecureBoot-* to determine
// whether Secure Boot is enabled, and also checks for firmware setup mode.
func (m *FirmwareMonitor) checkSecureBoot(ctx context.Context) {
	const efiVarsDir = "/sys/firmware/efi/efivars"

	secureBootEnabled := m.readEFIBoolVar(efiVarsDir, "SecureBoot")
	indicators := []string{}
	if !secureBootEnabled {
		indicators = append(indicators, "secure_boot_disabled")
	}
	event := &common.HostEvent{
		EventType:  "secure_boot_status",
		Platform:   "linux",
		Hostname:   m.cfg.Hostname,
		Timestamp:  time.Now(),
		Indicators: indicators,
		RawData: map[string]interface{}{
			"secure_boot_enabled": secureBootEnabled,
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}

	// Check setup mode.
	setupMode := m.readEFIBoolVar(efiVarsDir, "SetupMode")
	if setupMode {
		setupEvent := &common.HostEvent{
			EventType:  "firmware_setup_mode",
			Platform:   "linux",
			Hostname:   m.cfg.Hostname,
			Timestamp:  time.Now(),
			Indicators: []string{"firmware_setup_mode"},
			RawData: map[string]interface{}{
				"setup_mode": true,
			},
		}
		select {
		case m.eventCh <- setupEvent:
		case <-ctx.Done():
		}
	}
}

// readEFIBoolVar looks for the named EFI variable in efiVarsDir (matching
// "<name>-*" glob) and returns true if the value byte indicates enabled (1).
func (m *FirmwareMonitor) readEFIBoolVar(efiVarsDir, name string) bool {
	pattern := filepath.Join(efiVarsDir, name+"-*")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return false
	}
	// EFI variable files have a 4-byte attribute prefix followed by data.
	data, err := os.ReadFile(matches[0])
	if err != nil || len(data) < 5 {
		return false
	}
	// The data byte is at offset 4 (after the 4-byte EFI_VARIABLE_ATTRIBUTE header).
	return data[4] == 1
}

// checkKernelHardening reads dmesg_restrict and kptr_restrict proc settings.
func (m *FirmwareMonitor) checkKernelHardening(ctx context.Context) {
	checks := []struct {
		path      string
		indicator string
	}{
		{"/proc/sys/kernel/dmesg_restrict", "dmesg_restrict_disabled"},
		{"/proc/sys/kernel/kptr_restrict", "kptr_restrict_disabled"},
	}

	for _, c := range checks {
		data, err := os.ReadFile(c.path)
		if err != nil {
			continue
		}
		val := strings.TrimSpace(string(data))
		if val != "0" {
			continue
		}
		event := &common.HostEvent{
			EventType:  "kernel_hardening_disabled",
			Platform:   "linux",
			Hostname:   m.cfg.Hostname,
			Timestamp:  time.Now(),
			Indicators: []string{c.indicator},
			RawData: map[string]interface{}{
				"setting": c.path,
				"value":   val,
			},
		}
		select {
		case m.eventCh <- event:
		case <-ctx.Done():
			return
		}
	}
}

// emitEFIVariableModified emits an event when an EFI variable file changes.
func (m *FirmwareMonitor) emitEFIVariableModified(ctx context.Context, varPath string) {
	varName := filepath.Base(varPath)
	event := &common.HostEvent{
		EventType: "efi_variable_modified",
		Platform:  "linux",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		RawData: map[string]interface{}{
			"variable_name": varName,
			"variable_path": varPath,
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}
