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
	"go.uber.org/zap"
)

// ETWProcessMonitor provides zero-latency process creation/termination events
// by subscribing to the Microsoft-Windows-Kernel-Process ETW provider.
//
// Provider GUID: {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
//
// If the ETW session cannot be started (e.g. insufficient privileges), the
// monitor logs a warning and callers should fall back to the polling-based
// ProcessMonitor.
type ETWProcessMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	session  interface{} // ETW session handle (opaque to avoid cgo dependency)
	stopCh   chan struct{}
	wg       sync.WaitGroup
	cancelFn context.CancelFunc
}

// newETWProcessMonitor creates an ETWProcessMonitor that sends events to eventCh.
func newETWProcessMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *ETWProcessMonitor {
	return &ETWProcessMonitor{
		cfg:     cfg,
		eventCh: eventCh,
		logger:  logger,
		stopCh:  make(chan struct{}),
	}
}

// Start attempts to start the ETW session. Returns an error if the session
// cannot be opened (e.g. the process is not running as Administrator).
// On success it launches a background goroutine to process ETW events.
func (m *ETWProcessMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	session, err := startETWSession("OpenGuard-HostGuard-ProcessTrace")
	if err != nil {
		cancel()
		return err
	}
	m.session = session

	m.wg.Add(1)
	go m.processEvents(ctx, session)
	return nil
}

// Stop signals the ETW processing goroutine to exit and waits for it.
func (m *ETWProcessMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	stopETWSession(m.session)
	m.wg.Wait()
}

// processEvents reads events from the ETW session and dispatches them.
func (m *ETWProcessMonitor) processEvents(ctx context.Context, session interface{}) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			evt, ok := readNextETWEvent(session)
			if !ok {
				// Session closed or no events; yield.
				select {
				case <-ctx.Done():
					return
				case <-time.After(1 * time.Millisecond):
				}
				continue
			}
			m.handleETWEvent(ctx, evt)
		}
	}
}

// etwEvent carries the fields extracted from a raw ETW event record.
type etwEvent struct {
	eventID          uint16
	pid              uint32
	ppid             uint32
	imageFileName    string
	commandLine      string
	parentImageName  string
	exitCode         uint32
}

// handleETWEvent processes a single ETW event from the kernel process provider.
func (m *ETWProcessMonitor) handleETWEvent(ctx context.Context, evt etwEvent) {
	switch evt.eventID {
	case 1: // Process Start
		info := &common.ProcessInfo{
			PID:     evt.pid,
			PPID:    evt.ppid,
			Name:    evt.imageFileName,
			ExePath: evt.imageFileName,
			CmdLine: evt.commandLine,
		}
		m.emitEvent(ctx, "process_created", info, nil)
		// Immediate anomaly check — no need to wait for poll interval.
		if indicators := m.checkETWAnomalies(evt); len(indicators) > 0 {
			m.emitEvent(ctx, "process_anomaly", info, indicators)
		}

	case 2: // Process Stop
		info := &common.ProcessInfo{
			PID:  evt.pid,
			Name: evt.imageFileName,
		}
		m.emitEvent(ctx, "process_terminated", info, map[string]interface{}{
			"exit_code": evt.exitCode,
		})
	}
}

// checkETWAnomalies inspects an ETW process start event for anomaly indicators.
func (m *ETWProcessMonitor) checkETWAnomalies(evt etwEvent) []string {
	var indicators []string

	exeLower := strings.ToLower(evt.imageFileName)

	// Suspicious path check.
	suspiciousPaths := append(m.cfg.SuspiciousPaths, `%temp%`, `%appdata%`, `c:\users`, `c:\windows\temp`)
	for _, sp := range suspiciousPaths {
		if strings.Contains(exeLower, strings.ToLower(sp)) {
			indicators = append(indicators, "suspicious_path")
			break
		}
	}

	// Masquerading: known system binary running from wrong path.
	if strings.EqualFold(evt.imageFileName, "svchost.exe") &&
		!strings.Contains(exeLower, `c:\windows\system32`) {
		indicators = append(indicators, "masquerading")
	}

	// Unusual parent-child: shell spawned by browser or Office.
	if isWindowsShell(evt.imageFileName) && isWindowsOfficeOrBrowser(evt.parentImageName) {
		indicators = append(indicators, "unusual_parent_child")
	}

	return indicators
}

// emitEvent sends a HostEvent onto the event channel, optionally merging extra raw data.
func (m *ETWProcessMonitor) emitEvent(ctx context.Context, eventType string, info *common.ProcessInfo, rawData interface{}) {
	event := &common.HostEvent{
		EventType: eventType,
		Platform:  "windows",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		Process:   info,
	}
	if rd, ok := rawData.(map[string]interface{}); ok {
		event.RawData = rd
	}
	if ind, ok := rawData.([]string); ok {
		event.Indicators = ind
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// ─── ETW session stubs ───────────────────────────────────────────────────────
//
// The functions below are thin wrappers around the Windows ETW API.
// They are implemented here as stubs that return errors, because the Go
// standard library does not expose ETW APIs directly and adding a cgo or
// external dependency would change the module graph.
//
// In a production build these would be replaced with real ETW calls using
// the Windows trace API (OpenTrace / ProcessTrace / CloseTrace) via
// golang.org/x/sys/windows or a dedicated ETW library such as
// github.com/bi-zone/etw.

// startETWSession opens an ETW real-time session for the
// Microsoft-Windows-Kernel-Process provider.
// Returns an opaque session handle or an error if the session cannot be opened
// (e.g. insufficient privileges).
func startETWSession(name string) (interface{}, error) {
	// Stub: ETW requires Administrator privileges and a real ETW library.
	// Return an error so the sensor falls back to polling.
	return nil, errETWUnavailable
}

// stopETWSession closes an ETW session returned by startETWSession.
func stopETWSession(session interface{}) {}

// readNextETWEvent reads the next available event from the session.
// Returns (event, true) if an event is available, or (zero, false) otherwise.
func readNextETWEvent(session interface{}) (etwEvent, bool) {
	return etwEvent{}, false
}

// errETWUnavailable is returned when ETW cannot be initialised.
// This is expected on non-Administrator processes.
// TODO: Replace the stub implementation above with a real ETW session using
// github.com/bi-zone/etw or golang.org/x/sys/windows to call
// OpenTrace/ProcessTrace/CloseTrace before using this in production.
var errETWUnavailable = fmt.Errorf("windows: ETW session requires Administrator privileges")
