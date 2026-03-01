//go:build windows

// Package hostguardwindows implements the HostGuard sensor for Windows.
package hostguardwindows

import (
	"context"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// FileMonitor watches sensitive paths for file I/O events using a dedicated
// ETW session subscribed to the Microsoft-Windows-Kernel-File provider.
//
// Provider GUID: {EDD08927-9CC4-4E65-B970-C2560FB5C289}
//
// Monitored Event IDs:
//
//	12 (Create), 13 (Cleanup), 14 (Close), 15 (Read), 16 (Write),
//	17 (SetInfo), 18 (Delete), 19 (Rename), 26 (QueryInfo), 27 (FSControl)
type FileMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	session  interface{} // ETW session handle
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

// Start attempts to start the ETW file I/O session.
// If unavailable (e.g. not Administrator), it logs a warning and returns nil
// so that the rest of the sensor can continue.
func (m *FileMonitor) Start(ctx context.Context) error {
	if len(m.cfg.SensitivePathPrefixes) == 0 {
		return nil
	}

	session, err := startETWSession("OpenGuard-HostGuard-FileTrace")
	if err != nil {
		m.logger.Warn("windows fileio: ETW file session unavailable", zap.Error(err))
		return nil // graceful degradation — don't block the sensor
	}
	m.session = session

	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	m.wg.Add(1)
	go m.processEvents(ctx, session)
	return nil
}

// Stop shuts down the ETW file monitor.
func (m *FileMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	stopETWSession(m.session)
	m.wg.Wait()
}

// processEvents reads ETW events from the session and dispatches file I/O events.
func (m *FileMonitor) processEvents(ctx context.Context, session interface{}) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			evt, ok := readNextETWEvent(session)
			if !ok {
				select {
				case <-ctx.Done():
					return
				case <-time.After(1 * time.Millisecond):
				}
				continue
			}
			m.handleFileEvent(ctx, evt)
		}
	}
}

// handleFileEvent processes a single ETW event from the kernel file provider.
func (m *FileMonitor) handleFileEvent(ctx context.Context, evt etwEvent) {
	path := evt.imageFileName
	if path == "" {
		return
	}
	if !m.isSensitivePath(path) {
		return
	}

	op := fileEventIDToOp(evt.eventID)
	eventType := fileOpToEventType(op)

	fileIO := &common.FileIOEvent{
		PID:       evt.pid,
		Path:      path,
		Operation: op,
	}

	event := &common.HostEvent{
		EventType: eventType,
		Platform:  "windows",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		FileIO:    fileIO,
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
		return
	}

	// Emit suspicious_file_access for sensitive paths.
	suspicious := &common.HostEvent{
		EventType:  "suspicious_file_access",
		Platform:   "windows",
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

// fileEventIDToOp maps a Kernel-File ETW event ID to a file operation string.
func fileEventIDToOp(eventID uint16) string {
	switch eventID {
	case 12:
		return "create"
	case 13, 14:
		return "read"
	case 15:
		return "read"
	case 16:
		return "write"
	case 17:
		return "chmod"
	case 18:
		return "delete"
	case 19:
		return "rename"
	default:
		return "read"
	}
}

// fileOpToEventType maps an operation string to a HostEvent EventType.
func fileOpToEventType(op string) string {
	switch op {
	case "create":
		return "file_created"
	case "delete":
		return "file_deleted"
	case "write", "rename", "chmod":
		return "file_modified"
	default:
		return "file_access"
	}
}

// isSensitivePath returns true if the path starts with any configured sensitive prefix.
func (m *FileMonitor) isSensitivePath(path string) bool {
	pathLower := strings.ToLower(path)
	for _, prefix := range m.cfg.SensitivePathPrefixes {
		if strings.HasPrefix(pathLower, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}
