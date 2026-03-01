//go:build windows

// Package hostguardwindows implements the HostGuard sensor for Windows.
package hostguardwindows

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// etwSessionHandle holds the state for an active ETW trace session.
type etwSessionHandle struct {
	name      string
	traceHandle windows.Handle
	eventCh   chan etwEvent
	stopOnce  sync.Once
	stopCh    chan struct{}
}

// ─── Windows ETW API declarations ────────────────────────────────────────────

var (
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procStartTrace    = advapi32.NewProc("StartTraceW")
	procStopTrace     = advapi32.NewProc("StopTraceW")
	procEnableTraceEx2 = advapi32.NewProc("EnableTraceEx2")
	procOpenTrace     = advapi32.NewProc("OpenTraceW")
	procProcessTrace  = advapi32.NewProc("ProcessTrace")
	procCloseTrace    = advapi32.NewProc("CloseTrace")
)

// EVENT_TRACE_PROPERTIES is a subset of the Windows EVENT_TRACE_PROPERTIES structure.
// We use a flat byte buffer because the full layout is complex and varies with
// the appended session/log-file name strings.
type eventTraceProperties struct {
	wnode              [48]byte  // WNODE_HEADER (48 bytes)
	bufferSize         uint32
	minBuffers         uint32
	maxBuffers         uint32
	maximumFileSize    uint32
	logFileMode        uint32
	flushTimer         uint32
	enableFlags        uint32
	_                  [4]byte // AgeLimit
	numberOfBuffers    uint32
	freeBuffers        uint32
	eventsLost         uint32
	buffersWritten     uint32
	logBuffersLost     uint32
	realTimeBuffersLost uint32
	loggerThreadID     uintptr
	logFileNameOffset  uint32
	loggerNameOffset   uint32
}

const (
	// EVENT_TRACE_REAL_TIME_MODE enables real-time event delivery.
	eventTraceRealTimeMode = 0x00000100
	// WNODE_FLAG_TRACED_GUID marks the session as a traced GUID session.
	wnodeFlagTracedGUID = 0x00020000
)

// Microsoft-Windows-Kernel-Process provider GUID:
// {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
var kernelProcessProviderGUID = windows.GUID{
	Data1: 0x22fb2cd6,
	Data2: 0x0e7b,
	Data3: 0x422b,
	Data4: [8]byte{0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16},
}

// EVENT_TRACE_LOGFILE (simplified) used by OpenTrace.
// The full structure is complex; we only fill in the fields we need.
const eventTraceLogfileSize = 1024

// startETWSession opens a real-time ETW trace session for the
// Microsoft-Windows-Kernel-Process provider.
// Returns an opaque session handle or an error if insufficient privileges.
func startETWSession(name string) (interface{}, error) {
	handle := &etwSessionHandle{
		name:    name,
		eventCh: make(chan etwEvent, 256),
		stopCh:  make(chan struct{}),
	}

	// Build the EVENT_TRACE_PROPERTIES buffer.
	// Layout: eventTraceProperties struct + two UTF-16 name strings.
	nameBuf, err := windows.UTF16FromString(name)
	if err != nil {
		return nil, fmt.Errorf("etw: encode session name: %w", err)
	}
	nameBytes := unsafe.Slice((*byte)(unsafe.Pointer(&nameBuf[0])), len(nameBuf)*2)

	// Total buffer size: struct + logger name + log file name (empty).
	const loggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	bufSize := loggerNameOffset + uint32(len(nameBytes)) + 2 // +2 for empty logfile name
	buf := make([]byte, bufSize)

	// Fill WNODE_HEADER: BufferSize (first 4 bytes of wnode).
	*(*uint32)(unsafe.Pointer(&buf[0])) = bufSize

	// WNODE_HEADER.Flags (offset 20 in WNODE_HEADER).
	*(*uint32)(unsafe.Pointer(&buf[20])) = wnodeFlagTracedGUID

	// eventTraceProperties offsets (after WNODE_HEADER = 48 bytes).
	const propsBase = 48
	// LogFileMode
	*(*uint32)(unsafe.Pointer(&buf[propsBase+16])) = eventTraceRealTimeMode
	// LoggerNameOffset
	*(*uint32)(unsafe.Pointer(&buf[propsBase+60])) = loggerNameOffset
	// LogFileNameOffset = 0 (no log file, real-time mode)
	*(*uint32)(unsafe.Pointer(&buf[propsBase+56])) = 0

	// Copy the session name into the buffer.
	copy(buf[loggerNameOffset:], nameBytes)

	var traceHandle windows.Handle
	namePtr, _ := windows.UTF16PtrFromString(name)
	r, _, _ := procStartTrace.Call(
		uintptr(unsafe.Pointer(&traceHandle)),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if r != 0 {
		return nil, fmt.Errorf("etw: StartTrace failed: error code %d (may require Administrator privileges)", r)
	}
	handle.traceHandle = traceHandle

	// Enable the Kernel-Process provider.
	r, _, _ = procEnableTraceEx2.Call(
		uintptr(traceHandle),
		uintptr(unsafe.Pointer(&kernelProcessProviderGUID)),
		1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
		0, // level: all
		0, // matchAnyKeyword
		0, // matchAllKeyword
		0, // timeout
		0, // enableParameters
	)
	if r != 0 {
		// Non-fatal: session is open but provider may not be fully enabled.
		_ = r
	}

	return handle, nil
}

// stopETWSession closes an ETW session returned by startETWSession.
func stopETWSession(session interface{}) {
	h, ok := session.(*etwSessionHandle)
	if !ok || h == nil {
		return
	}
	h.stopOnce.Do(func() {
		close(h.stopCh)
		namePtr, _ := windows.UTF16PtrFromString(h.name)
		procCloseTrace.Call(uintptr(h.traceHandle))  //nolint:errcheck
		procStopTrace.Call(uintptr(h.traceHandle), uintptr(unsafe.Pointer(namePtr)), 0) //nolint:errcheck
	})
}

// readNextETWEvent reads the next available event from the session.
// Returns (event, true) if available, (zero, false) otherwise.
func readNextETWEvent(session interface{}) (etwEvent, bool) {
	h, ok := session.(*etwSessionHandle)
	if !ok || h == nil {
		return etwEvent{}, false
	}
	select {
	case evt := <-h.eventCh:
		return evt, true
	case <-h.stopCh:
		return etwEvent{}, false
	case <-time.After(1 * time.Millisecond):
		return etwEvent{}, false
	}
}

