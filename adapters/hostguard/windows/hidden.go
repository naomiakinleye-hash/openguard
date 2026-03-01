//go:build windows

// Package hostguardwindows implements the HostGuard sensor for Windows.
package hostguardwindows

import (
	"context"
	"fmt"
	"sync"
	"time"
	"unsafe"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"github.com/StackExchange/wmi"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

// HiddenProcessScanner cross-references multiple process enumeration sources
// to detect rootkit-hidden processes on Windows.
type HiddenProcessScanner struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newHiddenProcessScanner creates a HiddenProcessScanner.
func newHiddenProcessScanner(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *HiddenProcessScanner {
	return &HiddenProcessScanner{
		cfg:     cfg,
		eventCh: eventCh,
		logger:  logger,
	}
}

// Start begins periodic hidden process scanning.
func (s *HiddenProcessScanner) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel

	interval := s.cfg.HiddenScanInterval
	if interval <= 0 {
		interval = 60 * time.Second
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.scan(ctx)
			}
		}
	}()
	return nil
}

// Stop gracefully shuts down the scanner.
func (s *HiddenProcessScanner) Stop() {
	if s.cancelFn != nil {
		s.cancelFn()
	}
	s.wg.Wait()
}

// scan enumerates processes using multiple sources and emits events for hidden ones.
func (s *HiddenProcessScanner) scan(ctx context.Context) {
	// Source A: NtQuerySystemInformation (native NT API).
	setA, err := s.enumNtQuerySystemInformation()
	if err != nil {
		s.logger.Warn("windows hidden: NtQuerySystemInformation", zap.Error(err))
		return
	}

	// Source B: WMI Win32_Process.
	setB := s.enumWMI()

	// Source C: CreateToolhelp32Snapshot.
	setC := s.enumToolhelp()

	// PIDs in A but missing from B or C are potentially hidden.
	for pid := range setA {
		missingFrom := []string{}
		if _, ok := setB[pid]; !ok {
			missingFrom = append(missingFrom, "wmi")
		}
		if _, ok := setC[pid]; !ok {
			missingFrom = append(missingFrom, "toolhelp32")
		}
		if len(missingFrom) == 0 {
			continue
		}

		// Confirm existence at kernel level via OpenProcess.
		if !s.confirmProcess(pid) {
			continue
		}

		result := &common.HiddenProcessResult{
			PID:         pid,
			FoundBy:     []string{"nt_query_system_information"},
			MissingFrom: missingFrom,
		}
		s.emit(ctx, result)
	}
}

// systemProcessInformation is the structure returned by NtQuerySystemInformation
// for SystemProcessInformation (class 5). Only the fields we need are declared.
// The struct layout follows the Windows SDK definition.
type systemProcessInformation struct {
	NextEntryOffset              uint32
	NumberOfThreads              uint32
	_                            [6]int64 // reserved
	ImageName                    unicodeString
	BasePriority                 int32
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
	// ... remaining fields omitted
	_                            [44]byte
}

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

// enumNtQuerySystemInformation uses the native NT API to enumerate all processes.
func (s *HiddenProcessScanner) enumNtQuerySystemInformation() (map[uint32]struct{}, error) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQuerySystemInformation := ntdll.NewProc("NtQuerySystemInformation")

	const SystemProcessInformation = 5
	bufSize := uint32(1 << 20) // start with 1 MB
	buf := make([]byte, bufSize)

	for {
		var returnLength uint32
		status, _, _ := ntQuerySystemInformation.Call(
			uintptr(SystemProcessInformation),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&returnLength)),
		)

		const statusInfoLengthMismatch = 0xC0000004
		const statusBufferTooSmall = 0xC0000023
		if status == statusInfoLengthMismatch || status == statusBufferTooSmall {
			bufSize = returnLength + 4096
			buf = make([]byte, bufSize)
			continue
		}
		if status != 0 {
			return nil, fmt.Errorf("NtQuerySystemInformation status: 0x%x", status)
		}

		break
	}

	pids := make(map[uint32]struct{})
	offset := uintptr(0)
	for {
		if offset >= uintptr(len(buf)) {
			break
		}
		entry := (*systemProcessInformation)(unsafe.Pointer(&buf[offset]))
		pid := uint32(entry.UniqueProcessID)
		if pid > 0 {
			pids[pid] = struct{}{}
		}
		if entry.NextEntryOffset == 0 {
			break
		}
		offset += uintptr(entry.NextEntryOffset)
	}
	return pids, nil
}

// win32ProcessHidden is used for WMI enumeration in the hidden process scanner.
type win32ProcessHidden struct {
	ProcessID uint32
}

// enumWMI enumerates processes using WMI Win32_Process.
func (s *HiddenProcessScanner) enumWMI() map[uint32]struct{} {
	pids := make(map[uint32]struct{})
	var procs []win32ProcessHidden
	if err := wmi.Query("SELECT ProcessId FROM Win32_Process", &procs); err != nil {
		s.logger.Warn("windows hidden: WMI enumeration", zap.Error(err))
		return pids
	}
	for _, p := range procs {
		pids[p.ProcessID] = struct{}{}
	}
	return pids
}

// enumToolhelp enumerates processes using CreateToolhelp32Snapshot.
func (s *HiddenProcessScanner) enumToolhelp() map[uint32]struct{} {
	pids := make(map[uint32]struct{})
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		s.logger.Warn("windows hidden: CreateToolhelp32Snapshot", zap.Error(err))
		return pids
	}
	defer windows.CloseHandle(snapshot) //nolint:errcheck

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return pids
	}
	for {
		pids[entry.ProcessID] = struct{}{}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return pids
}

// confirmProcess attempts to open the process with limited query rights.
// Returns true if the process exists at kernel level.
func (s *HiddenProcessScanner) confirmProcess(pid uint32) bool {
	const processQueryLimitedInformation = 0x1000
	handle, err := windows.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return false
	}
	windows.CloseHandle(handle) //nolint:errcheck
	return true
}

// emit sends a hidden_process_detected HostEvent.
func (s *HiddenProcessScanner) emit(ctx context.Context, result *common.HiddenProcessResult) {
	event := &common.HostEvent{
		EventType:     "hidden_process_detected",
		Platform:      "windows",
		Hostname:      s.cfg.Hostname,
		Timestamp:     time.Now(),
		HiddenProcess: result,
		Indicators:    []string{"hidden_process"},
	}
	select {
	case s.eventCh <- event:
	case <-ctx.Done():
	}
}

