//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// HiddenProcessScanner cross-references multiple process enumeration sources
// to detect rootkit-hidden processes.
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

// scan performs the cross-reference enumeration and emits hidden_process_detected events.
func (s *HiddenProcessScanner) scan(ctx context.Context) {
	// Source A: /proc readdir
	setA := s.enumProcReaddir()

	// Source B: brute-force kill(pid, 0)
	maxPID := s.readPIDMax()
	setB := s.enumBruteForce(maxPID)

	// Cross-reference: any PID in B but not A is potentially hidden.
	for pid := range setB {
		if _, inA := setA[pid]; inA {
			continue
		}
		// Confirm the process exists at kernel level but is absent from /proc readdir.
		exePath := s.tryReadExe(pid)
		if exePath == "" && !s.tryOpenMaps(pid) {
			// Cannot confirm existence; skip.
			continue
		}

		result := &common.HiddenProcessResult{
			PID:         pid,
			FoundBy:     []string{"brute_force_pid"},
			MissingFrom: []string{"proc_readdir"},
			ExePath:     exePath,
		}
		s.emit(ctx, result)
	}
}

// enumProcReaddir reads all numeric directories in /proc.
func (s *HiddenProcessScanner) enumProcReaddir() map[uint32]struct{} {
	pids := make(map[uint32]struct{})
	entries, err := os.ReadDir("/proc")
	if err != nil {
		s.logger.Warn("linux hidden: readdir /proc", zap.Error(err))
		return pids
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if pid, err := strconv.ParseUint(e.Name(), 10, 32); err == nil {
			pids[uint32(pid)] = struct{}{}
		}
	}
	return pids
}

// enumBruteForce probes PIDs 1..maxPID using kill(pid, 0).
func (s *HiddenProcessScanner) enumBruteForce(maxPID int) map[uint32]struct{} {
	pids := make(map[uint32]struct{})
	for pid := 1; pid <= maxPID; pid++ {
		err := syscall.Kill(pid, 0)
		if err == nil || err == syscall.EPERM {
			pids[uint32(pid)] = struct{}{}
		}
	}
	return pids
}

// readPIDMax reads /proc/sys/kernel/pid_max and caps at 65536 for performance.
func (s *HiddenProcessScanner) readPIDMax() int {
	data, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		return 65536
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || n > 65536 {
		return 65536
	}
	return n
}

// tryReadExe attempts to read /proc/<pid>/exe and returns the path if successful.
func (s *HiddenProcessScanner) tryReadExe(pid uint32) string {
	link := fmt.Sprintf("/proc/%d/exe", pid)
	path, err := os.Readlink(link)
	if err != nil {
		return ""
	}
	return path
}

// tryOpenMaps attempts to open /proc/<pid>/maps to confirm kernel-level existence.
func (s *HiddenProcessScanner) tryOpenMaps(pid uint32) bool {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		return false
	}
	syscall.Close(fd) //nolint:errcheck
	return true
}

// emit sends a hidden_process_detected HostEvent.
func (s *HiddenProcessScanner) emit(ctx context.Context, result *common.HiddenProcessResult) {
	event := &common.HostEvent{
		EventType: "hidden_process_detected",
		Platform:  "linux",
		Hostname:  s.cfg.Hostname,
		Timestamp: time.Now(),
		HiddenProcess: result,
		Indicators: []string{"hidden_process"},
	}
	select {
	case s.eventCh <- event:
	case <-ctx.Done():
	}
}
