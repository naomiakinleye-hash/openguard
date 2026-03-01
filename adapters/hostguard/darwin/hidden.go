//go:build darwin

// Package hostguarddarwin implements the HostGuard sensor for macOS.
package hostguarddarwin

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// HiddenProcessScanner cross-references multiple process enumeration sources
// to detect rootkit-hidden processes on macOS.
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
	// Source A: ps -axo pid=
	setA := s.enumPS()
	// Source B: sysctl kern.proc.all
	setB := s.enumSysctl()
	// Source C: brute-force kill -0 for PIDs 1..10000
	setC := s.enumBruteForce(10000)

	// PIDs in B or C not in A are potentially hidden.
	candidates := make(map[uint32]struct{})
	for pid := range setB {
		if _, inA := setA[pid]; !inA {
			candidates[pid] = struct{}{}
		}
	}
	for pid := range setC {
		if _, inA := setA[pid]; !inA {
			candidates[pid] = struct{}{}
		}
	}

	for pid := range candidates {
		foundBy := []string{}
		missingFrom := []string{"ps"}
		if _, ok := setB[pid]; ok {
			foundBy = append(foundBy, "sysctl")
		}
		if _, ok := setC[pid]; ok {
			foundBy = append(foundBy, "brute_force_pid")
		}
		result := &common.HiddenProcessResult{
			PID:         pid,
			FoundBy:     foundBy,
			MissingFrom: missingFrom,
		}
		s.emit(ctx, result)
	}
}

// enumPS runs ps -axo pid= and returns the set of PIDs.
func (s *HiddenProcessScanner) enumPS() map[uint32]struct{} {
	pids := make(map[uint32]struct{})
	out, err := exec.Command("ps", "-axo", "pid=").Output()
	if err != nil {
		s.logger.Warn("darwin hidden: ps enumeration", zap.Error(err))
		return pids
	}
	scanner := bytes.NewReader(out)
	buf := make([]byte, len(out))
	n, _ := scanner.Read(buf)
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, err := strconv.ParseUint(line, 10, 32)
		if err == nil {
			pids[uint32(pid)] = struct{}{}
		}
	}
	return pids
}

// enumSysctl returns the set of PIDs from kern.proc.all.
func (s *HiddenProcessScanner) enumSysctl() map[uint32]struct{} {
	pids := make(map[uint32]struct{})
	pidList, err := listPIDsSysctl()
	if err != nil {
		s.logger.Warn("darwin hidden: sysctl enumeration", zap.Error(err))
		return pids
	}
	for _, pid := range pidList {
		pids[pid] = struct{}{}
	}
	return pids
}

// enumBruteForce probes PIDs 1..max using kill(pid, 0).
func (s *HiddenProcessScanner) enumBruteForce(max int) map[uint32]struct{} {
	pids := make(map[uint32]struct{})
	for pid := 1; pid <= max; pid++ {
		err := syscall.Kill(pid, 0)
		if err == nil || err == syscall.EPERM {
			pids[uint32(pid)] = struct{}{}
		}
	}
	return pids
}

// emit sends a hidden_process_detected HostEvent.
func (s *HiddenProcessScanner) emit(ctx context.Context, result *common.HiddenProcessResult) {
	event := &common.HostEvent{
		EventType:     "hidden_process_detected",
		Platform:      "darwin",
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

