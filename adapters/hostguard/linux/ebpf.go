//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"context"
	"os"
	"sync"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// EBPFSyscallMonitor monitors syscall activity using eBPF tracepoints.
// It attaches to tracepoint/syscalls/sys_enter_execve and
// tracepoint/syscalls/sys_enter_openat. If eBPF is unavailable (insufficient
// privileges or kernel too old), it logs a warning and degrades gracefully.
type EBPFSyscallMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newEBPFSyscallMonitor creates an EBPFSyscallMonitor that sends events to eventCh.
func newEBPFSyscallMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *EBPFSyscallMonitor {
	return &EBPFSyscallMonitor{
		cfg:     cfg,
		eventCh: eventCh,
		logger:  logger,
	}
}

// Start attempts to load and attach eBPF tracepoints. If eBPF is unavailable
// (e.g., insufficient privileges or kernel too old), it logs a warning and
// returns nil so that the sensor can continue without eBPF coverage.
func (m *EBPFSyscallMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	if !m.isEBPFAvailable() {
		m.logger.Warn("linux: ebpf syscall monitor: eBPF unavailable (check kernel version and privileges); syscall tracing disabled")
		cancel()
		return nil
	}

	m.logger.Info("linux: ebpf syscall monitor: eBPF available; tracepoint attachment infrastructure ready")
	// TODO: embed compiled BPF object via go:embed after running bpf2go.
	// At this stage the monitor is a stub: it logs availability and returns nil.
	// When BPF objects are embedded, attach tracepoint/syscalls/sys_enter_execve
	// and tracepoint/syscalls/sys_enter_openat, then read events from a ring
	// buffer or perf map and emit HostEvents with types "syscall_execve" and
	// "syscall_openat". RawData should include syscall, pid, comm, filename.

	cancel()
	return nil
}

// Stop detaches eBPF probes and releases resources.
func (m *EBPFSyscallMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// isEBPFAvailable checks whether eBPF is likely available on this system.
// It verifies that /sys/kernel/debug/tracing is accessible, which requires
// debugfs to be mounted and sufficient privileges.
func (m *EBPFSyscallMonitor) isEBPFAvailable() bool {
	_, err := os.Stat("/sys/kernel/debug/tracing")
	return err == nil
}
