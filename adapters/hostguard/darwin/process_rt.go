//go:build darwin

// Package hostguarddarwin implements the HostGuard sensor for macOS.
package hostguarddarwin

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// RealtimeProcessMonitor uses kqueue EVFILT_PROC to receive kernel-pushed
// process lifecycle events. Because kqueue requires per-PID subscription, a
// background goroutine periodically discovers new PIDs and registers them.
// If kqueue is unavailable, it falls back to the polling ProcessMonitor.
type RealtimeProcessMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newRealtimeProcessMonitor creates a RealtimeProcessMonitor.
func newRealtimeProcessMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *RealtimeProcessMonitor {
	return &RealtimeProcessMonitor{
		cfg:     cfg,
		eventCh: eventCh,
		logger:  logger,
	}
}

// Start opens a kqueue and begins monitoring process events.
// Returns an error if kqueue cannot be used, so the caller can fall back.
func (m *RealtimeProcessMonitor) Start(ctx context.Context) error {
	kq, err := syscall.Kqueue()
	if err != nil {
		return fmt.Errorf("darwin realtime proc: kqueue: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	// Channel to pass newly discovered PIDs to the kqueue loop.
	newPIDCh := make(chan uint32, 256)

	m.wg.Add(2)
	go m.pidDiscoveryLoop(ctx, newPIDCh)
	go m.kqueueLoop(ctx, kq, newPIDCh)
	return nil
}

// Stop signals all goroutines and waits for them to exit.
func (m *RealtimeProcessMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// pidDiscoveryLoop periodically scans all PIDs using sysctl and sends new ones
// to the kqueue loop for registration.
func (m *RealtimeProcessMonitor) pidDiscoveryLoop(ctx context.Context, newPIDCh chan<- uint32) {
	defer m.wg.Done()
	known := make(map[uint32]struct{})
	ticker := time.NewTicker(m.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pids, err := listPIDsSysctl()
			if err != nil {
				m.logger.Warn("darwin realtime proc: list PIDs via sysctl", zap.Error(err))
				continue
			}
			for _, pid := range pids {
				if _, ok := known[pid]; !ok {
					known[pid] = struct{}{}
					select {
					case newPIDCh <- pid:
					case <-ctx.Done():
						return
					default:
					}
				}
			}
		}
	}
}

// kqueueLoop registers PIDs in the kqueue and waits for events.
func (m *RealtimeProcessMonitor) kqueueLoop(ctx context.Context, kq int, newPIDCh <-chan uint32) {
	defer m.wg.Done()
	defer syscall.Close(kq) //nolint:errcheck

	const noteExec = 0x20000000 // NOTE_EXEC
	const noteExit = 0x80000000 // NOTE_EXIT
	const noteFork = 0x40000000 // NOTE_FORK

	timeout := syscall.NsecToTimespec(int64(500 * time.Millisecond))
	events := make([]syscall.Kevent_t, 32)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Register any newly discovered PIDs.
		drainPIDs:
		for {
			select {
			case pid := <-newPIDCh:
				change := syscall.Kevent_t{
					Ident:  uint64(pid),
					Filter: syscall.EVFILT_PROC,
					Flags:  syscall.EV_ADD | syscall.EV_ONESHOT,
					Fflags: uint32(noteExec | noteExit | noteFork),
				}
				syscall.Kevent(kq, []syscall.Kevent_t{change}, nil, nil) //nolint:errcheck
			default:
				break drainPIDs
			}
		}

		n, err := syscall.Kevent(kq, nil, events, &timeout)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				m.logger.Warn("darwin realtime proc: kevent", zap.Error(err))
				time.Sleep(500 * time.Millisecond)
				continue
			}
		}

		for i := 0; i < n; i++ {
			ev := events[i]
			pid := uint32(ev.Ident)
			fflags := ev.Fflags

			if fflags&uint32(noteExec) != 0 {
				m.handleExec(ctx, pid)
			}
			if fflags&uint32(noteExit) != 0 {
				m.handleExit(ctx, pid)
			}
			if fflags&uint32(noteFork) != 0 {
				// The child PID is in the data field.
				childPID := uint32(ev.Data)
				if childPID > 0 {
					m.handleExec(ctx, childPID)
				}
			}
		}
	}
}

// handleExec collects process details via ps and emits process_created.
func (m *RealtimeProcessMonitor) handleExec(ctx context.Context, pid uint32) {
	info := collectProcDetails(pid)
	m.emit(ctx, "process_created", info, nil)
}

// handleExit emits a process_terminated event.
func (m *RealtimeProcessMonitor) handleExit(ctx context.Context, pid uint32) {
	info := &common.ProcessInfo{PID: pid}
	m.emit(ctx, "process_terminated", info, nil)
}

// collectProcDetails runs ps to get process information for a single PID.
func collectProcDetails(pid uint32) *common.ProcessInfo {
	cmd := exec.Command("ps", "-o", "pid=,ppid=,comm=,command=", "-p", strconv.FormatUint(uint64(pid), 10))
	out, err := cmd.Output()
	if err != nil {
		return &common.ProcessInfo{PID: pid}
	}
	scanner := bytes.NewReader(out)
	var buf [4096]byte
	n, _ := scanner.Read(buf[:])
	line := strings.TrimSpace(string(buf[:n]))
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return &common.ProcessInfo{PID: pid}
	}
	ppid, _ := strconv.ParseUint(fields[1], 10, 32)
	comm := fields[2]
	cmdLine := ""
	if len(fields) > 3 {
		cmdLine = strings.Join(fields[3:], " ")
	}
	return &common.ProcessInfo{
		PID:     pid,
		PPID:    uint32(ppid),
		Name:    comm,
		ExePath: comm,
		CmdLine: cmdLine,
	}
}

// emit sends a HostEvent onto the event channel.
func (m *RealtimeProcessMonitor) emit(ctx context.Context, eventType string, info *common.ProcessInfo, rawData map[string]interface{}) {
	event := &common.HostEvent{
		EventType: eventType,
		Platform:  "darwin",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		Process:   info,
		RawData:   rawData,
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// listPIDsSysctl returns all active PIDs from kern.proc.all via sysctl.
func listPIDsSysctl() ([]uint32, error) {
	// kern.proc.all (KERN_PROC_ALL = 0) returns an array of kinfo_proc.
	// We use syscall.SysctlRaw to get the raw bytes and parse PIDs.
	buf, err := unix.SysctlRaw("kern.proc.all")
	if err != nil {
		return nil, fmt.Errorf("sysctl kern.proc.all: %w", err)
	}

	// struct kinfo_proc is 648 bytes on Darwin arm64/amd64.
	// The PID is at offset 40 (p_pid field in struct extern_proc at start of kinfo_proc).
	const kinfoProcSize = 648
	const pidOffset = 40

	if len(buf) < kinfoProcSize {
		return nil, nil
	}

	var pids []uint32
	for offset := 0; offset+kinfoProcSize <= len(buf); offset += kinfoProcSize {
		// pid_t is int32, little-endian on Darwin.
		pidBytes := buf[offset+pidOffset : offset+pidOffset+4]
		pid := int32(uint32(pidBytes[0]) | uint32(pidBytes[1])<<8 | uint32(pidBytes[2])<<16 | uint32(pidBytes[3])<<24)
		if pid > 0 {
			pids = append(pids, uint32(pid))
		}
	}
	return pids, nil
}

