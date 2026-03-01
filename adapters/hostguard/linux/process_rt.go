//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// netlinkProcEventHeader mirrors the kernel cn_msg + proc_event header.
// We use raw byte parsing rather than cgo to avoid build-tag complications.
const (
	netlinkConnector = 11 // NETLINK_CONNECTOR
	cnIdxProc        = 1  // CN_IDX_PROC
	cnValProc        = 1  // CN_VAL_PROC

	procEventNone  = 0x00000000
	procEventFork  = 0x00000001
	procEventExec  = 0x00000002
	procEventUID   = 0x00000004
	procEventExit  = 0x80000000
)

// RealtimeProcessMonitor uses the Linux netlink connector (proc_event) to
// receive kernel-pushed process lifecycle events with zero polling latency.
// If the netlink socket cannot be opened due to insufficient privileges, it
// falls back gracefully to the polling-based ProcessMonitor.
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

// Start opens the netlink connector socket and begins receiving proc_event messages.
// Returns an error if the socket cannot be opened (e.g. insufficient privileges).
func (m *RealtimeProcessMonitor) Start(ctx context.Context) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, netlinkConnector)
	if err != nil {
		return fmt.Errorf("linux realtime proc: netlink socket: %w", err)
	}

	addr := unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Pid:    uint32(os.Getpid()),
		Groups: 1,
	}
	if err := unix.Bind(fd, &addr); err != nil {
		unix.Close(fd) //nolint:errcheck
		return fmt.Errorf("linux realtime proc: bind netlink: %w", err)
	}

	// Send subscription message to enable proc events.
	if err := sendSubscribeMsg(fd, true); err != nil {
		unix.Close(fd) //nolint:errcheck
		return fmt.Errorf("linux realtime proc: subscribe: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	m.wg.Add(1)
	go m.readLoop(ctx, fd)
	return nil
}

// Stop signals the read loop to exit and waits for it.
func (m *RealtimeProcessMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// readLoop reads netlink messages and dispatches proc_event payloads.
func (m *RealtimeProcessMonitor) readLoop(ctx context.Context, fd int) {
	defer m.wg.Done()
	defer unix.Close(fd) //nolint:errcheck

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set a short read deadline so we can check ctx.Done periodically.
		tv := unix.Timeval{Sec: 1, Usec: 0}
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			m.logger.Warn("linux realtime proc: set receive timeout", zap.Error(err))
		}

		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				m.logger.Warn("linux realtime proc: recvfrom", zap.Error(err))
				continue
			}
		}
		m.handleNetlinkMsg(ctx, buf[:n])
	}
}

// handleNetlinkMsg parses a raw netlink message and dispatches the proc_event.
// Netlink message layout: nlmsghdr (16 bytes) | cn_msg (20 bytes) | proc_event data
func (m *RealtimeProcessMonitor) handleNetlinkMsg(ctx context.Context, msg []byte) {
	const nlHdrSize = 16
	const cnMsgSize = 20
	const minSize = nlHdrSize + cnMsgSize + 4 // at least 4 bytes for event what

	if len(msg) < minSize {
		return
	}

	// Skip nlmsghdr (16 bytes) and cn_msg header (20 bytes).
	payload := msg[nlHdrSize+cnMsgSize:]
	if len(payload) < 8 {
		return
	}

	// proc_event.what is the first uint32 (little-endian).
	what := uint32(payload[0]) | uint32(payload[1])<<8 | uint32(payload[2])<<16 | uint32(payload[3])<<24

	switch what {
	case procEventExec:
		// exec_proc_event: what(4) + cpu(4) + timestamp_ns(8) + process_pid(4) + process_tgid(4)
		if len(payload) < 24 {
			return
		}
		pid := uint32(payload[16]) | uint32(payload[17])<<8 | uint32(payload[18])<<16 | uint32(payload[19])<<24
		m.handleExecEvent(ctx, pid)

	case procEventExit:
		// exit_proc_event: what(4) + cpu(4) + timestamp_ns(8) + process_pid(4) + process_tgid(4) + exit_code(4) + exit_signal(4)
		if len(payload) < 28 {
			return
		}
		pid := uint32(payload[16]) | uint32(payload[17])<<8 | uint32(payload[18])<<16 | uint32(payload[19])<<24
		exitCode := uint32(payload[24]) | uint32(payload[25])<<8 | uint32(payload[26])<<16 | uint32(payload[27])<<24
		m.handleExitEvent(ctx, pid, exitCode)

	case procEventUID:
		// id_proc_event: what(4) + cpu(4) + timestamp_ns(8) + process_pid(4) + process_tgid(4) + ruid(4) + euid(4)
		if len(payload) < 32 {
			return
		}
		pid := uint32(payload[16]) | uint32(payload[17])<<8 | uint32(payload[18])<<16 | uint32(payload[19])<<24
		ruid := uint32(payload[24]) | uint32(payload[25])<<8 | uint32(payload[26])<<16 | uint32(payload[27])<<24
		euid := uint32(payload[28]) | uint32(payload[29])<<8 | uint32(payload[30])<<16 | uint32(payload[31])<<24
		if euid == 0 && ruid != 0 {
			m.handlePrivEscEvent(ctx, pid, ruid)
		}
	}
}

// handleExecEvent reads /proc/<pid>/* and emits a process_created event.
func (m *RealtimeProcessMonitor) handleExecEvent(ctx context.Context, pid uint32) {
	snap, err := readProcInfo(pid)
	if err != nil {
		return
	}
	m.emit(ctx, "process_created", &snap.info, nil)
}

// handleExitEvent emits a process_terminated event.
func (m *RealtimeProcessMonitor) handleExitEvent(ctx context.Context, pid uint32, exitCode uint32) {
	info := &common.ProcessInfo{PID: pid}
	m.emit(ctx, "process_terminated", info, map[string]interface{}{
		"exit_code": exitCode,
	})
}

// handlePrivEscEvent emits a privilege_escalation event.
func (m *RealtimeProcessMonitor) handlePrivEscEvent(ctx context.Context, pid uint32, oldUID uint32) {
	snap, err := readProcInfo(pid)
	if err != nil {
		snap = processSnapshot{info: common.ProcessInfo{PID: pid}}
	}
	m.emit(ctx, "privilege_escalation", &snap.info, map[string]interface{}{
		"old_uid": oldUID,
		"new_uid": uint32(0),
	})
}

// emit sends a HostEvent onto the event channel.
func (m *RealtimeProcessMonitor) emit(ctx context.Context, eventType string, info *common.ProcessInfo, rawData map[string]interface{}) {
	event := &common.HostEvent{
		EventType: eventType,
		Platform:  "linux",
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

// sendSubscribeMsg sends a cn_msg to subscribe/unsubscribe from proc events.
func sendSubscribeMsg(fd int, subscribe bool) error {
	// Build: nlmsghdr | cn_msg | uint32(op)
	const nlHdrSize = 16
	const cnMsgSize = 20
	const opSize = 4
	totalSize := nlHdrSize + cnMsgSize + opSize

	buf := make([]byte, totalSize)

	// nlmsghdr: len(4) + type(2) + flags(2) + seq(4) + pid(4)
	putUint32LE(buf[0:], uint32(totalSize))
	putUint16LE(buf[4:], syscall.NLMSG_DONE)
	// flags, seq, pid = 0

	// cn_msg: idx(4) + val(4) + seq(4) + ack(4) + len(2) + flags(2)
	putUint32LE(buf[nlHdrSize:], cnIdxProc)
	putUint32LE(buf[nlHdrSize+4:], cnValProc)
	putUint16LE(buf[nlHdrSize+16:], uint16(opSize))

	// op: PROC_CN_MCAST_LISTEN(1) or PROC_CN_MCAST_IGNORE(2)
	op := uint32(2)
	if subscribe {
		op = 1
	}
	putUint32LE(buf[nlHdrSize+cnMsgSize:], op)

	sa := unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	return unix.Sendto(fd, buf, 0, &sa)
}

func putUint32LE(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func putUint16LE(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "timeout") ||
		strings.Contains(err.Error(), "would block") ||
		err == syscall.EAGAIN ||
		err == syscall.EWOULDBLOCK
}

// Ensure syscall package is used by sendSubscribeMsg.
var _ = syscall.NLMSG_DONE
