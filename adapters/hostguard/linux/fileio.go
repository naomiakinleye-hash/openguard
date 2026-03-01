//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// FileMonitor watches sensitive paths for file I/O events using fanotify
// (when available) with inotify as a fallback for unprivileged environments.
type FileMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
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

// Start begins monitoring sensitive paths. It tries fanotify first, then falls
// back to inotify if fanotify is unavailable.
func (m *FileMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	if len(m.cfg.SensitivePathPrefixes) == 0 {
		cancel()
		return nil
	}

	// Try fanotify (requires CAP_SYS_ADMIN).
	fanFd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE)
	if err == nil {
		if markErr := m.markFanotifyPaths(fanFd); markErr != nil {
			m.logger.Warn("linux fileio: fanotify mark paths", zap.Error(markErr))
			unix.Close(fanFd) //nolint:errcheck
		} else {
			m.wg.Add(1)
			go m.fanotifyLoop(ctx, fanFd)
			return nil
		}
	} else {
		m.logger.Warn("linux fileio: fanotify unavailable, falling back to inotify", zap.Error(err))
	}

	// Fallback: inotify.
	inoFd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		cancel()
		return fmt.Errorf("linux fileio: inotify init: %w", err)
	}

	wds := m.addInotifyWatches(inoFd)
	if len(wds) == 0 {
		unix.Close(inoFd) //nolint:errcheck
		cancel()
		return nil
	}

	m.wg.Add(1)
	go m.inotifyLoop(ctx, inoFd, wds)
	return nil
}

// Stop gracefully shuts down the FileMonitor.
func (m *FileMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// markFanotifyPaths marks all sensitive paths with the relevant fanotify event mask.
func (m *FileMonitor) markFanotifyPaths(fd int) error {
	mask := uint64(unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_ONDIR)
	var lastErr error
	for _, path := range m.cfg.SensitivePathPrefixes {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM,
			mask, unix.AT_FDCWD, path); err != nil {
			// Try without FAN_MARK_FILESYSTEM for non-root mount points.
			if err2 := unix.FanotifyMark(fd, unix.FAN_MARK_ADD,
				mask, unix.AT_FDCWD, path); err2 != nil {
				m.logger.Warn("linux fileio: fanotify mark", zap.String("path", path), zap.Error(err2))
				lastErr = err2
			}
		}
	}
	return lastErr
}

// fanotifyLoop reads fanotify events and emits HostEvents.
func (m *FileMonitor) fanotifyLoop(ctx context.Context, fd int) {
	defer m.wg.Done()
	defer unix.Close(fd) //nolint:errcheck

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		tv := unix.Timeval{Sec: 1, Usec: 0}
		unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv) //nolint:errcheck

		n, err := unix.Read(fd, buf)
		if err != nil {
			if isTimeout(err) || err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				select {
				case <-ctx.Done():
					return
				case <-time.After(100 * time.Millisecond):
				}
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				m.logger.Warn("linux fileio: fanotify read", zap.Error(err))
				time.Sleep(500 * time.Millisecond)
				continue
			}
		}

		m.parseFanotifyEvents(ctx, buf[:n])
	}
}

// parseFanotifyEvents parses raw fanotify event metadata from buf.
func (m *FileMonitor) parseFanotifyEvents(ctx context.Context, buf []byte) {
	// FAN_EVENT_METADATA layout (struct fanotify_event_metadata):
	// event_len(4) vers(1) reserved(1) metadata_len(2) mask(8) fd(4) pid(4)
	const metaSize = 24
	offset := 0
	for offset+metaSize <= len(buf) {
		evLen := int(uint32(buf[offset]) | uint32(buf[offset+1])<<8 | uint32(buf[offset+2])<<16 | uint32(buf[offset+3])<<24)
		if evLen < metaSize || offset+evLen > len(buf) {
			break
		}
		mask := uint64(buf[offset+8]) | uint64(buf[offset+9])<<8 | uint64(buf[offset+10])<<16 | uint64(buf[offset+11])<<24 |
			uint64(buf[offset+12])<<32 | uint64(buf[offset+13])<<40 | uint64(buf[offset+14])<<48 | uint64(buf[offset+15])<<56
		evFd := int(int32(uint32(buf[offset+16]) | uint32(buf[offset+17])<<8 | uint32(buf[offset+18])<<16 | uint32(buf[offset+19])<<24))
		pid := uint32(buf[offset+20]) | uint32(buf[offset+21])<<8 | uint32(buf[offset+22])<<16 | uint32(buf[offset+23])<<24

		path := ""
		if evFd > 0 {
			path = fdToPath(evFd)
			unix.Close(evFd) //nolint:errcheck
		}

		if path != "" {
			op := fanotifyMaskToOp(mask)
			m.emitFileEvent(ctx, pid, path, op)
		}

		offset += evLen
	}
}

// fanotifyMaskToOp converts a fanotify event mask to a file operation string.
func fanotifyMaskToOp(mask uint64) string {
	if mask&unix.FAN_MODIFY != 0 || mask&unix.FAN_CLOSE_WRITE != 0 {
		return "write"
	}
	if mask&unix.FAN_OPEN != 0 {
		return "read"
	}
	return "read"
}

// fdToPath resolves a file descriptor to its path via /proc/self/fd/<n>.
func fdToPath(fd int) string {
	link := fmt.Sprintf("/proc/self/fd/%d", fd)
	path, err := os.Readlink(link)
	if err != nil {
		return ""
	}
	return path
}

// addInotifyWatches adds inotify watches for all sensitive paths.
// Returns a map from watch descriptor to path.
func (m *FileMonitor) addInotifyWatches(fd int) map[int32]string {
	wds := make(map[int32]string)
	mask := uint32(unix.IN_CREATE | unix.IN_DELETE | unix.IN_MODIFY | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_ATTRIB)
	for _, path := range m.cfg.SensitivePathPrefixes {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			// Add watch for the directory itself.
			wd, err := unix.InotifyAddWatch(fd, path, mask)
			if err != nil {
				m.logger.Warn("linux fileio: inotify add watch", zap.String("path", path), zap.Error(err))
				continue
			}
			wds[int32(wd)] = path
		} else {
			// Add watch for the parent directory.
			dir := filepath.Dir(path)
			wd, err := unix.InotifyAddWatch(fd, dir, mask)
			if err != nil {
				m.logger.Warn("linux fileio: inotify add watch", zap.String("path", dir), zap.Error(err))
				continue
			}
			wds[int32(wd)] = dir
		}
	}
	return wds
}

// inotifyLoop reads inotify events and emits HostEvents.
func (m *FileMonitor) inotifyLoop(ctx context.Context, fd int, wds map[int32]string) {
	defer m.wg.Done()
	defer unix.Close(fd) //nolint:errcheck

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				select {
				case <-ctx.Done():
					return
				case <-time.After(100 * time.Millisecond):
				}
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				m.logger.Warn("linux fileio: inotify read", zap.Error(err))
				time.Sleep(500 * time.Millisecond)
				continue
			}
		}

		m.parseInotifyEvents(ctx, buf[:n], wds)
	}
}

// parseInotifyEvents parses raw inotify events.
func (m *FileMonitor) parseInotifyEvents(ctx context.Context, buf []byte, wds map[int32]string) {
	// inotify_event: wd(4) mask(4) cookie(4) len(4) [name (len bytes)]
	const hdrSize = 16
	offset := 0
	for offset+hdrSize <= len(buf) {
		wd := int32(uint32(buf[offset]) | uint32(buf[offset+1])<<8 | uint32(buf[offset+2])<<16 | uint32(buf[offset+3])<<24)
		mask := uint32(buf[offset+4]) | uint32(buf[offset+5])<<8 | uint32(buf[offset+6])<<16 | uint32(buf[offset+7])<<24
		nameLen := int(uint32(buf[offset+12]) | uint32(buf[offset+13])<<8 | uint32(buf[offset+14])<<16 | uint32(buf[offset+15])<<24)

		name := ""
		if nameLen > 0 && offset+hdrSize+nameLen <= len(buf) {
			rawName := buf[offset+hdrSize : offset+hdrSize+nameLen]
			// null-terminated
			name = strings.TrimRight(string(rawName), "\x00")
		}

		dir := wds[wd]
		path := dir
		if name != "" {
			path = filepath.Join(dir, name)
		}

		if path != "" {
			op := inotifyMaskToOp(mask)
			m.emitFileEvent(ctx, 0, path, op) // PID not available from inotify
		}

		offset += hdrSize + nameLen
	}
}

// inotifyMaskToOp converts an inotify event mask to a file operation string.
func inotifyMaskToOp(mask uint32) string {
	switch {
	case mask&unix.IN_CREATE != 0:
		return "create"
	case mask&unix.IN_DELETE != 0:
		return "delete"
	case mask&unix.IN_MOVED_FROM != 0:
		return "rename"
	case mask&unix.IN_MOVED_TO != 0:
		return "rename"
	case mask&unix.IN_MODIFY != 0:
		return "write"
	case mask&unix.IN_ATTRIB != 0:
		return "chmod"
	default:
		return "read"
	}
}

// emitFileEvent builds and sends a HostEvent for a file I/O operation.
func (m *FileMonitor) emitFileEvent(ctx context.Context, pid uint32, path, op string) {
	procName := ""
	if pid > 0 {
		if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
			procName = strings.TrimSpace(string(comm))
		}
	}

	fileIO := &common.FileIOEvent{
		PID:         pid,
		ProcessName: procName,
		Path:        path,
		Operation:   op,
	}

	eventType := "file_modified"
	switch op {
	case "read":
		eventType = "file_access"
	case "create":
		eventType = "file_created"
	case "delete":
		eventType = "file_deleted"
	}

	event := &common.HostEvent{
		EventType: eventType,
		Platform:  "linux",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		FileIO:    fileIO,
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
		return
	}

	// Emit suspicious_file_access if the path matches a sensitive prefix.
	if m.isSensitivePath(path) {
		suspicious := &common.HostEvent{
			EventType:  "suspicious_file_access",
			Platform:   "linux",
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
}

// isSensitivePath returns true if the path starts with any configured sensitive prefix.
func (m *FileMonitor) isSensitivePath(path string) bool {
	for _, prefix := range m.cfg.SensitivePathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
