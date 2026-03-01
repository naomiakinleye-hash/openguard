//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// procNetEntry holds a single row parsed from /proc/net/tcp (or udp, etc.).
type procNetEntry struct {
	localAddr  string
	localPort  uint16
	remoteAddr string
	remotePort uint16
	state      string
	inode      uint64
}

// tcpStateMap maps hex state values from /proc/net/tcp to human-readable strings.
var tcpStateMap = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

// NetworkMonitor watches /proc/net for network connection changes.
type NetworkMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	baseline map[string]common.NetworkConnection // key: "proto:localAddr:localPort:remoteAddr:remotePort"
	stopCh   chan struct{}
	mu       sync.RWMutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newNetworkMonitor creates a NetworkMonitor that sends events to eventCh.
func newNetworkMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *NetworkMonitor {
	return &NetworkMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		baseline: make(map[string]common.NetworkConnection),
		stopCh:   make(chan struct{}),
	}
}

// Start begins polling /proc/net at the configured interval.
func (m *NetworkMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	interval := m.cfg.PollInterval
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.poll(ctx)
			}
		}
	}()
	return nil
}

// Stop gracefully shuts down the NetworkMonitor.
func (m *NetworkMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll takes a snapshot of current connections and compares to baseline.
func (m *NetworkMonitor) poll(ctx context.Context) {
	current, err := m.snapshot()
	if err != nil {
		m.logger.Warn("linux: network snapshot", zap.Error(err))
		return
	}

	m.mu.Lock()
	last := m.baseline
	currentMap := make(map[string]common.NetworkConnection, len(current))
	for _, conn := range current {
		key := connKey(conn)
		currentMap[key] = conn
	}
	m.baseline = currentMap
	m.mu.Unlock()

	// Detect new connections.
	remoteIPCounts := make(map[uint32]map[string]struct{})
	for key, conn := range currentMap {
		if _, existed := last[key]; !existed {
			m.emitNetworkEvent(ctx, "connection_established", conn, nil)
			indicators := m.checkConnectionAnomalies(conn)
			if len(indicators) > 0 {
				m.emitNetworkEvent(ctx, "suspicious_connection", conn, indicators)
			}
			// Track remote IPs per PID for volume detection.
			if conn.RemoteAddr != "" && !common.IsLoopback(conn.RemoteAddr) {
				if remoteIPCounts[conn.PID] == nil {
					remoteIPCounts[conn.PID] = make(map[string]struct{})
				}
				remoteIPCounts[conn.PID][conn.RemoteAddr] = struct{}{}
			}
		}
	}

	// High-volume connection check.
	for pid, ips := range remoteIPCounts {
		if len(ips) > 50 {
			// Find a representative connection for this PID.
			for _, conn := range currentMap {
				if conn.PID == pid {
					m.emitNetworkEvent(ctx, "high_volume_connection", conn, []string{"high_volume_connection"})
					break
				}
			}
		}
	}

	// Detect closed connections.
	for key, conn := range last {
		if _, exists := currentMap[key]; !exists {
			m.emitNetworkEvent(ctx, "connection_closed", conn, nil)
		}
	}
}

// checkConnectionAnomalies returns indicators for suspicious connections.
func (m *NetworkMonitor) checkConnectionAnomalies(conn common.NetworkConnection) []string {
	var indicators []string

	// Suspicious remote port.
	if common.IsSuspiciousPort(conn.RemotePort) {
		indicators = append(indicators, "suspicious_remote_port")
	}

	// Non-browser process connecting to port 80/443 to external IP.
	if (conn.RemotePort == 80 || conn.RemotePort == 443) &&
		!common.IsPrivateRange(conn.RemoteAddr) && !common.IsLoopback(conn.RemoteAddr) &&
		!isBrowserProcess(conn.ProcessName) {
		indicators = append(indicators, "unexpected_http_connection")
	}

	// Known malicious process names.
	if isKnownMaliciousProcess(conn.ProcessName) {
		indicators = append(indicators, "known_malicious_process_network")
	}

	// Process from suspicious paths.
	if isSuspiciousLinuxPath(conn.ProcessName) {
		indicators = append(indicators, "suspicious_path_network")
	}

	// Headless process (no TTY) making outbound connections - checked via process name heuristic.
	// This is a best-effort check; full TTY detection requires /proc/[pid]/stat.
	if conn.Direction == "outbound" && isHeadlessProcess(conn.ProcessName) {
		indicators = append(indicators, "headless_process_network")
	}

	// Web server making outbound connection to non-local IP.
	if isWebServerProcess(conn.ProcessName) && conn.Direction == "outbound" &&
		!common.IsPrivateRange(conn.RemoteAddr) && !common.IsLoopback(conn.RemoteAddr) {
		indicators = append(indicators, "server_unexpected_outbound")
	}

	return indicators
}

// snapshot reads /proc/net files and returns all current connections.
func (m *NetworkMonitor) snapshot() ([]common.NetworkConnection, error) {
	inodeMap, err := m.buildInodeMap()
	if err != nil {
		m.logger.Debug("linux: build inode map (partial results expected)", zap.Error(err))
	}

	var conns []common.NetworkConnection

	files := []struct {
		path  string
		proto string
		ipv6  bool
	}{
		{"/proc/net/tcp", "tcp", false},
		{"/proc/net/tcp6", "tcp6", true},
		{"/proc/net/udp", "udp", false},
		{"/proc/net/udp6", "udp6", true},
	}

	for _, f := range files {
		entries, err := m.parseNetFile(f.path, f.proto)
		if err != nil {
			m.logger.Debug("linux: parse net file", zap.String("path", f.path), zap.Error(err))
			continue
		}
		for _, entry := range entries {
			pid := uint32(0)
			if entry.inode != 0 {
				if p, ok := inodeMap[entry.inode]; ok {
					pid = p
				}
			}
			procName := ""
			if pid != 0 {
				procName = readProcName(pid)
			}
			direction := "unknown"
			if entry.remoteAddr != "" && entry.remoteAddr != "0.0.0.0" && entry.remoteAddr != "::" {
				direction = "outbound"
			}
			conns = append(conns, common.NetworkConnection{
				PID:         pid,
				ProcessName: procName,
				Protocol:    f.proto,
				LocalAddr:   entry.localAddr,
				LocalPort:   entry.localPort,
				RemoteAddr:  entry.remoteAddr,
				RemotePort:  entry.remotePort,
				State:       entry.state,
				Direction:   direction,
			})
		}
	}
	return conns, nil
}

// parseNetFile parses a /proc/net/tcp (or similar) file.
func (m *NetworkMonitor) parseNetFile(path, proto string) ([]procNetEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("linux: open %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	isIPv6 := strings.HasSuffix(proto, "6")
	var entries []procNetEntry
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip header
		}
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		localAddr, localPort, err := parseHexAddr(fields[1], isIPv6)
		if err != nil {
			continue
		}
		remoteAddr, remotePort, err := parseHexAddr(fields[2], isIPv6)
		if err != nil {
			continue
		}
		stateHex := strings.ToUpper(fields[3])
		state := tcpStateMap[stateHex]
		if state == "" {
			state = stateHex
		}
		inode := uint64(0)
		if len(fields) > 9 {
			inode, _ = strconv.ParseUint(fields[9], 10, 64)
		}
		entries = append(entries, procNetEntry{
			localAddr:  localAddr,
			localPort:  localPort,
			remoteAddr: remoteAddr,
			remotePort: remotePort,
			state:      state,
			inode:      inode,
		})
	}
	return entries, scanner.Err()
}

// buildInodeMap scans /proc/[pid]/fd/ symlinks to map socket inodes to PIDs.
func (m *NetworkMonitor) buildInodeMap() (map[uint64]uint32, error) {
	inodeMap := make(map[uint64]uint32)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return inodeMap, fmt.Errorf("linux: readdir /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			// Permission errors are expected for processes owned by other users.
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// Socket symlinks look like "socket:[12345]".
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inodeStr := link[8 : len(link)-1]
				inode, err := strconv.ParseUint(inodeStr, 10, 64)
				if err != nil {
					continue
				}
				inodeMap[inode] = uint32(pid)
			}
		}
	}
	return inodeMap, nil
}

// parseHexAddr converts a /proc/net hex address:port to IP string and port number.
// The hex address is in little-endian format for IPv4.
func parseHexAddr(hexAddr string, isIPv6 bool) (string, uint16, error) {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid addr: %s", hexAddr)
	}

	portVal, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("parse port %s: %w", parts[1], err)
	}

	addrHex := parts[0]
	var ip string
	if isIPv6 {
		ip, err = parseIPv6HexAddr(addrHex)
		if err != nil {
			return "", 0, fmt.Errorf("parse ipv6 addr %s: %w", addrHex, err)
		}
	} else {
		b, err := hex.DecodeString(addrHex)
		if err != nil || len(b) != 4 {
			return "", 0, fmt.Errorf("parse ipv4 addr %s: %w", addrHex, err)
		}
		// IPv4 is stored little-endian.
		ip = fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}

	return ip, uint16(portVal), nil
}

// parseIPv6HexAddr converts a 32-character hex string from /proc/net/tcp6 to
// a colon-separated IPv6 address string.
// Each 4-byte group in the file is stored little-endian (reversed), so we
// read each group as a uint32 in little-endian order and then reorder the bytes.
func parseIPv6HexAddr(addrHex string) (string, error) {
	b, err := hex.DecodeString(addrHex)
	if err != nil || len(b) != 16 {
		return "", fmt.Errorf("decode: expected 16 bytes, got %d", len(b))
	}
	// IPv6 in /proc/net/tcp6 is stored as 4 little-endian 32-bit words.
	// Reorder bytes within each 4-byte group to get big-endian network order.
	var reordered [16]byte
	for i := 0; i < 4; i++ {
		reordered[i*4+0] = b[i*4+3]
		reordered[i*4+1] = b[i*4+2]
		reordered[i*4+2] = b[i*4+1]
		reordered[i*4+3] = b[i*4+0]
	}
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		uint16(reordered[0])<<8|uint16(reordered[1]),
		uint16(reordered[2])<<8|uint16(reordered[3]),
		uint16(reordered[4])<<8|uint16(reordered[5]),
		uint16(reordered[6])<<8|uint16(reordered[7]),
		uint16(reordered[8])<<8|uint16(reordered[9]),
		uint16(reordered[10])<<8|uint16(reordered[11]),
		uint16(reordered[12])<<8|uint16(reordered[13]),
		uint16(reordered[14])<<8|uint16(reordered[15]),
	), nil
}

// connKey returns a stable map key for a network connection.
func connKey(conn common.NetworkConnection) string {
	return fmt.Sprintf("%s:%s:%d:%s:%d", conn.Protocol, conn.LocalAddr, conn.LocalPort, conn.RemoteAddr, conn.RemotePort)
}

// readProcName reads the process name from /proc/<pid>/comm.
func readProcName(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// emitNetworkEvent sends a HostEvent for a network connection change.
func (m *NetworkMonitor) emitNetworkEvent(ctx context.Context, eventType string, conn common.NetworkConnection, indicators []string) {
	event := &common.HostEvent{
		EventType: eventType,
		Platform:  "linux",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		Process: &common.ProcessInfo{
			PID:  conn.PID,
			Name: conn.ProcessName,
		},
		Indicators: indicators,
		RawData: map[string]interface{}{
			"protocol":    conn.Protocol,
			"local_addr":  conn.LocalAddr,
			"local_port":  conn.LocalPort,
			"remote_addr": conn.RemoteAddr,
			"remote_port": conn.RemotePort,
			"state":       conn.State,
			"direction":   conn.Direction,
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// isBrowserProcess returns true if the process name matches a known browser.
func isBrowserProcess(name string) bool {
	browsers := []string{"firefox", "chrome", "chromium", "brave", "opera", "safari", "edge"}
	nameLower := strings.ToLower(name)
	for _, b := range browsers {
		if strings.Contains(nameLower, b) {
			return true
		}
	}
	return false
}

// isKnownMaliciousProcess returns true if the process name matches known malicious tools.
func isKnownMaliciousProcess(name string) bool {
	malicious := []string{"mimikatz", "meterpreter", "metasploit", "cobalt", "empire", "pwdump"}
	nameLower := strings.ToLower(name)
	for _, m := range malicious {
		if strings.Contains(nameLower, m) {
			return true
		}
	}
	return false
}

// isSuspiciousLinuxPath returns true if the process name hints at a suspicious path origin.
func isSuspiciousLinuxPath(name string) bool {
	// Process names from /tmp or hidden dirs are suspicious.
	return strings.HasPrefix(name, ".") || strings.Contains(name, "tmp")
}

// isHeadlessProcess returns true for processes that typically run without a TTY.
func isHeadlessProcess(name string) bool {
	headless := []string{"python", "python3", "perl", "ruby", "node", "php", "bash", "sh"}
	nameLower := strings.ToLower(name)
	for _, h := range headless {
		if nameLower == h {
			return true
		}
	}
	return false
}

// isWebServerProcess returns true for known web server process names.
func isWebServerProcess(name string) bool {
	servers := []string{"nginx", "apache2", "httpd", "php-fpm", "lighttpd"}
	nameLower := strings.ToLower(name)
	for _, s := range servers {
		if nameLower == s {
			return true
		}
	}
	return false
}
