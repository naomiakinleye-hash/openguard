//go:build darwin

// Package hostguarddarwin implements the HostGuard sensor for macOS.
package hostguarddarwin

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// lsofEntry holds a single connection record parsed from lsof output.
type lsofEntry struct {
	pid      uint32
	command  string
	proto    string
	local    string
	remote   string
	state    string
}

// NetworkMonitor watches network connections on macOS using lsof/netstat.
type NetworkMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	baseline map[string]common.NetworkConnection
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

// Start begins polling network connections at the configured interval.
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
		m.logger.Warn("darwin: network snapshot", zap.Error(err))
		return
	}

	m.mu.Lock()
	last := m.baseline
	currentMap := make(map[string]common.NetworkConnection, len(current))
	for _, conn := range current {
		key := darwinConnKey(conn)
		currentMap[key] = conn
	}
	m.baseline = currentMap
	m.mu.Unlock()

	remoteIPCounts := make(map[uint32]map[string]struct{})
	for key, conn := range currentMap {
		if _, existed := last[key]; !existed {
			m.emitNetworkEvent(ctx, "connection_established", conn, nil)
			indicators := m.checkConnectionAnomalies(conn)
			if len(indicators) > 0 {
				m.emitNetworkEvent(ctx, "suspicious_connection", conn, indicators)
			}
			if conn.RemoteAddr != "" && !common.IsLoopback(conn.RemoteAddr) {
				if remoteIPCounts[conn.PID] == nil {
					remoteIPCounts[conn.PID] = make(map[string]struct{})
				}
				remoteIPCounts[conn.PID][conn.RemoteAddr] = struct{}{}
			}
		}
	}

	for pid, ips := range remoteIPCounts {
		if len(ips) > 50 {
			for _, conn := range currentMap {
				if conn.PID == pid {
					m.emitNetworkEvent(ctx, "high_volume_connection", conn, []string{"high_volume_connection"})
					break
				}
			}
		}
	}

	for key, conn := range last {
		if _, exists := currentMap[key]; !exists {
			m.emitNetworkEvent(ctx, "connection_closed", conn, nil)
		}
	}
}

// snapshot returns a list of current connections using lsof (falling back to netstat).
func (m *NetworkMonitor) snapshot() ([]common.NetworkConnection, error) {
	conns, err := m.snapshotLsof()
	if err != nil {
		m.logger.Debug("darwin: lsof unavailable, falling back to netstat", zap.Error(err))
		return m.snapshotNetstat()
	}
	return conns, nil
}

// snapshotLsof parses lsof -i -n -P -F pcnT output.
func (m *NetworkMonitor) snapshotLsof() ([]common.NetworkConnection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "lsof", "-i", "-n", "-P", "-F", "pcnTP")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("darwin: lsof: %w", err)
	}

	var conns []common.NetworkConnection
	var current lsofEntry
	hasPID := false

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}
		field := line[0]
		value := line[1:]

		switch field {
		case 'p':
			// New process record — emit previous if valid.
			if hasPID && current.local != "" {
				if conn, ok := parseLsofEntry(current); ok {
					conns = append(conns, conn)
				}
			}
			pid, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				hasPID = false
				continue
			}
			current = lsofEntry{pid: uint32(pid)}
			hasPID = true
		case 'c':
			current.command = value
		case 'P':
			current.proto = strings.ToLower(value)
		case 'n':
			if strings.Contains(value, "->") {
				parts := strings.SplitN(value, "->", 2)
				current.local = strings.TrimSpace(parts[0])
				current.remote = strings.TrimSpace(parts[1])
			} else {
				current.local = value
			}
		case 'T':
			if strings.HasPrefix(value, "ST=") {
				current.state = value[3:]
			}
		}
	}
	// Emit last record.
	if hasPID && current.local != "" {
		if conn, ok := parseLsofEntry(current); ok {
			conns = append(conns, conn)
		}
	}
	return conns, scanner.Err()
}

// parseLsofEntry converts an lsofEntry to a NetworkConnection.
func parseLsofEntry(e lsofEntry) (common.NetworkConnection, bool) {
	localAddr, localPort := splitAddrPort(e.local)
	remoteAddr, remotePort := splitAddrPort(e.remote)

	direction := "unknown"
	if remoteAddr != "" {
		direction = "outbound"
	}

	return common.NetworkConnection{
		PID:         e.pid,
		ProcessName: e.command,
		Protocol:    e.proto,
		LocalAddr:   localAddr,
		LocalPort:   localPort,
		RemoteAddr:  remoteAddr,
		RemotePort:  remotePort,
		State:       e.state,
		Direction:   direction,
	}, true
}

// snapshotNetstat parses netstat output as a fallback.
func (m *NetworkMonitor) snapshotNetstat() ([]common.NetworkConnection, error) {
	var conns []common.NetworkConnection
	for _, args := range [][]string{
		{"-anv", "-p", "tcp"},
		{"-anv", "-p", "udp"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, "netstat", args...)
		out, err := cmd.Output()
		cancel()
		if err != nil {
			continue
		}
		proto := "tcp"
		if args[len(args)-1] == "udp" {
			proto = "udp"
		}
		parsed := parseNetstatOutput(out, proto)
		conns = append(conns, parsed...)
	}
	return conns, nil
}

// parseNetstatOutput parses netstat -anv output lines.
func parseNetstatOutput(out []byte, proto string) []common.NetworkConnection {
	var conns []common.NetworkConnection
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		// netstat output: Proto Recv-Q Send-Q Local-Address Foreign-Address State
		p := strings.ToLower(fields[0])
		if !strings.HasPrefix(p, proto) {
			continue
		}
		localAddr, localPort := splitAddrPort(fields[3])
		remoteAddr, remotePort := splitAddrPort(fields[4])
		state := ""
		if len(fields) > 5 {
			state = fields[5]
		}
		direction := "unknown"
		if remoteAddr != "" && remoteAddr != "*" && remoteAddr != "0.0.0.0" {
			direction = "outbound"
		}
		conns = append(conns, common.NetworkConnection{
			Protocol:   proto,
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			State:      state,
			Direction:  direction,
		})
	}
	return conns
}

// splitAddrPort splits an address:port string into address and port components.
// Handles IPv6 addresses in bracket notation [::1]:8080.
func splitAddrPort(addrPort string) (string, uint16) {
	if addrPort == "" || addrPort == "*" {
		return addrPort, 0
	}
	// IPv6 bracket notation.
	if strings.HasPrefix(addrPort, "[") {
		end := strings.LastIndex(addrPort, "]")
		if end < 0 {
			return addrPort, 0
		}
		addr := addrPort[1:end]
		rest := addrPort[end+1:]
		if strings.HasPrefix(rest, ":") {
			p, _ := strconv.ParseUint(rest[1:], 10, 16)
			return addr, uint16(p)
		}
		return addr, 0
	}
	// IPv4 or hostname.
	idx := strings.LastIndex(addrPort, ":")
	if idx < 0 {
		return addrPort, 0
	}
	addr := addrPort[:idx]
	p, _ := strconv.ParseUint(addrPort[idx+1:], 10, 16)
	return addr, uint16(p)
}

// darwinConnKey returns a stable map key for a network connection.
func darwinConnKey(conn common.NetworkConnection) string {
	return fmt.Sprintf("%s:%s:%d:%s:%d", conn.Protocol, conn.LocalAddr, conn.LocalPort, conn.RemoteAddr, conn.RemotePort)
}

// checkConnectionAnomalies returns indicators for suspicious connections.
func (m *NetworkMonitor) checkConnectionAnomalies(conn common.NetworkConnection) []string {
	var indicators []string

	if common.IsSuspiciousPort(conn.RemotePort) {
		indicators = append(indicators, "suspicious_remote_port")
	}

	if (conn.RemotePort == 80 || conn.RemotePort == 443) &&
		!common.IsPrivateRange(conn.RemoteAddr) && !common.IsLoopback(conn.RemoteAddr) &&
		!isDarwinBrowserProcess(conn.ProcessName) {
		indicators = append(indicators, "unexpected_http_connection")
	}

	if isKnownMaliciousDarwinProcess(conn.ProcessName) {
		indicators = append(indicators, "known_malicious_process_network")
	}

	if isSuspiciousDarwinPath(conn.ProcessName) {
		indicators = append(indicators, "suspicious_path_network")
	}

	return indicators
}

// emitNetworkEvent sends a HostEvent for a network connection change.
func (m *NetworkMonitor) emitNetworkEvent(ctx context.Context, eventType string, conn common.NetworkConnection, indicators []string) {
	event := &common.HostEvent{
		EventType: eventType,
		Platform:  "darwin",
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

func isDarwinBrowserProcess(name string) bool {
	browsers := []string{
		"com.apple.WebKit.WebContent", "firefox", "chrome", "Safari",
		"Chromium", "brave", "opera",
	}
	for _, b := range browsers {
		if strings.EqualFold(name, b) || strings.Contains(name, b) {
			return true
		}
	}
	return false
}

func isKnownMaliciousDarwinProcess(name string) bool {
	malicious := []string{"mimikatz", "meterpreter", "metasploit", "cobalt", "empire", "pwdump"}
	nameLower := strings.ToLower(name)
	for _, m := range malicious {
		if strings.Contains(nameLower, m) {
			return true
		}
	}
	return false
}

func isSuspiciousDarwinPath(name string) bool {
	// Process names that originate from suspicious paths.
	suspicious := []string{"/tmp/", "Downloads/", "/var/folders/"}
	for _, s := range suspicious {
		if strings.Contains(name, s) {
			return true
		}
	}
	return false
}
