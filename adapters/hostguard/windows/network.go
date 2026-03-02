//go:build windows

// Package hostguardwindows implements the HostGuard sensor for Windows.
package hostguardwindows

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unsafe"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

// MIB_TCPROW2 maps to the Windows MIB_TCPROW2 structure.
type mibTCPRow2 struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
	OffloadState uint32
}

// MIB_UDPROW_OWNER_PID maps to the Windows MIB_UDPROW_OWNER_PID structure.
type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

// tcpStateWindowsMap maps Windows TCP state values to strings.
var tcpStateWindowsMap = map[uint32]string{
	1:  "CLOSED",
	2:  "LISTEN",
	3:  "SYN_SENT",
	4:  "SYN_RCVD",
	5:  "ESTABLISHED",
	6:  "FIN_WAIT1",
	7:  "FIN_WAIT2",
	8:  "CLOSE_WAIT",
	9:  "CLOSING",
	10: "LAST_ACK",
	11: "TIME_WAIT",
	12: "DELETE_TCB",
}

// lazy-loaded iphlpapi.dll functions.
var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
	afInet              = 2  // AF_INET
	afInet6             = 23 // AF_INET6
)

// mibTCP6RowOwnerPID maps to the Windows MIB_TCP6ROW_OWNER_PID structure.
type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

// mibUDP6RowOwnerPID maps to the Windows MIB_UDP6ROW_OWNER_PID structure.
type mibUDP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPID    uint32
}

// NetworkMonitor watches Windows network connections using iphlpapi.dll.
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

// poll takes a snapshot and emits events for changes.
func (m *NetworkMonitor) poll(ctx context.Context) {
	current, err := m.snapshot()
	if err != nil {
		m.logger.Warn("windows: network snapshot", zap.Error(err))
		return
	}

	m.mu.Lock()
	last := m.baseline
	currentMap := make(map[string]common.NetworkConnection, len(current))
	for _, conn := range current {
		key := windowsConnKey(conn)
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

// snapshot returns the current TCP and UDP connections using iphlpapi.dll.
func (m *NetworkMonitor) snapshot() ([]common.NetworkConnection, error) {
	var conns []common.NetworkConnection

	tcpConns, err := getExtendedTCPTable()
	if err != nil {
		m.logger.Debug("windows: GetExtendedTcpTable", zap.Error(err))
	} else {
		conns = append(conns, tcpConns...)
	}

	tcp6Conns, err := getExtendedTCP6Table()
	if err != nil {
		m.logger.Debug("windows: GetExtendedTcpTable IPv6", zap.Error(err))
	} else {
		conns = append(conns, tcp6Conns...)
	}

	udpConns, err := getExtendedUDPTable()
	if err != nil {
		m.logger.Debug("windows: GetExtendedUdpTable", zap.Error(err))
	} else {
		conns = append(conns, udpConns...)
	}

	udp6Conns, err := getExtendedUDP6Table()
	if err != nil {
		m.logger.Debug("windows: GetExtendedUdpTable IPv6", zap.Error(err))
	} else {
		conns = append(conns, udp6Conns...)
	}

	return conns, nil
}

// getExtendedTCPTable calls GetExtendedTcpTable to get TCP connections with PID.
func getExtendedTCPTable() ([]common.NetworkConnection, error) {
	var size uint32
	// First call to get required buffer size.
	ret, _, _ := procGetExtendedTcpTable.Call(
		0, uintptr(unsafe.Pointer(&size)), 1, afInet, tcpTableOwnerPIDAll, 0,
	)
	// ERROR_INSUFFICIENT_BUFFER = 122
	if ret != 122 && ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable size query: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, afInet, tcpTableOwnerPIDAll, 0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable: %d", ret)
	}

	count := binary.LittleEndian.Uint32(buf[0:4])
	var conns []common.NetworkConnection
	rowSize := uint32(unsafe.Sizeof(mibTCPRow2{}))
	for i := uint32(0); i < count; i++ {
		offset := 4 + i*rowSize
		if offset+rowSize > uint32(len(buf)) {
			break
		}
		row := (*mibTCPRow2)(unsafe.Pointer(&buf[offset]))
		// In MIB_TCPROW2 the port is stored as a big-endian (network byte order)
		// uint16 in the lower 16 bits of a uint32 field. ntohs converts it to
		// host byte order.
		localAddr := uint32ToIP(row.LocalAddr)
		remoteAddr := uint32ToIP(row.RemoteAddr)
		localPort := uint16(ntohs(uint16(row.LocalPort & 0xFFFF)))
		remotePort := uint16(ntohs(uint16(row.RemotePort & 0xFFFF)))
		state := tcpStateWindowsMap[row.State]
		direction := "unknown"
		if remoteAddr != "0.0.0.0" {
			direction = "outbound"
		}
		conns = append(conns, common.NetworkConnection{
			PID:        row.OwningPID,
			Protocol:   "tcp",
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			State:      state,
			Direction:  direction,
		})
	}
	return conns, nil
}

// getExtendedUDPTable calls GetExtendedUdpTable to get UDP connections with PID.
func getExtendedUDPTable() ([]common.NetworkConnection, error) {
	var size uint32
	ret, _, _ := procGetExtendedUdpTable.Call(
		0, uintptr(unsafe.Pointer(&size)), 1, afInet, udpTableOwnerPID, 0,
	)
	if ret != 122 && ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable size query: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, afInet, udpTableOwnerPID, 0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable: %d", ret)
	}

	count := binary.LittleEndian.Uint32(buf[0:4])
	var conns []common.NetworkConnection
	rowSize := uint32(unsafe.Sizeof(mibUDPRowOwnerPID{}))
	for i := uint32(0); i < count; i++ {
		offset := 4 + i*rowSize
		if offset+rowSize > uint32(len(buf)) {
			break
		}
		row := (*mibUDPRowOwnerPID)(unsafe.Pointer(&buf[offset]))
		localAddr := uint32ToIP(row.LocalAddr)
		// In MIB_UDPROW_OWNER_PID the port is stored as a big-endian (network byte order)
		// uint16 in the lower 16 bits of a uint32 field.
		localPort := uint16(ntohs(uint16(row.LocalPort & 0xFFFF)))
		conns = append(conns, common.NetworkConnection{
			PID:       row.OwningPID,
			Protocol:  "udp",
			LocalAddr: localAddr,
			LocalPort: localPort,
			Direction: "unknown",
		})
	}
	return conns, nil
}

// uint32ToIP converts a uint32 (network byte order) to an IP address string.
func uint32ToIP(addr uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, addr)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

// bytesToIPv6 converts a 16-byte array to a normalized IPv6 address string.
func bytesToIPv6(b [16]byte) string {
	return net.IP(b[:]).String()
}

// getExtendedTCP6Table calls GetExtendedTcpTable with AF_INET6 to get IPv6 TCP connections.
func getExtendedTCP6Table() ([]common.NetworkConnection, error) {
	var size uint32
	ret, _, _ := procGetExtendedTcpTable.Call(
		0, uintptr(unsafe.Pointer(&size)), 1, afInet6, tcpTableOwnerPIDAll, 0,
	)
	if ret != 122 && ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable IPv6 size query: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, afInet6, tcpTableOwnerPIDAll, 0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable IPv6: %d", ret)
	}

	count := binary.LittleEndian.Uint32(buf[0:4])
	var conns []common.NetworkConnection
	rowSize := uint32(unsafe.Sizeof(mibTCP6RowOwnerPID{}))
	for i := uint32(0); i < count; i++ {
		offset := 4 + i*rowSize
		if offset+rowSize > uint32(len(buf)) {
			break
		}
		row := (*mibTCP6RowOwnerPID)(unsafe.Pointer(&buf[offset]))
		localAddr := bytesToIPv6(row.LocalAddr)
		remoteAddr := bytesToIPv6(row.RemoteAddr)
		localPort := uint16(ntohs(uint16(row.LocalPort)))
		remotePort := uint16(ntohs(uint16(row.RemotePort)))
		state := tcpStateWindowsMap[row.State]
		direction := "unknown"
		ip := net.ParseIP(remoteAddr)
		if ip != nil && !ip.IsUnspecified() {
			direction = "outbound"
		}
		conns = append(conns, common.NetworkConnection{
			PID:        row.OwningPID,
			Protocol:   "tcp6",
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			State:      state,
			Direction:  direction,
		})
	}
	return conns, nil
}

// getExtendedUDP6Table calls GetExtendedUdpTable with AF_INET6 to get IPv6 UDP connections.
func getExtendedUDP6Table() ([]common.NetworkConnection, error) {
	var size uint32
	ret, _, _ := procGetExtendedUdpTable.Call(
		0, uintptr(unsafe.Pointer(&size)), 1, afInet6, udpTableOwnerPID, 0,
	)
	if ret != 122 && ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable IPv6 size query: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, afInet6, udpTableOwnerPID, 0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable IPv6: %d", ret)
	}

	count := binary.LittleEndian.Uint32(buf[0:4])
	var conns []common.NetworkConnection
	rowSize := uint32(unsafe.Sizeof(mibUDP6RowOwnerPID{}))
	for i := uint32(0); i < count; i++ {
		offset := 4 + i*rowSize
		if offset+rowSize > uint32(len(buf)) {
			break
		}
		row := (*mibUDP6RowOwnerPID)(unsafe.Pointer(&buf[offset]))
		localAddr := bytesToIPv6(row.LocalAddr)
		localPort := uint16(ntohs(uint16(row.LocalPort)))
		conns = append(conns, common.NetworkConnection{
			PID:       row.OwningPID,
			Protocol:  "udp6",
			LocalAddr: localAddr,
			LocalPort: localPort,
			Direction: "unknown",
		})
	}
	return conns, nil
}

// ntohs converts a uint16 from network byte order to host byte order.
func ntohs(n uint16) uint16 {
	return (n>>8)&0xff | (n&0xff)<<8
}

// windowsConnKey returns a stable map key for a network connection.
func windowsConnKey(conn common.NetworkConnection) string {
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
		!isWindowsBrowserProcess(conn.ProcessName) {
		indicators = append(indicators, "unexpected_http_connection")
	}

	if isKnownMaliciousWindowsProcess(conn.ProcessName) {
		indicators = append(indicators, "known_malicious_process_network")
	}

	if isSuspiciousWindowsPath(conn.ProcessName) {
		indicators = append(indicators, "suspicious_path_network")
	}

	return indicators
}

// emitNetworkEvent sends a HostEvent for a network connection change.
func (m *NetworkMonitor) emitNetworkEvent(ctx context.Context, eventType string, conn common.NetworkConnection, indicators []string) {
	event := &common.HostEvent{
		EventType: eventType,
		Platform:  "windows",
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

func isWindowsBrowserProcess(name string) bool {
	browsers := []string{"chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe", "brave.exe"}
	nameLower := strings.ToLower(name)
	for _, b := range browsers {
		if nameLower == b {
			return true
		}
	}
	return false
}

func isKnownMaliciousWindowsProcess(name string) bool {
	malicious := []string{"mimikatz", "meterpreter", "metasploit", "cobalt", "empire", "pwdump"}
	nameLower := strings.ToLower(name)
	for _, mal := range malicious {
		if strings.Contains(nameLower, mal) {
			return true
		}
	}
	return false
}

func isSuspiciousWindowsPath(name string) bool {
	nameLower := strings.ToLower(name)
	// Check for literal path fragments; environment variables are not expanded
	// in process names returned by Windows APIs.
	suspiciousPaths := []string{`\temp\`, `\appdata\`, `\users\`}
	for _, sp := range suspiciousPaths {
		if strings.Contains(nameLower, sp) {
			return true
		}
	}
	return false
}
