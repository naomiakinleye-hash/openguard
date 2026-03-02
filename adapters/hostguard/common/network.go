// Package hostguardcommon provides shared types and utilities for the HostGuard sensor.
package hostguardcommon

import (
	"net"
)

// NetworkConnection represents an active network connection associated with a process.
type NetworkConnection struct {
	PID         uint32
	ProcessName string
	Protocol    string // tcp, udp, tcp6, udp6
	LocalAddr   string
	LocalPort   uint16
	RemoteAddr  string
	RemotePort  uint16
	State       string // ESTABLISHED, LISTEN, TIME_WAIT, CLOSE_WAIT, etc.
	Direction   string // inbound, outbound, unknown
}

// NetworkEvent wraps a connection change for emission as a HostEvent.
// EventType will be one of: "connection_established", "connection_closed",
// "suspicious_connection", "high_volume_connection"
type NetworkEvent struct {
	Connection NetworkConnection
	EventType  string
	Indicators []string
}

// SuspiciousRemotePorts lists ports commonly used by C2 frameworks and malware.
var SuspiciousRemotePorts = []uint16{
	1337, 4444, 4445, 5555, 6666, 7777, 8888, 9999, 31337, 65535,
	1234, 2222, 3333, 6667, 6668, 6669, 1604, 8531, 5900, 9001,
}

// IsLoopback returns true if the address is a loopback address.
func IsLoopback(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// IsSuspiciousPort returns true if the port is in the suspicious ports list.
func IsSuspiciousPort(port uint16) bool {
	for _, p := range SuspiciousRemotePorts {
		if p == port {
			return true
		}
	}
	return false
}

// IsPrivateRange returns true if the address is in RFC1918 private ranges.
func IsPrivateRange(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
