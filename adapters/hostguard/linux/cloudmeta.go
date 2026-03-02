//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// imdsIP is the well-known link-local IP for cloud instance metadata services
// (AWS, GCP, Azure, DigitalOcean all use 169.254.169.254).
const imdsIP = "169.254.169.254"

// imdsHexIP is the little-endian hex representation of 169.254.169.254 as it
// appears in /proc/net/tcp. Each IPv4 address byte (169=0xA9, 254=0xFE) is stored
// in little-endian order, producing bytes [0xFE, 0xA9, 0xFE, 0xA9] → "FEA9FEA9".
const imdsHexIP = "FEA9FEA9"

// cloudAgentAllowlist is the set of process names known to legitimately access
// the cloud instance metadata service.
var cloudAgentAllowlist = map[string]bool{
	"cloud-init":                      true,
	"amazon-ssm-agent":                true,
	"google_metadata_script_runner":   true,
	"waagent":                         true,
	"do-agent":                        true,
}

// CloudMetadataMonitor watches /proc/net/tcp for outbound connections to cloud
// instance metadata service endpoints and flags unexpected processes.
type CloudMetadataMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
	// seen tracks recently reported (pid, remote) pairs to reduce duplicate events.
	seen map[string]struct{}
	mu   sync.Mutex
}

// newCloudMetadataMonitor creates a CloudMetadataMonitor that sends events to eventCh.
func newCloudMetadataMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *CloudMetadataMonitor {
	return &CloudMetadataMonitor{
		cfg:     cfg,
		eventCh: eventCh,
		logger:  logger,
		seen:    make(map[string]struct{}),
	}
}

// Start begins polling /proc/net/tcp at the configured interval.
func (m *CloudMetadataMonitor) Start(ctx context.Context) error {
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

// Stop gracefully shuts down the CloudMetadataMonitor.
func (m *CloudMetadataMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll scans /proc/net/tcp for connections to the IMDS address.
func (m *CloudMetadataMonitor) poll(ctx context.Context) {
	inodeMap, err := buildCloudInodeMap()
	if err != nil {
		m.logger.Debug("linux: cloud meta monitor: build inode map", zap.Error(err))
	}

	conns, err := m.parseIMDSConnections(inodeMap)
	if err != nil {
		m.logger.Warn("linux: cloud meta monitor: parse /proc/net/tcp", zap.Error(err))
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, c := range conns {
		key := fmt.Sprintf("%d:%s", c.pid, c.remoteAddr)
		if _, already := m.seen[key]; already {
			continue
		}
		m.seen[key] = struct{}{}
		m.emitCloudMetaEvent(ctx, c)
	}
}

// imdsConn holds information about a detected IMDS connection.
type imdsConn struct {
	pid        uint32
	procName   string
	remoteAddr string
	remotePort uint16
}

// parseIMDSConnections scans /proc/net/tcp for connections to the IMDS IP.
func (m *CloudMetadataMonitor) parseIMDSConnections(inodeMap map[uint64]uint32) ([]imdsConn, error) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return nil, fmt.Errorf("open /proc/net/tcp: %w", err)
	}
	defer f.Close() //nolint:errcheck

	var conns []imdsConn
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		// fields[2] is the remote address in hex (little-endian IP:port).
		remoteHex := strings.ToUpper(fields[2])
		parts := strings.SplitN(remoteHex, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] != imdsHexIP {
			continue
		}
		// Parse remote port.
		portVal := uint16(0)
		if p, err := parseHexUint16(parts[1]); err == nil {
			portVal = p
		}
		// Resolve inode → PID.
		inode := uint64(0)
		if len(fields) > 9 {
			if n, err := parseUint64(fields[9]); err == nil {
				inode = n
			}
		}
		pid := uint32(0)
		if inode != 0 {
			if p, ok := inodeMap[inode]; ok {
				pid = p
			}
		}
		procName := ""
		if pid != 0 {
			procName = readProcName(pid)
		}
		conns = append(conns, imdsConn{
			pid:        pid,
			procName:   procName,
			remoteAddr: imdsIP,
			remotePort: portVal,
		})
	}
	return conns, scanner.Err()
}

// emitCloudMetaEvent emits a cloud metadata access event.
// Caller must hold m.mu.
func (m *CloudMetadataMonitor) emitCloudMetaEvent(ctx context.Context, c imdsConn) {
	eventType := "cloud_metadata_access"
	indicators := []string{}

	if c.procName != "" && !cloudAgentAllowlist[c.procName] {
		eventType = "suspicious_cloud_metadata_access"
		indicators = append(indicators, "imds_abuse")
	}

	event := &common.HostEvent{
		EventType: eventType,
		Platform:  "linux",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		Process: &common.ProcessInfo{
			PID:  c.pid,
			Name: c.procName,
		},
		Indicators: indicators,
		RawData: map[string]interface{}{
			"pid":          c.pid,
			"process_name": c.procName,
			"destination":  fmt.Sprintf("%s:%d", c.remoteAddr, c.remotePort),
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// buildCloudInodeMap builds a map of socket inode → PID from /proc/[pid]/fd/.
func buildCloudInodeMap() (map[uint64]uint32, error) {
	inodeMap := make(map[uint64]uint32)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return inodeMap, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := parseUint64(entry.Name())
		if err != nil {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inodeStr := link[8 : len(link)-1]
				if inode, err := parseUint64(inodeStr); err == nil {
					inodeMap[inode] = uint32(pid)
				}
			}
		}
	}
	return inodeMap, nil
}

// parseHexUint16 parses a hex string representing a port number to uint16.
// The string is expected to be exactly 4 hex characters (e.g., "0050" for port 80).
func parseHexUint16(s string) (uint16, error) {
	if len(s) > 4 {
		return 0, fmt.Errorf("hex string too long: %q", s)
	}
	// Zero-pad to 4 characters on the left.
	padded := fmt.Sprintf("%04s", s)
	// Replace any spaces introduced by fmt.Sprintf right-padding with zeros.
	padded = strings.ReplaceAll(padded, " ", "0")
	b, err := hex.DecodeString(padded)
	if err != nil || len(b) != 2 {
		return 0, fmt.Errorf("parse hex uint16 %q: %w", s, err)
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

// parseUint64 parses a decimal string to uint64.
func parseUint64(s string) (uint64, error) {
	var v uint64
	_, err := fmt.Sscanf(s, "%d", &v)
	return v, err
}
