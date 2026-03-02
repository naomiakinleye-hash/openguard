// Package hostguardcommon provides shared types and utilities for the HostGuard sensor.
package hostguardcommon

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ProcessInfo holds information about a running process.
type ProcessInfo struct {
	PID        uint32
	PPID       uint32
	Name       string
	ExePath    string
	CmdLine    string
	Username   string
	CPUPercent float64
	MemoryMB   float64
	StartTime  time.Time
	Status     string // running, sleeping, zombie, etc.
	ContainerID string // container ID extracted from cgroup path, if any
	CgroupPath  string // raw cgroup path from /proc/<pid>/cgroup
}

// StartupItem represents a scheduled task, launch agent, service, or cron entry.
type StartupItem struct {
	ID           string
	Name         string
	Type         string // scheduled_task, launch_agent, launch_daemon, cron, systemd_unit, registry_run
	Command      string
	User         string
	Enabled      bool
	LastModified time.Time
	Source       string // file path or registry key
}

// HostEvent is the raw host sensor event before normalization.
type HostEvent struct {
	EventType string // process_created, process_terminated, process_anomaly,
	// privilege_escalation, startup_item_added, startup_item_modified,
	// resource_spike, suspicious_path,
	// file_access, file_modified, file_created, file_deleted, suspicious_file_access,
	// hidden_process_detected,
	// kernel_module_loaded, kernel_module_unloaded,
	// kernel_extension_loaded, kernel_extension_unloaded,
	// driver_loaded, driver_unloaded,
	// user_login, user_logout, sudo_invocation, ssh_login, brute_force_attempt,
	// dns_query, dns_config_changed,
	// ipc_shared_memory_created, ipc_shared_memory_deleted,
	// named_pipe_created, suspicious_ipc, suspicious_unix_socket, suspicious_named_pipe,
	// container_escape_attempt, privileged_container_process,
	// container_process_created, container_started, container_stopped,
	// usb_device_inserted, usb_device_removed, usb_mass_storage_inserted, usb_hid_inserted,
	// syscall_execve, syscall_openat, suspicious_syscall_sequence,
	// cloud_metadata_access, suspicious_cloud_metadata_access,
	// low_and_slow_anomaly,
	// secure_boot_status, firmware_setup_mode, efi_variable_modified, kernel_hardening_disabled,
	// browser_anomaly
	Platform      string // windows, darwin, linux
	Hostname      string
	Timestamp     time.Time
	Process       *ProcessInfo
	StartupItem   *StartupItem
	FileIO        *FileIOEvent
	HiddenProcess *HiddenProcessResult
	Login         *LoginEvent
	DNSQuery      *DNSQueryEvent
	Indicators    []string               // matched indicator strings
	RawData       map[string]interface{}
}

// ToUnifiedEvent converts a HostEvent to the UnifiedEvent JSON format
// compatible with the ingest service schema (schemas/unified-event.schema.json).
// It generates a UUID event_id, computes a basic audit_hash (SHA-256 of payload),
// and sets domain="host", human_approved=false.
func (e *HostEvent) ToUnifiedEvent() ([]byte, error) {
	severity, riskScore, tier := classifyEvent(e)

	actorID := "unknown"
	if e.Process != nil && e.Process.Username != "" {
		actorID = e.Process.Username
	}

	targetID := e.Hostname
	if e.Process != nil {
		targetID = fmt.Sprintf("%s:%d", e.Hostname, e.Process.PID)
	}

	metadata := map[string]interface{}{
		"platform":   e.Platform,
		"event_type": e.EventType,
	}
	if e.Process != nil {
		metadata["pid"] = e.Process.PID
		metadata["ppid"] = e.Process.PPID
		metadata["process_name"] = e.Process.Name
		metadata["exe_path"] = e.Process.ExePath
		metadata["cmdline"] = e.Process.CmdLine
		metadata["cpu_percent"] = e.Process.CPUPercent
		metadata["memory_mb"] = e.Process.MemoryMB
		metadata["status"] = e.Process.Status
	}
	if e.StartupItem != nil {
		metadata["startup_item_id"] = e.StartupItem.ID
		metadata["startup_item_name"] = e.StartupItem.Name
		metadata["startup_item_type"] = e.StartupItem.Type
		metadata["startup_item_command"] = e.StartupItem.Command
		metadata["startup_item_source"] = e.StartupItem.Source
	}
	if e.FileIO != nil {
		metadata["file_path"] = e.FileIO.Path
		metadata["file_operation"] = e.FileIO.Operation
		metadata["pid"] = e.FileIO.PID
		metadata["process_name"] = e.FileIO.ProcessName
		if e.FileIO.OldPath != "" {
			metadata["file_old_path"] = e.FileIO.OldPath
		}
	}
	if e.HiddenProcess != nil {
		metadata["hidden_pid"] = e.HiddenProcess.PID
		metadata["hidden_found_by"] = e.HiddenProcess.FoundBy
		metadata["hidden_missing_from"] = e.HiddenProcess.MissingFrom
		metadata["hidden_exe_path"] = e.HiddenProcess.ExePath
		metadata["hidden_cmdline"] = e.HiddenProcess.CmdLine
	}
	if e.Login != nil {
		metadata["login_username"] = e.Login.Username
		metadata["login_tty"] = e.Login.TTY
		metadata["login_remote_host"] = e.Login.RemoteHost
		metadata["login_pid"] = e.Login.PID
		metadata["login_session_id"] = e.Login.SessionID
		metadata["login_subtype"] = e.Login.EventSubtype
	}
	if e.DNSQuery != nil {
		metadata["dns_pid"] = e.DNSQuery.PID
		metadata["dns_process_name"] = e.DNSQuery.ProcessName
		metadata["dns_query_name"] = e.DNSQuery.QueryName
		metadata["dns_query_type"] = e.DNSQuery.QueryType
		metadata["dns_resolver"] = e.DNSQuery.Resolver
		metadata["dns_response"] = e.DNSQuery.Response
	}
	for k, v := range e.RawData {
		metadata[k] = v
	}

	indicators := e.Indicators
	if indicators == nil {
		indicators = []string{}
	}

	intermediate := map[string]interface{}{
		"event_id":  uuid.New().String(),
		"timestamp": e.Timestamp.UTC().Format(time.RFC3339),
		"source": map[string]interface{}{
			"type":    "host",
			"adapter": "hostguard",
			"host_id": e.Hostname,
		},
		"domain":    "host",
		"severity":  severity,
		"risk_score": riskScore,
		"tier":      tier,
		"actor": map[string]interface{}{
			"id":   actorID,
			"type": "process",
		},
		"target": map[string]interface{}{
			"id":   targetID,
			"type": "host",
		},
		"indicators":       indicators,
		"policy_citations": []string{},
		"human_approved":   false,
		"audit_hash":       "",
		"metadata":         metadata,
	}

	// First marshal without audit_hash to compute hash.
	intermediate["audit_hash"] = ""
	partial, err := json.Marshal(intermediate)
	if err != nil {
		return nil, fmt.Errorf("hostguard: marshal partial event: %w", err)
	}

	hash := sha256.Sum256(partial)
	intermediate["audit_hash"] = fmt.Sprintf("%x", hash)

	payload, err := json.Marshal(intermediate)
	if err != nil {
		return nil, fmt.Errorf("hostguard: marshal unified event: %w", err)
	}
	return payload, nil
}

// classifyEvent assigns severity, risk_score, and tier based on event type and indicators.
func classifyEvent(e *HostEvent) (severity string, riskScore float64, tier string) {
	// Indicator special-cases take priority over event type.
	for _, ind := range e.Indicators {
		switch ind {
		case "critical_service_stopped":
			return "critical", 95.0, "T3"
		case "suspicious_kernel_module":
			return "critical", 95.0, "immediate"
		case "hidden_driver":
			return "critical", 95.0, "immediate"
		case "usb_mass_storage_inserted":
			return "high", 70.0, "T2"
		case "usb_hid_inserted":
			return "high", 70.0, "T2"
		case "imds_abuse":
			return "critical", 95.0, "immediate"
		case "secure_boot_disabled":
			return "high", 70.0, "T2"
		case "firmware_setup_mode":
			return "critical", 95.0, "immediate"
		case "browser_remote_debugging_enabled":
			return "high", 70.0, "T2"
		case "browser_security_disabled":
			return "high", 75.0, "T2"
		}
	}
	switch e.EventType {
	case "privilege_escalation":
		return "high", 80.0, "T3"
	case "process_anomaly", "suspicious_path":
		return "medium", 50.0, "T2"
	case "startup_item_added", "startup_item_modified":
		return "high", 70.0, "T2"
	case "resource_spike":
		return "medium", 40.0, "T1"
	case "process_created", "process_terminated":
		return "info", 10.0, "T0"
	case "connection_established", "connection_closed":
		return "info", 10.0, "T0"
	case "suspicious_connection", "high_volume_connection":
		return "high", 70.0, "T2"
	case "hidden_process_detected":
		return "critical", 90.0, "immediate"
	case "suspicious_file_access":
		return "high", 70.0, "T2"
	case "file_access", "file_modified", "file_created", "file_deleted":
		return "medium", 40.0, "T1"
	case "kernel_module_loaded", "kernel_module_unloaded",
		"kernel_extension_loaded", "kernel_extension_unloaded":
		return "medium", 50.0, "T2"
	case "driver_loaded", "driver_unloaded":
		return "medium", 50.0, "T2"
	case "user_login", "user_logout":
		return "info", 15.0, "T0"
	case "sudo_invocation":
		return "medium", 45.0, "T2"
	case "ssh_login":
		return "medium", 40.0, "T1"
	case "brute_force_attempt":
		return "critical", 90.0, "immediate"
	case "dns_query":
		return "info", 10.0, "T0"
	case "dns_config_changed":
		return "medium", 50.0, "T2"
	case "ipc_shared_memory_created", "ipc_shared_memory_deleted":
		return "low", 20.0, "T1"
	case "suspicious_ipc", "suspicious_unix_socket", "suspicious_named_pipe":
		return "high", 70.0, "T2"
	case "named_pipe_created":
		return "info", 10.0, "T0"
	case "container_escape_attempt":
		return "critical", 95.0, "immediate"
	case "privileged_container_process":
		return "high", 75.0, "T3"
	case "container_process_created", "container_started", "container_stopped":
		return "info", 10.0, "T0"
	// USB / Peripheral Device events.
	case "usb_device_inserted":
		return "medium", 40.0, "T1"
	case "usb_device_removed":
		return "info", 10.0, "T0"
	case "usb_mass_storage_inserted":
		return "high", 70.0, "T2"
	case "usb_hid_inserted":
		return "high", 65.0, "T2"
	// eBPF syscall tracing events.
	case "syscall_execve":
		return "info", 15.0, "T0"
	case "syscall_openat":
		return "info", 10.0, "T0"
	case "suspicious_syscall_sequence":
		return "high", 75.0, "T2"
	// Cloud metadata service events.
	case "cloud_metadata_access":
		return "info", 20.0, "T1"
	case "suspicious_cloud_metadata_access":
		return "critical", 90.0, "immediate"
	// Low-and-slow anomaly.
	case "low_and_slow_anomaly":
		return "medium", 55.0, "T2"
	// Firmware / secure boot events.
	case "secure_boot_status":
		return "info", 10.0, "T0"
	case "firmware_setup_mode":
		return "critical", 95.0, "immediate"
	case "efi_variable_modified":
		return "high", 75.0, "T2"
	case "kernel_hardening_disabled":
		return "medium", 50.0, "T2"
	// Browser activity events.
	case "browser_anomaly":
		return "medium", 50.0, "T2"
	default:
		return "low", 20.0, "T1"
	}
}
