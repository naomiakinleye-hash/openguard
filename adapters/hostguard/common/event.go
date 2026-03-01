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
	// hidden_process_detected
	Platform      string // windows, darwin, linux
	Hostname      string
	Timestamp     time.Time
	Process       *ProcessInfo
	StartupItem   *StartupItem
	FileIO        *FileIOEvent
	HiddenProcess *HiddenProcessResult
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
	// critical_service_stopped indicator always maps to T3.
	for _, ind := range e.Indicators {
		if ind == "critical_service_stopped" {
			return "critical", 95.0, "T3"
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
	default:
		return "low", 20.0, "T1"
	}
}
