// Package hostguardcommon provides shared types and utilities for the HostGuard sensor.
package hostguardcommon

// HiddenProcessResult represents a process found by one enumeration method but not another.
type HiddenProcessResult struct {
	PID         uint32
	FoundBy     []string // enumeration methods that found it, e.g. ["brute_force_pid", "netlink"]
	MissingFrom []string // methods that should have found it but didn't, e.g. ["proc_readdir", "ps"]
	ExePath     string
	CmdLine     string
}
