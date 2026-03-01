// Package hostguardcommon provides shared types and utilities for the HostGuard sensor.
package hostguardcommon

// FileIOEvent represents a file access, modification, creation, or deletion event.
type FileIOEvent struct {
	PID         uint32
	ProcessName string
	Path        string
	Operation   string // read, write, create, delete, rename, chmod, setxattr
	OldPath     string // for rename
}
