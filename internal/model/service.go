package model

import "time"

// ServiceStatus is the locked enum for the Service.status field.
type ServiceStatus string

const (
	ServiceRunning     ServiceStatus = "running"
	ServiceStopped     ServiceStatus = "stopped"
	ServiceNotInstalled ServiceStatus = "not-installed"
)

// Valid reports whether s is one of the three locked statuses.
func (s ServiceStatus) Valid() bool {
	switch s {
	case ServiceRunning, ServiceStopped, ServiceNotInstalled:
		return true
	}
	return false
}

// Service is a long-running process the host exposes.
type Service struct {
	ID            string        `json:"id"`
	HostID        string        `json:"host_id"`
	Name          string        `json:"name"`
	Status        ServiceStatus `json:"status"`
	ConfigFileIDs []string      `json:"config_file_ids,omitempty"`
	DiscoveredAt  time.Time     `json:"discovered_at"`
}
