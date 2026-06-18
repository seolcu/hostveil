package model

import "time"

// ContainerImage is a Docker image in use on the host.
type ContainerImage struct {
	ID               string    `json:"id"`
	HostID           string    `json:"host_id"`
	Repository       string    `json:"repository"`
	Tag              string    `json:"tag"`
	Digest           string    `json:"digest"`
	InUse            bool      `json:"in_use"`
	VulnerabilityIDs []string  `json:"vulnerability_ids,omitempty"`
	LastSeenAt       time.Time `json:"last_seen_at"`
}
