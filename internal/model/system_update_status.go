package model

import "time"

// SystemUpdateStatus is whether the host has pending security updates.
type SystemUpdateStatus struct {
	Count           int       `json:"count"`
	AffectedPackages []string `json:"affected_packages,omitempty"`
	LastCheckedAt   time.Time `json:"last_checked_at"`
}
