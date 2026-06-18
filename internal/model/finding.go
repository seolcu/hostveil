package model

import "time"

// Category is the locked enum for Finding.category.
type Category string

const (
	CategorySSH                  Category = "ssh"
	CategoryDocker               Category = "docker"
	CategoryImageCVE             Category = "image_cve"
	CategoryReverseProxy         Category = "reverse_proxy"
	CategorySSLTLS               Category = "ssl_tls"
	CategoryHardeningFirewall    Category = "hardening_firewall"
	CategoryHardeningFail2ban    Category = "hardening_fail2ban"
	CategoryHardeningUnattended  Category = "hardening_unattended"
	CategoryHardeningSysctl      Category = "hardening_sysctl"
	CategoryHardeningUpdates     Category = "hardening_updates"
)

// Valid reports whether c is one of the locked categories.
func (c Category) Valid() bool {
	switch c {
	case CategorySSH, CategoryDocker, CategoryImageCVE, CategoryReverseProxy,
		CategorySSLTLS,
		CategoryHardeningFirewall, CategoryHardeningFail2ban,
		CategoryHardeningUnattended, CategoryHardeningSysctl,
		CategoryHardeningUpdates:
		return true
	}
	return false
}

// State is the locked enum for Finding.state (lifecycle).
type State string

const (
	StateNew            State = "new"
	StateStillPresent   State = "still_present"
	StateResolved       State = "resolved"
	StateSuppressed     State = "suppressed"
)

// EntityRefKind is the locked enum for EntityRef.kind.
type EntityRefKind string

const (
	EntityRefKindHost           EntityRefKind = "host"
	EntityRefKindService        EntityRefKind = "service"
	EntityRefKindConfigFile     EntityRefKind = "config_file"
	EntityRefKindSetting        EntityRefKind = "setting"
	EntityRefKindContainerImage EntityRefKind = "container_image"
	EntityRefKindVulnerability  EntityRefKind = "vulnerability"
)

// EntityRef is a typed reference from a Finding to a target entity.
type EntityRef struct {
	Kind    EntityRefKind `json:"kind"`
	ID      string        `json:"id"`
	Display string        `json:"display"`
}

// Finding is a single problem the program reports.
type Finding struct {
	ID           string       `json:"id"`
	ScanRunID    string       `json:"scan_run_id"`
	Fingerprint  string       `json:"fingerprint"` // sha256 hex of (category, rule_id, sorted(entity_refs))
	Category     Category     `json:"category"`
	RuleID       string       `json:"rule_id"`
	Severity     Severity     `json:"severity"`
	Title        string       `json:"title"`
	Description  string       `json:"description"`
	EntityRefs   []EntityRef  `json:"entity_refs"`
	FixID        string       `json:"fix_id,omitempty"`
	State        State        `json:"state"`
	FirstSeenAt  time.Time    `json:"first_seen_at"`
	LastSeenAt   time.Time    `json:"last_seen_at"`
}
