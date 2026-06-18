package model

import "time"

// SSLCertificate is a TLS certificate observed on the host.
type SSLCertificate struct {
	Path        string    `json:"path,omitempty"`
	Issuer      string    `json:"issuer"`
	NotAfter    time.Time `json:"not_after"`
	RenewalHook string    `json:"renewal_hook,omitempty"` // e.g. "systemd:certbot.timer"
}
