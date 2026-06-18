package model

import "time"

// WebSession is a single hostveil web invocation.
type WebSession struct {
	ID                    string     `json:"id"`
	HostID                string     `json:"host_id"`
	StartedAt             time.Time  `json:"started_at"`
	EndedAt               *time.Time `json:"ended_at,omitempty"`
	BindAddress           string     `json:"bind_address"`
	IsLoopback            bool       `json:"is_loopback"`
	AuthTokenSHA256       string     `json:"auth_token_sha256,omitempty"`
	TLSFingerprint        string     `json:"tls_fingerprint,omitempty"`
	DashboardViews        int        `json:"dashboard_views"`
	FixActionsTriggered   int        `json:"fix_actions_triggered"`
	RejectedAuthAttempts  int        `json:"rejected_auth_attempts"`
}
