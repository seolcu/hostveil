package domain

import "time"

const (
	HTTPClientTimeout     = 15 * time.Second
	DockerComposeTimeout  = 10 * time.Second
	TrivyConfigTimeout    = 5 * time.Minute
	TrivyImageTimeout     = 5 * time.Minute
	LynisAuditTimeout     = 2 * time.Minute
	HTTPReadHeaderTimeout = 5 * time.Second
	TUITickInterval       = 100 * time.Millisecond
)
