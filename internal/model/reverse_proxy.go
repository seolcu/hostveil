package model

// ReverseProxy is a web-facing proxy the host runs.
type ReverseProxy struct {
	Name        string   `json:"name"` // nginx | caddy
	Version     string   `json:"version,omitempty"`
	VHostIDs    []string `json:"vhost_ids"`
	ConfigFileID string  `json:"config_file_id"`
}
