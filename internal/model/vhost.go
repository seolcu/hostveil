package model

// VHost is a single virtual host defined by a ReverseProxy.
type VHost struct {
	Name         string   `json:"name"`
	ServerName   string   `json:"server_name"`
	Locations    []string `json:"locations,omitempty"`
	Settings     []Setting `json:"settings,omitempty"`
	ReverseProxyID string `json:"reverse_proxy_id"`
}
