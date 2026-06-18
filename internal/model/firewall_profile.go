package model

// FirewallBackend is the locked enum for FirewallProfile.backend.
type FirewallBackend string

const (
	FirewallBackendUFW      FirewallBackend = "ufw"
	FirewallBackendIPTables FirewallBackend = "iptables"
	FirewallBackendNFTables FirewallBackend = "nftables"
	FirewallBackendNone     FirewallBackend = "none"
)

// FirewallRule is one entry in the active firewall rule set.
type FirewallRule struct {
	Action string `json:"action"` // allow | deny | reject | drop
	From   string `json:"from"`
	To     string `json:"to"`
	Port   string `json:"port,omitempty"`
	Proto  string `json:"proto,omitempty"`
}

// FirewallProfile is the host's firewall state.
type FirewallProfile struct {
	Backend       FirewallBackend `json:"backend"`
	DefaultPolicy string          `json:"default_policy"`
	Rules         []FirewallRule  `json:"rules,omitempty"`
}
