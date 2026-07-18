package model

// Source identifies which detection domain produced a finding. It is
// also the finding-ID namespace prefix ("compose.ds016", "ssh.rootlogin")
// and the key used to route findings to scoring axes.
//
// SourceUnset is the zero value on purpose: a finding built without an
// explicit source is invalid, never a silently-valid default. Routing by
// this typed enum (not by string-prefixing the ID) is only safe because
// the zero value means "unset" rather than a real domain.
type Source int

const (
	SourceUnset Source = iota // 0 = invalid; never a real domain
	SourceCompose
	SourceSSH
	SourceFirewall
	SourceUpdates
	SourceCVE
	SourcePorts
	SourceAccounts
	SourceFilePerms
)

// String returns the stable lowercase domain name, also used as the
// finding-ID prefix each checker owns.
func (s Source) String() string {
	switch s {
	case SourceCompose:
		return "compose"
	case SourceSSH:
		return "ssh"
	case SourceFirewall:
		return "firewall"
	case SourceUpdates:
		return "updates"
	case SourceCVE:
		return "cve"
	case SourcePorts:
		return "ports"
	case SourceAccounts:
		return "accounts"
	case SourceFilePerms:
		return "fileperms"
	default:
		return "unset"
	}
}

// Valid reports whether the source was set to a real domain.
func (s Source) Valid() bool {
	return s >= SourceCompose && s <= SourceFilePerms
}

// AllSources lists every real detection domain in scan/report order.
func AllSources() []Source {
	return []Source{
		SourceCompose, SourceSSH, SourceFirewall, SourceUpdates, SourceCVE,
		SourcePorts, SourceAccounts, SourceFilePerms,
	}
}
