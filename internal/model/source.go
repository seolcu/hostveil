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
	SourceAgent
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
	case SourceAgent:
		return "agent"
	default:
		return "unset"
	}
}

// Valid reports whether the source was set to a real domain.
//
// The upper bound is a range check, so a new domain appended to the const
// block must be added here too. Forgetting is silent and total: every
// finding from the new domain fails Validate() and is dropped after the
// scan, so the domain reports clean rather than reporting nothing.
func (s Source) Valid() bool {
	return s >= SourceCompose && s <= SourceAgent
}

// AllSources lists every real detection domain in scan/report order.
func AllSources() []Source {
	return []Source{
		SourceCompose, SourceSSH, SourceFirewall, SourceUpdates, SourceCVE,
		SourcePorts, SourceAccounts, SourceFilePerms, SourceAgent,
	}
}
