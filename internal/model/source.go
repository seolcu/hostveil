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
	SourceSysctl
	SourceDockerd
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
	case SourceSysctl:
		return "sysctl"
	case SourceDockerd:
		return "dockerd"
	default:
		return "unset"
	}
}

// Label returns the short display name every interface shows for the
// domain — the filter chip in the dashboard, the filter line in the TUI.
//
// It lives here rather than in each UI because it did live in each UI, and
// they drifted. The TUI wrote the table out in a switch and the dashboard
// wrote it again in JavaScript, and when the sysctl domain landed neither
// copy was updated: the dashboard filtered its domain chips by membership
// in that table, so eight kernel-hardening findings became unfilterable,
// and a failed sysctl domain announced itself as "10 failed".
//
// The labels are shorter than the scoring axis labels on purpose. An axis
// names a subject in a table with room for it ("Container exposure"); a
// chip sits in a row of nine and has to stay narrow.
//
// There is no fallback for an unknown domain, which is the point: adding a
// Source without a label here fails TestEverySourceHasALabel rather than
// rendering as a bare integer somewhere nobody looks.
func (s Source) Label() string {
	switch s {
	case SourceCompose:
		return "Container"
	case SourceSSH:
		return "SSH"
	case SourceFirewall:
		return "Firewall"
	case SourceUpdates:
		return "Updates"
	case SourceCVE:
		return "CVEs"
	case SourcePorts:
		return "Ports"
	case SourceAccounts:
		return "Accounts"
	case SourceFilePerms:
		return "File perms"
	case SourceAgent:
		return "AI agents"
	case SourceSysctl:
		return "Kernel"
	case SourceDockerd:
		return "Dockerd"
	default:
		return ""
	}
}

// Valid reports whether the source was set to a real domain.
//
// The upper bound is a range check, so a new domain appended to the const
// block must be added here too. Forgetting is silent and total: every
// finding from the new domain fails Validate() and is dropped after the
// scan, so the domain reports clean rather than reporting nothing.
func (s Source) Valid() bool {
	return s >= SourceCompose && s <= SourceDockerd
}

// AllSources lists every real detection domain in scan/report order.
func AllSources() []Source {
	return []Source{
		SourceCompose, SourceSSH, SourceFirewall, SourceUpdates, SourceCVE,
		SourcePorts, SourceAccounts, SourceFilePerms, SourceAgent, SourceSysctl,
		SourceDockerd,
	}
}
