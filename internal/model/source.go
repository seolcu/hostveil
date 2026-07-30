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
	SourceSystemd

	sourceCount // sentinel, not a domain; keep last
)

// sourceDef is everything hostveil knows about a detection domain.
//
// There used to be six of these tables, all keyed by the same constant and
// all maintained by hand: the const block, a String switch, a Label switch,
// the upper bound of Valid, the AllSources slice, and axisDefs over in
// score.go. Adding a domain meant finding all six, and the record shows
// that nobody did. When the sysctl domain landed, the two display tables
// that then lived in the UIs were missed, and the dashboard dropped a whole
// domain's filter chip while announcing its failures as "10". Those were
// pulled back here — and the dashboard immediately grew a *seventh* copy,
// keyed by axis ID this time, which fell behind by two domains before
// anyone noticed.
//
// The lesson taken is not "write the table down once more carefully". It is
// that a domain is one thing and should be described in one row, and that
// anything shaped like a parallel table keyed by Source is a copy waiting
// to go stale.
type sourceDef struct {
	source Source
	// name is the stable lowercase domain name, and it is not just a
	// display string: it is the finding-ID prefix each checker owns, it is
	// the first field of Finding.Key(), and the fix registry matches globs
	// against it. Changing one renames things on disk.
	name string
	// label is the short display name every interface shows — the filter
	// chip in the dashboard, the filter line in the TUI. It is shorter
	// than axisLabel on purpose: an axis names a subject in a table with
	// room for it, a chip sits in a row of eleven and has to stay narrow.
	label string
	// axisID and axisLabel name the domain's scoring axis; cap is its
	// share of the overall score. See axisDefs in score.go for why the
	// caps sit where they do.
	axisID    string
	axisLabel string
	cap       int
}

// sourceDefs describes every detection domain, in scan and report order.
//
// That one order serves two purposes, and the coupling is a decision
// rather than an accident: AllSources order drives scan projection and the
// dashboard's live progress list, and the same order drives the scoring
// axes down the page. Both are "most consequential first", which is why
// they have agreed through eleven domains. If a future change needs the
// axes displayed in some other order — worst-first, say — that is a
// projection to add here, not a reason to keep two hand-maintained lists.
//
// A third copy of this order lives in cmd/hostveil/app.go, where the
// checkers are registered; it is what actually orders Report.Domains, and
// TestCheckerRegistrationMatchesSourceOrder there holds it to this one.
//
// The Source is an explicit column and every lookup is keyed by it. Rows
// must never be found by position: SourceUnset owns 0, so this table's
// rows sit one off from their values, while the severity table's do not.
// These values are serialized as bare integers into on-disk scan
// snapshots, so an off-by-one here would survive every test — they all
// round-trip through this same table — and would surface only as a
// previous scan whose findings had all changed domain, which reads to a
// user as "everything on this host is new and everything old is fixed".
var sourceDefs = []sourceDef{
	{SourceCompose, "compose", "Container", "container", "Container exposure", 14},
	{SourceSSH, "ssh", "SSH", "ssh", "SSH hardening", 14},
	{SourceFirewall, "firewall", "Firewall", "firewall", "Host firewall", 9},
	{SourceUpdates, "updates", "Updates", "updates", "Auto-updates", 7},
	{SourceCVE, "cve", "CVEs", "cve", "Vulnerabilities", 10},
	{SourcePorts, "ports", "Ports", "ports", "Exposed services", 8},
	{SourceAccounts, "accounts", "Accounts", "accounts", "Account hygiene", 7},
	{SourceFilePerms, "fileperms", "File perms", "fileperms", "File permissions", 5},
	{SourceAgent, "agent", "AI agents", "agent", "AI agent runtimes", 8},
	{SourceSysctl, "sysctl", "Kernel", "sysctl", "Kernel hardening", 5},
	{SourceDockerd, "dockerd", "Dockerd", "dockerd", "Docker daemon", 7},
	{SourceSystemd, "systemd", "Services", "systemd", "Service hardening", 6},
}

var sourceIndex = indexBy(sourceDefs, func(d sourceDef) Source { return d.source })

// String returns the stable lowercase domain name, also used as the
// finding-ID prefix each checker owns.
func (s Source) String() string {
	if d, ok := sourceIndex[s]; ok {
		return d.name
	}
	return "unset"
}

// Label returns the short display name every interface shows for the
// domain.
//
// There is no fallback for an unknown domain, which is the point: a domain
// with no row here renders as "" and trips TestEverySourceConstHasATableRow
// rather than drawing a bare integer somewhere nobody looks.
func (s Source) Label() string {
	return sourceIndex[s].label
}

// Valid reports whether the source was set to a real domain.
//
// This is table membership, not a range check. The bound used to be
// written out as `s <= SourceDockerd` and had to be edited by hand for
// every new domain; forgetting was silent and total, because every finding
// from the new domain then failed Validate() and was dropped after the
// scan, so the domain reported clean rather than reporting nothing. A
// membership test cannot fall behind the table it tests.
func (s Source) Valid() bool {
	_, ok := sourceIndex[s]
	return ok
}

// AllSources lists every real detection domain in scan/report order.
func AllSources() []Source {
	return columnOf(sourceDefs, func(d sourceDef) Source { return d.source })
}
