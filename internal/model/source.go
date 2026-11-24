package model

// Source identifies which detection domain produced a finding. It is
// also the finding-ID namespace prefix ("compose.ds016", "ssh.rootlogin")
// and the key used to route findings to scoring axes.
//
// SourceUnset is the zero value: a finding built without an
// explicit source is invalid, never a silently-valid default. Routing by
// this typed enum (not by string-prefixing the ID) is only safe because
// the zero value means "unset".
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
	SourceProxy
	SourceProxmox
	SourceKube
	SourceForensic

	sourceCount // sentinel; keep last
)

// sourceDef is everything Hostveil knows about a detection domain.
//
// There used to be six of these tables, all keyed by the same constant and
// all maintained by hand: the const block, a String switch, a Label switch,
// the upper bound of Valid, the AllSources slice, and axisDefs over in
// score.go. Adding a domain meant finding all six, and the record shows
// that no one did. When the sysctl domain landed, the two display tables
// that then lived in the UIs were missed, and the dashboard dropped a whole
// domain's filter chip while announcing its failures as "10". Those were
// pulled back here, and the dashboard immediately grew a *seventh* copy,
// keyed by axis ID this time, which fell behind by two domains before
// anyone noticed.
//
// The lesson taken is not "write the table down once more carefully". It is
// that a domain is one thing and should be described in one row, and that
// anything shaped like a parallel table keyed by Source is a copy waiting
// to go stale.
type sourceDef struct {
	source Source
	// name is the stable lowercase domain name, and more than a
	// display string: it is the finding-ID prefix each checker owns, it is
	// the first field of Finding.Key(), and the fix registry matches globs
	// against it. Changing one renames things on disk.
	name string
	// label is the short display name every interface shows: the filter
	// chip in the dashboard, the filter line in the TUI. It is shorter
	// than axisLabel: an axis names a subject in a table with
	// room for it, a chip sits in a row of eleven and has to stay narrow.
	label string
	// axisID and axisLabel name the domain's scoring axis; cap is its
	// share of the overall score. See axisDefs in score.go for why the
	// caps sit where they do.
	axisID    string
	axisLabel string
	cap       int
	// optIn keeps the domain out of a scan unless the operator asks for it
	// by name. See Source.OptIn.
	optIn bool
}

// sourceDefs describes every detection domain, in scan and report order.
//
// That one order serves two purposes, and the coupling is intended: AllSources order drives scan projection and the
// dashboard's live progress list, and the same order drives the scoring
// axes down the page. Both are "most consequential first", which is why
// they have agreed through eleven domains. If a future change needs the
// axes displayed in some other order (worst-first, say) that is a
// projection to add here. Two hand-maintained lists would drift.
//
// A third copy of this order lives in cmd/hostveil/app.go, where the
// checkers are registered; it is what orders Report.Domains, and
// TestCheckerRegistrationMatchesSourceOrder there holds it to this one.
//
// The Source is an explicit column and every lookup is keyed by it. Rows
// must never be found by position: SourceUnset owns 0, so this table's
// rows sit one off from their values, while the severity table's do not.
// These values are serialized as bare integers into on-disk scan
// snapshots, so an off-by-one here would survive every test (they all
// round-trip through this same table) and would surface only as a
// previous scan whose findings had all changed domain, which reads to a
// user as "everything on this host is new and everything old is fixed".
var sourceDefs = []sourceDef{
	{SourceCompose, "compose", "Container", "container", "Container exposure", 8, false},
	{SourceSSH, "ssh", "SSH", "ssh", "SSH hardening", 9, false},
	{SourceFirewall, "firewall", "Firewall", "firewall", "Host firewall", 6, false},
	{SourceUpdates, "updates", "Updates", "updates", "Auto-updates", 7, false},
	{SourceCVE, "cve", "CVEs", "cve", "Vulnerabilities", 7, false},
	{SourcePorts, "ports", "Ports", "ports", "Exposed services", 6, false},
	{SourceAccounts, "accounts", "Accounts", "accounts", "Account hygiene", 7, false},
	{SourceFilePerms, "fileperms", "File perms", "fileperms", "File permissions", 5, false},
	{SourceAgent, "agent", "AI agents", "agent", "AI agent runtimes", 6, false},
	{SourceSysctl, "sysctl", "Kernel", "sysctl", "Kernel hardening", 5, false},
	{SourceDockerd, "dockerd", "Dockerd", "dockerd", "Docker daemon", 7, false},
	{SourceSystemd, "systemd", "Services", "systemd", "Service hardening", 6, false},
	{SourceProxy, "proxy", "Proxy", "proxy", "Reverse proxy", 6, false},
	{SourceProxmox, "proxmox", "Proxmox", "proxmox", "Proxmox VE host", 6, false},
	{SourceKube, "kube", "Kubernetes", "kube", "Single-node Kubernetes", 5, false},
	{SourceForensic, "forensic", "Forensics", "forensic", "Forensic readiness", 4, true},
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
// There is no fallback for an unknown domain, so that a domain
// with no row here renders as "" and trips TestEverySourceConstHasATableRow
// so a bare integer is never drawn somewhere no one looks.
func (s Source) Label() string {
	return sourceIndex[s].label
}

// Valid reports whether the source was set to a real domain.
//
// This is table membership. The bound used to be
// written out as `s <= SourceDockerd` and had to be edited by hand for
// every new domain; forgetting was silent and total, because every finding
// from the new domain then failed Validate() and was dropped after the
// scan, so the domain reported clean. A
// membership test cannot fall behind the table it tests.
func (s Source) Valid() bool {
	_, ok := sourceIndex[s]
	return ok
}

// OptIn reports whether the domain runs only when the operator names it.
//
// Forensic readiness is the one such domain. It asks whether a host keeps the
// evidence an investigation would need (ninety days of journal, auditd, a log
// copy off the box), which is a fair question for an organisation and not one
// the owner of a home server can do much about. Charged by default, it lowered
// the score of exactly the reader Hostveil is written for, over findings that
// reader has no reason to act on. Off by default and named with `--with`, it
// is still one flag away for whoever wants it.
func (s Source) OptIn() bool { return sourceIndex[s].optIn }

// OptInSources lists the domains that run only when asked for, in scan order.
func OptInSources() []Source {
	var out []Source
	for _, d := range sourceDefs {
		if d.optIn {
			out = append(out, d.source)
		}
	}
	return out
}

// AllSources lists every real detection domain in scan/report order.
func AllSources() []Source {
	return columnOf(sourceDefs, func(d sourceDef) Source { return d.source })
}

// sourceByName carries a row sourceDefs does not: SourceUnset owns the zero
// value and has no table entry, but String() renders it "unset", and a
// marshaller that writes a name it cannot read back is a one-way door. It is
// the only enum here needing this: RemediationKind gives its Unset a real
// row, and Severity's and ScanState's zero values are ordinary members.
var sourceByName = func() map[string]Source {
	m := nameIndex(sourceDefs,
		func(d sourceDef) Source { return d.source },
		func(d sourceDef) string { return d.name })
	m[SourceUnset.String()] = SourceUnset
	return m
}()

// ParseSource resolves a lowercase domain name.
func ParseSource(s string) (Source, bool) {
	src, ok := sourceByName[s]
	return src, ok
}

// MarshalJSON writes the name. See enum.go.
func (s Source) MarshalJSON() ([]byte, error) { return marshalEnum(s.String()) }

// UnmarshalJSON accepts the name or the integer older snapshots hold.
func (s *Source) UnmarshalJSON(data []byte) error {
	v, err := unmarshalEnum(data, "source", sourceByName, func(v Source) bool {
		return v == SourceUnset || v.Valid()
	})
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// presenceGated lists the domains whose subject is a kind of host, not a
// part of every host: a Proxmox VE node, a single-node Kubernetes. For these,
// Skipped means "this host is not one", which is the answer for nearly every
// host and not a blind spot, so the interfaces do not list them as skipped.
// Every other domain's skip (no Trivy, no permission to read sshd_config) is
// something the operator can act on and stays visible.
var presenceGated = map[Source]bool{
	SourceProxmox: true,
	SourceKube:    true,
}

// PresenceGated reports whether a skip of this domain means the host is not
// the kind of host the domain audits. See presenceGated.
func (s Source) PresenceGated() bool { return presenceGated[s] }

// Absent reports whether d is a presence-gated domain that did not run: a
// domain the interfaces leave out entirely.
func (d DomainResult) Absent() bool { return d.State == ScanSkipped && d.Source.PresenceGated() }
