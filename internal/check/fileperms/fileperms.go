// Package fileperms implements a native checker for the two things that
// decide who can read and write a sensitive host file: its permission bits
// and its owner. A world-writable /etc/passwd or a group-readable SSH host
// key is a quiet but serious hole, and so is a mode-0600 /etc/shadow that
// belongs to somebody other than root — 0600 says "only the owner", and the
// whole question is who that is.
package fileperms

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Rule declares the strictest acceptable permission for one sensitive file.
// A file is flagged when its permission bits include anything outside
// MaxMode (i.e. perm &^ MaxMode != 0).
type Rule struct {
	Path    string      // exact path, or a glob when Glob is true
	Glob    bool        // expand Path with filepath.Glob (e.g. SSH host keys)
	MaxMode os.FileMode // strictest acceptable perm bits
	Sev     model.Severity
	ID      string
	Title   string
	Desc    string
}

// paths resolves the rule to the concrete files to stat. An error means the
// rule could not be evaluated at all, which is a coverage gap and not a pass.
//
// The glob is the reason this exists. filepath.Glob reports a directory it
// cannot read as zero matches and a nil error — indistinguishable from a host
// that simply has no SSH host keys — so an /etc/ssh the scan cannot enter
// would silently clear a High-severity rule about private keys being readable.
// Asking the directory directly is the only way to tell the two apart.
//
// It assumes the wildcard is in the last element, which is the shape Rule
// documents and the only shape defaultRules uses.
func (r Rule) paths() ([]string, error) {
	if !r.Glob {
		return []string{r.Path}, nil
	}
	matches, err := filepath.Glob(r.Path)
	if err != nil {
		return nil, fmt.Errorf("cannot expand %s: %w", r.Path, err)
	}
	if len(matches) > 0 {
		return matches, nil
	}
	dir := filepath.Dir(r.Path)
	if _, err := os.ReadDir(dir); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("cannot read %s — the files it holds were not checked", dir)
	}
	// The directory is absent or genuinely empty of matches. Nothing to judge.
	return nil, nil
}

// ownerFinding reports sensitive files that are not owned by root.
//
// The mode rules above answer "how much access do the bits grant" and
// stopped there, which is only half the question: mode 0600 grants
// everything to the owner and nothing to anyone else, so a /etc/shadow at
// 0600 owned by an ordinary user hands that user every password hash on the
// host — and the mode check calls it clean, because 0600 is exactly what it
// wants to see. Ownership is the other half, and every file in this table
// belongs to root on every distribution.
//
// One finding for all of them rather than one per path: the remediation is
// the same `chown root:root` in every case, and a host where this has gone
// wrong has usually had it go wrong to several files at once (a restore from
// a backup taken as the wrong user, an extracted archive).
const ownerFindingID = "fileperms.owner"

// rootUID is the owner every file in the rule table must have on a real
// host. These are paths whose ownership is fixed by the system, not by
// preference — Checker.OwnerUID exists only so a test can assert both
// directions without caring which account runs the suite.
const rootUID = 0

// Checker reports sensitive files with over-permissive modes.
type Checker struct {
	// Rules is the set of files to check; overridable for tests.
	Rules []Rule
	// OwnerUID is the uid every rule's file must belong to. Zero means
	// root, which is the answer on every real host; it is a field so a test
	// can assert the wrongly-owned case without having to run as a
	// particular account, and so the suite behaves the same under root and
	// under CI's unprivileged user.
	OwnerUID int
}

// New returns a fileperms checker with the default sensitive-file rules.
func New() *Checker { return &Checker{Rules: defaultRules(), OwnerUID: rootUID} }

func defaultRules() []Rule {
	return []Rule{
		{Path: "/etc/shadow", MaxMode: 0o640, Sev: model.SeverityHigh, ID: "fileperms.shadow",
			Title: "/etc/shadow is more permissive than it should be",
			Desc:  "/etc/shadow holds every account's password hash. If it is readable or writable beyond root (and the shadow group), those hashes can be stolen and cracked offline, or an attacker can set a password directly."},
		{Path: "/etc/passwd", MaxMode: 0o644, Sev: model.SeverityHigh, ID: "fileperms.passwd",
			Title: "/etc/passwd is writable by non-root users",
			Desc:  "/etc/passwd defines every account. If it is writable by anyone but root, a local user can add an account or change a UID to escalate to root."},
		{Path: "/etc/group", MaxMode: 0o644, Sev: model.SeverityHigh, ID: "fileperms.group",
			Title: "/etc/group is writable by non-root users",
			Desc:  "/etc/group defines group membership. If it is writable by non-root users, a local user can add themselves to a privileged group (e.g. sudo, docker) and escalate."},
		{Path: "/etc/gshadow", MaxMode: 0o640, Sev: model.SeverityHigh, ID: "fileperms.gshadow", Title: "/etc/gshadow is more permissive than it should be", Desc: "/etc/gshadow contains protected group credentials and membership data; access beyond root and the shadow group can expose credentials or enable privilege escalation."},
		{Path: "/etc/sudoers", MaxMode: 0o440, Sev: model.SeverityHigh, ID: "fileperms.sudoers", Title: "/etc/sudoers is writable or broadly readable", Desc: "A non-root user who can alter sudo policy can grant themselves root access."},
		{Path: "/etc/sudoers.d/*", Glob: true, MaxMode: 0o440, Sev: model.SeverityHigh, ID: "fileperms.sudoers-dropins", Title: "A sudoers drop-in is writable or broadly readable", Desc: "Sudoers drop-ins carry the same authority as /etc/sudoers; a writable one is a direct path to root."},
		{Path: "/etc/cron.d/*", Glob: true, MaxMode: 0o644, Sev: model.SeverityHigh, ID: "fileperms.cron", Title: "A system cron definition is writable by non-root users", Desc: "Files in /etc/cron.d can schedule commands as root, so non-root write access is a direct privilege-escalation path."},
		{Path: "/etc/systemd/system/*.service", Glob: true, MaxMode: 0o644, Sev: model.SeverityHigh, ID: "fileperms.systemd-units", Title: "A systemd service unit is writable by non-root users", Desc: "A writable system service definition lets a local user replace a command that systemd later starts as root."},
		{Path: "/root/.docker/config.json", MaxMode: 0o600, Sev: model.SeverityHigh, ID: "fileperms.docker-config", Title: "Root's Docker credentials are readable by other users", Desc: "Docker's config can contain registry authentication tokens; users who can read it can pull private images or publish as the host's registry identity."},
		{Path: "/etc/ssh/sshd_config", MaxMode: 0o644, Sev: model.SeverityMedium, ID: "fileperms.sshd-config",
			Title: "sshd_config is writable by non-root users",
			Desc:  "If the SSH server config is writable by non-root users, an attacker can weaken it (re-enable root login or password auth) and take over remote access."},
		{Path: "/etc/ssh/ssh_host_*_key", Glob: true, MaxMode: 0o640, Sev: model.SeverityHigh, ID: "fileperms.hostkey",
			Title: "SSH host private key is readable beyond root",
			Desc:  "An SSH host private key readable by non-root users lets them impersonate this server, enabling man-in-the-middle attacks on anyone connecting over SSH."},
	}
}

// Source identifies the fileperms domain.
func (*Checker) Source() model.Source { return model.SourceFilePerms }

// Available is always true: it simply stats whichever of its target files
// exist and skips the rest.
func (*Checker) Available(_ context.Context, _ platform.Env) (bool, string) {
	return true, ""
}

// Check stats each rule's file(s) and flags any over-permissive mode, and any
// file not owned by root.
//
// A rule it could not evaluate is recorded as a coverage gap rather than
// passed over. "This file is not here" and "I was not allowed to look at it"
// both used to arrive as a non-nil error from Stat and both were skipped, so
// a rule that could not run reported exactly like a rule that passed — on a
// domain whose whole job is noticing that a sensitive file is readable by the
// wrong people.
func (c *Checker) Check(_ context.Context, _ platform.Env) ([]model.Finding, error) {
	var findings []model.Finding
	var wrongOwner []string
	var cov check.Coverage
	for _, rule := range c.Rules {
		paths, err := rule.paths()
		if err != nil {
			cov.Missed(1, err.Error())
			continue
		}
		cov.Covered(1)

		var badPaths []string
		var badEvidence []string
		var unstattable []string
		for _, p := range paths {
			fi, err := os.Stat(p)
			switch {
			case os.IsNotExist(err):
				continue // no SSH server, no /etc/shadow: nothing to judge
			case err != nil:
				// Not the same as absent. The rule was not evaluated for this
				// file, and saying nothing would report it as having passed.
				unstattable = append(unstattable, p)
				continue
			case fi.IsDir():
				continue
			}
			// Checked for every rule, and independently of the mode: a file
			// can have impeccable bits and the wrong owner, which is the
			// case the mode check reads as clean.
			if uid, ok := fileUID(fi); ok && uid != c.OwnerUID {
				wrongOwner = append(wrongOwner, fmt.Sprintf("%s (uid %d)", p, uid))
			}
			if fi.Mode().Perm()&^rule.MaxMode != 0 {
				badPaths = append(badPaths, p)
				badEvidence = append(badEvidence, fmt.Sprintf("%s (%#o)", p, fi.Mode().Perm()))
			}
		}
		if len(unstattable) > 0 {
			sort.Strings(unstattable)
			cov.Missed(0, "cannot read "+strings.Join(unstattable, ", ")+
				" — their permissions were not checked")
		}
		if len(badPaths) == 0 {
			continue
		}
		sort.Strings(badPaths)
		sort.Strings(badEvidence)
		findings = append(findings, model.NewFinding(rule.ID, rule.Title, rule.Sev,
			model.SourceFilePerms, model.RemediationAuto,
			model.WithDescription(rule.Desc),
			model.WithHowToFix(fmt.Sprintf("Tighten the mode to %#o or stricter, e.g. `chmod %#o %s`.", rule.MaxMode, rule.MaxMode, badPaths[0])),
			model.WithEvidence("files", strings.Join(badEvidence, model.EvidenceSeparator)),
			// The machine-readable twin of "files": the fix needs the paths
			// alone, and parsing them back out of "/etc/shadow (0644), …"
			// breaks on any path containing ", " or " (". The separator is
			// PathListSeparator rather than EvidenceSeparator for the second
			// half of that reason — ", " is legal inside a path too.
			model.WithEvidence("paths", strings.Join(badPaths, model.PathListSeparator)),
			model.WithEvidence("expected", fmt.Sprintf("%#o", rule.MaxMode)),
		))
	}

	if len(wrongOwner) > 0 {
		sort.Strings(wrongOwner)
		findings = append(findings, model.NewFinding(ownerFindingID,
			"A sensitive system file is not owned by root",
			model.SeverityHigh, model.SourceFilePerms, model.RemediationManual,
			model.WithDescription("These files are owned by an account other than root. Permission bits are only half of who can read and write a file — the other half is who the owner is. A mode-0600 /etc/shadow grants everything to its owner and nothing to anyone else, so if that owner is an ordinary user, they hold every password hash on the host while the permissions look exactly right."),
			model.WithHowToFix("Restore root ownership, e.g. `chown root:root "+strings.SplitN(wrongOwner[0], " ", 2)[0]+"`. Check the group too — /etc/shadow is usually root:shadow. If this happened to several files at once, something restored them as the wrong user; look at how they got there before assuming a chown is the whole fix."),
			model.WithEvidence("files", strings.Join(wrongOwner, model.EvidenceSeparator)),
		))
	}
	return findings, cov.Err()
}

// fileUID reports the owning uid, and whether the platform gave one.
//
// ok is false where the stat result carries no Unix owner. That reads as
// "could not tell", and the caller flags nothing — the same rule the rest of
// this tool follows, because an unowned-looking file is a gap in what we can
// see rather than evidence about the host.
func fileUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
