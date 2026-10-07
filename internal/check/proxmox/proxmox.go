// Package proxmox audits a Proxmox VE host.
//
// A hypervisor is the machine every guest on it trusts, and the homelab one is
// usually reachable from the whole LAN on port 8006 with a root password and
// nothing else. This domain reads the three things a single-host audit can see
// and nothing inside a guest could: who can reach the management interface,
// whether root@pam logs into it with a second factor, and whether the host is
// actually receiving the updates its repository configuration claims.
//
// # What is deliberately not here
//
// **The datacenter firewall.** It is off by default and that matters, but a
// host with no filtering is already the firewall domain's finding. What that
// domain lacked was the other half — a PVE firewall that *is* on filters
// through its own chains under an INPUT policy of ACCEPT, which read as no
// firewall at all — and the fix for that lives there, in the probe, rather
// than as a second finding here about the same missing filter.
//
// **SSH root login.** PVE clusters use root SSH between nodes, so the ssh
// domain's rule is already the right one and its fix is already Review.
//
// **Guests.** A VM's config says what it is allowed to do, not what runs
// inside it, and auditing that is a different tool.
package proxmox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Checker reports weaknesses in a Proxmox VE host's own configuration.
type Checker struct {
	// Root prefixes every path read; "" and "/" both mean the real host.
	// Overridable so a test can lay a fake /etc out in a temp dir.
	Root string
}

// New returns a checker reading the host's own files.
func New() *Checker { return &Checker{} }

// Source identifies the Proxmox VE domain.
func (*Checker) Source() model.Source { return model.SourceProxmox }

func (c *Checker) path(p string) string {
	if c.Root == "" {
		return p
	}
	return filepath.Join(c.Root, p)
}

// Available requires /etc/pve, the cluster filesystem every PVE node mounts.
//
// A host without it is not a hypervisor this domain has an opinion about, and
// the axis is renormalized away rather than scored on an absence. It is not
// gated on platform.AuditableOS: nothing on macOS mounts /etc/pve, so the
// ordinary answer is already the right one there.
func (c *Checker) Available(context.Context, platform.Env) (bool, string) {
	if fi, err := os.Stat(c.path("/etc/pve")); err == nil && fi.IsDir() {
		return true, ""
	}
	return false, "not a Proxmox VE host — no /etc/pve"
}

// Check reads the three surfaces and reports what each could not cover.
func (c *Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	var cov check.Coverage
	var out []model.Finding

	if f, gap := c.auditWebUI(); gap != "" {
		cov.Missed(1, gap)
	} else {
		cov.Covered(1)
		out = append(out, f...)
	}

	if f, gap := c.auditRootTFA(); gap != "" {
		cov.Missed(1, gap)
	} else {
		cov.Covered(1)
		out = append(out, f...)
	}

	if f, gap := c.auditRepos(ctx, env.Runner); gap != "" {
		cov.Missed(1, gap)
	} else {
		cov.Covered(1)
		out = append(out, f...)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, cov.Err()
}

// --- the management interface ------------------------------------------------

const pveproxyDefaults = "/etc/default/pveproxy"

// auditWebUI decides whether pveproxy answers anyone who can route to it.
//
// Upstream's defaults are the finding: listen on the wildcard address, and a
// POLICY of allow when no ACL matches. Either of two settings narrows it —
// LISTEN_IP, or an allow-list that something actually enforces. ALLOW_FROM on
// its own enforces nothing, because what it does is win over a DENY_FROM, and
// with the default policy an address that matches neither is let in anyway.
func (c *Checker) auditWebUI() ([]model.Finding, string) {
	path := c.path(pveproxyDefaults)
	vars := map[string]string{}
	b, err := platform.ReadFileBounded(path, 1<<20)
	switch {
	case err == nil:
		vars = shellVars(string(b))
	case os.IsNotExist(err):
		// Absent is the package default, which is a complete answer.
	default:
		return nil, "could not read " + pveproxyDefaults + " — the web interface's access list was not audited"
	}

	if strings.TrimSpace(vars["LISTEN_IP"]) != "" {
		return nil, ""
	}
	allow := vars["ALLOW_FROM"]
	restricted := allow != "" && !coversEverything(allow) &&
		(strings.EqualFold(vars["POLICY"], "deny") || coversEverything(vars["DENY_FROM"]))
	if restricted {
		return nil, ""
	}

	opts := []model.FindingOption{
		model.WithDescription(
			"The Proxmox VE web interface and API (pveproxy, port 8006) listen on every address and accept a login from anywhere that can route to them — the package default. " +
				"Behind that login is every guest, every disk and the host's own shell, and the usual account is root@pam with the host's root password, " +
				"so the only thing between the LAN (or wherever else 8006 reaches) and the whole hypervisor is one password."),
		model.WithHowToFix(
			"Restrict who can reach it in " + pveproxyDefaults + ": `ALLOW_FROM=\"192.168.1.0/24\"`, `DENY_FROM=\"all\"` and `POLICY=\"allow\"` with your management network, then `systemctl restart pveproxy`. " +
				"On a single node `LISTEN_IP` on the management address works too — but not on a cluster, where the nodes reach each other's pveproxy on addresses that may be in other subnets. " +
				"A firewall rule for 8006 does the same job from the other side."),
		model.WithEvidence("port", "8006"),
	}
	if err == nil {
		opts = append(opts, model.WithEvidence("config", path))
	} else {
		opts = append(opts, model.WithEvidence("config", pveproxyDefaults+" (absent: package defaults)"))
	}
	for _, k := range []string{"ALLOW_FROM", "DENY_FROM", "POLICY"} {
		if v, ok := vars[k]; ok {
			opts = append(opts, model.WithEvidence(strings.ToLower(k), v))
		}
	}
	return []model.Finding{model.NewFinding("proxmox.webui-open",
		"The Proxmox VE web interface accepts logins from any address",
		model.SeverityMedium, model.SourceProxmox, model.RemediationManual, opts...)}, ""
}

// coversEverything reports whether a pveproxy address list names all
// addresses: `all`, or the zero-length prefixes it is an alias for.
func coversEverything(list string) bool {
	for _, f := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		switch strings.ToLower(f) {
		case "all", "0/0", "0.0.0.0/0", "::/0":
			return true
		}
	}
	return false
}

// shellVars reads KEY=value assignments from a file sourced by a shell script,
// which is what /etc/default/pveproxy is. Comments and blank lines are skipped
// and one layer of quoting is removed; anything more elaborate than an
// assignment is not the shape of this file.
func shellVars(body string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.ContainsAny(k, " \t") {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		} else if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		out[k] = v
	}
	return out
}

// --- root's second factor -----------------------------------------------------

const tfaConfig = "/etc/pve/priv/tfa.cfg"

// tfaEntry is the part of one registered factor this audit reads. TfaInfo in
// proxmox-tfa omits `enable` when it is true, so absent means on.
type tfaEntry struct {
	Enable *bool `json:"enable"`
}

func (e tfaEntry) on() bool { return e.Enable == nil || *e.Enable }

// tfaUser holds the factor lists proxmox-tfa's TfaUserData serializes. The
// recovery codes are left out on purpose: they are a way back in when the
// factor is lost, not a factor, and a root with only those still logs in with
// a password alone.
type tfaUser struct {
	TOTP     []tfaEntry `json:"totp"`
	U2F      []tfaEntry `json:"u2f"`
	WebAuthn []tfaEntry `json:"webauthn"`
	Yubico   []tfaEntry `json:"yubico"`
}

func (u tfaUser) factors() int {
	n := 0
	for _, list := range [][]tfaEntry{u.TOTP, u.U2F, u.WebAuthn, u.Yubico} {
		for _, e := range list {
			if e.on() {
				n++
			}
		}
	}
	return n
}

// auditRootTFA reports root@pam logging in with a password alone.
//
// The file lives under /etc/pve/priv, which only root can read, so a non-root
// scan records a gap here rather than guessing: "could not look" and "no
// second factor" would otherwise score the same.
func (c *Checker) auditRootTFA() ([]model.Finding, string) {
	b, err := platform.ReadFileBounded(c.path(tfaConfig), 4<<20)
	var users map[string]tfaUser
	switch {
	case err == nil:
		var cfg struct {
			Users map[string]tfaUser `json:"users"`
		}
		if jerr := json.Unmarshal(b, &cfg); jerr != nil {
			return nil, "could not parse " + tfaConfig + " — root's second factor was not audited"
		}
		users = cfg.Users
	case os.IsNotExist(err):
		// Written on the first enrolment, so no file means nobody has one.
	default:
		return nil, "could not read " + tfaConfig + " — root's second factor was not audited; re-run with sudo"
	}
	if users["root@pam"].factors() > 0 {
		return nil, ""
	}
	return []model.Finding{model.NewFinding("proxmox.root-no-tfa",
		"root@pam logs in to Proxmox VE with a password alone",
		model.SeverityMedium, model.SourceProxmox, model.RemediationManual,
		model.WithDescription(
			"root@pam has no enabled second factor — no TOTP, WebAuthn, U2F or Yubico entry in "+tfaConfig+". "+
				"It is the account that can do everything on the hypervisor, it cannot be renamed, and its password is the host's own root password, "+
				"so a guessed, reused or phished password is the whole of the host and every guest on it."),
		model.WithHowToFix(
			"Log in as root@pam and add a second factor under Datacenter → Permissions → Two Factor (TOTP or a WebAuthn key), then generate recovery keys and store them off the host. "+
				"Better still, do day-to-day work as a separate admin user in the pve realm with its own second factor, and keep root@pam for emergencies."),
		model.WithEvidence("user", "root@pam"),
		model.WithEvidence("config", tfaConfig),
	)}, ""
}

// --- updates actually arriving ------------------------------------------------

const enterpriseHost = "enterprise.proxmox.com"

// auditRepos reports an enterprise repository enabled on a host with no active
// subscription.
//
// That is the out-of-box state of every PVE install, and it fails quietly in
// the worst direction: `apt update` gets a 401 from the enterprise mirror,
// prints an error most people learn to ignore, and the host stops receiving
// Proxmox's own security updates while Debian's keep arriving and make it look
// patched. The updates domain cannot see this — it counts pending updates from
// the lists apt did manage to fetch.
func (c *Checker) auditRepos(ctx context.Context, r platform.CommandRunner) ([]model.Finding, string) {
	enabled, unread := c.enterpriseSources()
	if len(unread) > 0 {
		return nil, "could not read " + strings.Join(unread, ", ") + " — the package sources were not audited"
	}
	if len(enabled) == 0 {
		return nil, ""
	}

	if !platform.Has(r, "pvesubscription") {
		return nil, "an enterprise repository is enabled and pvesubscription is not installed to say whether a subscription covers it"
	}
	outb, err := r.Run(ctx, "pvesubscription", "get")
	if err != nil {
		return nil, "`pvesubscription get` failed — whether the enterprise repository is usable was not audited"
	}
	status := ""
	for _, line := range strings.Split(string(outb), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "status" {
			status = strings.ToLower(strings.TrimSpace(v))
		}
	}
	if status == "" {
		return nil, "`pvesubscription get` printed no status — whether the enterprise repository is usable was not audited"
	}
	if status == "active" {
		return nil, ""
	}
	// One file is one edit: the enterprise source rewritten to the
	// no-subscription one, which is signed by the same key. Two — PVE's and
	// Ceph's — are two edits, and a fix makes one.
	kind, why := model.RemediationReview, ""
	if len(enabled) != 1 {
		kind, why = model.RemediationManual, "The enterprise repository is enabled in "+strconv.Itoa(len(enabled))+
			" files, and a fix rewrites one file at a time."
	}
	return []model.Finding{model.NewFinding("proxmox.enterprise-repo-unsubscribed",
		"Proxmox updates come from a repository this host cannot use",
		model.SeverityMedium, model.SourceProxmox, kind, model.WithWhyNoFix(why),
		model.WithDescription(
			"The enterprise repository is enabled ("+strings.Join(enabled, ", ")+") but the subscription status is \""+status+"\", "+
				"so every `apt update` is refused by "+enterpriseHost+" and the Proxmox packages — the kernel, QEMU, the management stack — stop receiving updates. "+
				"Debian's own updates keep arriving, which is what makes the host look patched while the part that runs every guest is not."),
		model.WithHowToFix(
			"Either add a subscription (`pvesubscription set <key>`), or disable the enterprise repository and enable the no-subscription one: "+
				"set `Enabled: no` in the enterprise .sources file (or comment out the .list line), add the pve-no-subscription repository for your release as described in the Proxmox VE Package Repositories documentation, then `apt update && apt full-upgrade`. "+
				"The Repositories panel under the node in the web interface does both."),
		model.WithEvidence("status", status),
		model.WithEvidence("sources", strings.Join(enabled, ", ")),
	)}, ""
}

// enterpriseSources returns the apt source files that enable a Proxmox
// enterprise repository — PVE's own or Ceph's, in either the one-line format
// PVE 8 ships or the deb822 format PVE 9 does.
func (c *Checker) enterpriseSources() (enabled, unread []string) {
	files := []string{c.path("/etc/apt/sources.list")}
	for _, pat := range []string{"*.list", "*.sources"} {
		m, _ := filepath.Glob(c.path(filepath.Join("/etc/apt/sources.list.d", pat)))
		files = append(files, m...)
	}
	for _, f := range files {
		b, err := platform.ReadFileBounded(f, 1<<20)
		if err != nil {
			if !os.IsNotExist(err) {
				unread = append(unread, f)
			}
			continue
		}
		var on bool
		if strings.HasSuffix(f, ".sources") {
			on = deb822Enables(string(b))
		} else {
			on = oneLineEnables(string(b))
		}
		if on {
			enabled = append(enabled, strings.TrimPrefix(f, strings.TrimSuffix(c.Root, "/")))
		}
	}
	sort.Strings(enabled)
	return enabled, unread
}

func oneLineEnables(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "deb ") && strings.Contains(line, enterpriseHost) {
			return true
		}
	}
	return false
}

// deb822Enables reads the stanza format: stanzas separated by blank lines, each
// one off only when it says `Enabled: no`.
func deb822Enables(body string) bool {
	for _, stanza := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n\n") {
		uris, off := false, false
		field := ""
		for _, line := range strings.Split(stanza, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			// A field may continue on indented lines, and a URI on one of
			// them has a colon of its own, so it must not be read as a key.
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				if field == "uris" && strings.Contains(line, enterpriseHost) {
					uris = true
				}
				continue
			}
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			field = strings.ToLower(strings.TrimSpace(k))
			switch field {
			case "uris":
				uris = strings.Contains(v, enterpriseHost)
			case "enabled":
				switch strings.ToLower(strings.TrimSpace(v)) {
				case "no", "false":
					off = true
				}
			}
		}
		if uris && !off {
			return true
		}
	}
	return false
}
