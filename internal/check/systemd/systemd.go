// Package systemd audits the sandboxing of the services an operator
// installed themselves.
//
// A self-hosted server is a pile of long-running programs, and roughly half
// of them are not in containers. The compose domain covers the half that
// are: it reads what each service declares and says so when a container runs
// privileged, as root, or with no-new-privileges off. A service started by a
// unit file gets exactly the same decisions made about it — whether it can
// gain privileges, whether it can write outside its own data, whether it can
// read every user's home — and until this domain existed nothing looked at
// them at all.
//
// systemd already answers all of it. `systemctl show` reports the *effective*
// value of each property after the unit file, every drop-in, and every
// default have been merged, so this checker never has to model that
// precedence, and a value it reports is the value the service will run with.
//
// # Which units
//
// Only units whose fragment lives under /etc/systemd/system or
// /usr/local/lib/systemd/system: the ones the operator wrote or installed by
// hand. That is a deliberate line, not a shortcut.
//
// A distribution's own units are hardened by the distribution, on its
// schedule, and a drop-in that second-guesses them is the operator taking on
// maintenance of somebody else's service. More to the point, flagging them
// would bury the operator's own services under dozens of findings about
// software they did not choose to run and cannot sensibly change — and a
// domain that accuses everything is a domain nobody reads. The units this
// package reports on are the ones whose author is the person reading the
// report.
package systemd

import (
	"context"
	"fmt"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// operatorUnitDirs are the directories a unit file lives in when a person
// rather than a package put it there. /run is deliberately absent: units
// generated at boot are nobody's to edit and do not survive a reboot.
var operatorUnitDirs = []string{
	"/etc/systemd/system/",
	"/usr/local/lib/systemd/system/",
}

// showProperties are the unit properties this domain reads. Asked for in one
// batched call rather than one call per unit: a host with thirty operator
// units would otherwise be thirty round trips through the runner, each
// bounded by platform.DefaultTimeout, inside a scan that already runs every
// domain concurrently.
var showProperties = []string{
	"Id",
	"LoadState",
	"FragmentPath",
	"User",
	"NoNewPrivileges",
	"ProtectSystem",
	"ProtectHome",
	"PrivateTmp",
	// Which drop-ins systemd actually loaded for this unit, in the order it
	// applied them. Asked for because the fix writes a drop-in, and a drop-in
	// competes on filename: see dropInPath.
	"DropInPaths",
}

// Checker reports services running with systemd's protections switched off.
type Checker struct {
	// UnitDirs is the set of fragment path prefixes counted as operator
	// installed; overridable for tests.
	UnitDirs []string
}

// New returns a systemd service-hardening checker.
func New() *Checker { return &Checker{UnitDirs: operatorUnitDirs} }

// Source identifies the systemd domain.
func (*Checker) Source() model.Source { return model.SourceSystemd }

// Available requires systemd to be the service manager and to answer.
//
// The manager property is asked for rather than `systemctl` merely being on
// PATH: the binary is installed on hosts that boot something else, and on
// those it exits non-zero with "System has not been booted with systemd".
// Treating its presence as an answer would enumerate no units, find nothing,
// and score this axis a perfect 100 on a host it never looked at.
func (c *Checker) Available(ctx context.Context, env platform.Env) (bool, string) {
	if env.ServiceManager != platform.SMSystemd {
		return false, "systemd is not this host's service manager — there are no units to audit"
	}
	if !platform.Has(env.Runner, "systemctl") {
		return false, "systemctl is not installed — units cannot be read"
	}
	if _, err := env.Runner.Run(ctx, "systemctl", "show", "--property=Version"); err != nil {
		return false, "systemd did not answer — units cannot be read"
	}
	return true, ""
}

// Check reads every loaded service unit and reports the operator-installed
// ones running without systemd's protections.
func (c *Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	args := append([]string{"show", "*.service"}, "--property="+strings.Join(showProperties, ","))
	out, err := env.Runner.Run(ctx, "systemctl", args...)
	if err != nil {
		return nil, fmt.Errorf("listing service units: %w", err)
	}

	var findings []model.Finding
	for _, u := range parseUnits(string(out)) {
		if !c.operatorInstalled(u) {
			continue
		}
		for _, r := range rules {
			if !r.flagged(u) {
				continue
			}
			findings = append(findings, r.finding(u))
		}
	}
	return findings, nil
}

// operatorInstalled reports whether a unit is one the person reading the
// report installed. A unit systemd could not load has no properties worth
// judging and no fragment to point at.
func (c *Checker) operatorInstalled(u unit) bool {
	if u.LoadState != "loaded" || u.FragmentPath == "" {
		return false
	}
	for _, dir := range c.UnitDirs {
		if strings.HasPrefix(u.FragmentPath, dir) {
			return true
		}
	}
	return false
}

// unit is one service's effective configuration as systemd reports it.
type unit struct {
	ID              string
	LoadState       string
	FragmentPath    string
	User            string
	NoNewPrivileges string
	ProtectSystem   string
	ProtectHome     string
	PrivateTmp      string
	// DropInPaths is the space-separated list systemd reports, which is every
	// drop-in it loaded for this unit from /etc, /run and /usr/lib alike.
	DropInPaths string
}

// root reports whether the service runs as root, which is what decides how
// much the filesystem protections are worth. systemd reports an unset User
// as the empty string, and that is the common case: a unit that says nothing
// runs as root.
func (u unit) root() bool { return u.User == "" || u.User == "root" }

// parseUnits splits `systemctl show` output into one record per unit.
//
// systemd separates records with a blank line and prints Key=Value one per
// line, in an order of its own choosing — so records are keyed by name, never
// by position. A value may itself contain "=", so only the first is a
// separator.
func parseUnits(out string) []unit {
	var units []unit
	cur := map[string]string{}
	flush := func() {
		if len(cur) == 0 {
			return
		}
		units = append(units, unit{
			ID:              cur["Id"],
			LoadState:       cur["LoadState"],
			FragmentPath:    cur["FragmentPath"],
			User:            cur["User"],
			NoNewPrivileges: cur["NoNewPrivileges"],
			ProtectSystem:   cur["ProtectSystem"],
			ProtectHome:     cur["ProtectHome"],
			PrivateTmp:      cur["PrivateTmp"],
			DropInPaths:     cur["DropInPaths"],
		})
		cur = map[string]string{}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			cur[k] = v
		}
	}
	flush()
	return units
}
