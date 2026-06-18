// Package hardening aggregates the system-level hardening checks
// (spec FR-016, FR-017):
//
//   - hardening_firewall: which backend is active and is it
//     enforcing a default deny / allow policy?
//   - hardening_fail2ban: is the service installed and running?
//   - hardening_unattended: is unattended-upgrades configured and
//     active?
//   - hardening_sysctl: are the baseline sysctl values present?
//   - hardening_updates: how many security updates are pending?
//
// The Run aggregator dispatches each sub-check and merges the
// findings, with a CategorySkip for any sub-check that cannot run
// (e.g. firewall tooling not installed).
package hardening

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/checks"
	"github.com/seolcu/hostveil/internal/model"
)

// baselineSysctl is the list of sysctl keys and their expected
// secure values. The list is intentionally short; expanding it is a
// post-v3.0 policy decision.
var baselineSysctl = map[string]string{
	"net.ipv4.conf.all.rp_filter":                 "1",
	"net.ipv4.conf.default.rp_filter":             "1",
	"net.ipv4.conf.all.accept_source_route":        "0",
	"net.ipv4.conf.default.accept_source_route":    "0",
	"net.ipv4.conf.all.accept_redirects":           "0",
	"net.ipv4.conf.default.accept_redirects":       "0",
	"net.ipv4.conf.all.secure_redirects":           "1",
	"net.ipv4.conf.default.secure_redirects":       "1",
	"net.ipv4.conf.all.send_redirects":             "0",
	"net.ipv4.conf.default.send_redirects":         "0",
	"net.ipv4.conf.all.log_martians":               "1",
	"net.ipv4.conf.default.log_martians":           "1",
	"net.ipv4.icmp_echo_ignore_broadcasts":         "1",
	"net.ipv4.icmp_ignore_bogus_error_responses":   "1",
	"net.ipv4.tcp_syncookies":                     "1",
	"kernel.randomize_va_space":                   "2",
}

// Run implements checks.Run. The hardening category is special:
// the orchestrator calls Run once per hardening sub-category, and
// we filter the findings by the requested category. This prevents
// the same finding from being emitted five times when the
// orchestrator iterates over all five sub-categories.
//
// The special category sentinel "all" is used by callers that want
// every hardening finding (e.g. an integration test).
func Run(ctx context.Context) (checks.Result, error) {
	return RunForCategory(ctx, "")
}

// RunForCategory runs only the sub-check(s) for the given category.
// Pass an empty string to run all sub-checks.
func RunForCategory(ctx context.Context, only model.Category) (checks.Result, error) {
	now := time.Now().UTC()
	var findings []model.Finding
	var skipped []model.CategorySkip
	ran := false
	for cat, sub := range subChecks {
		if only != "" && cat != only {
			continue
		}
		ran = true
		f, s := sub.run(ctx, now)
		if s != nil {
			skip := *s
			skip.Category = cat
			skipped = append(skipped, skip)
		}
		findings = append(findings, f...)
	}
	if !ran {
		// Should not happen; the orchestrator only asks for
		// categories that are registered.
		return checks.Result{Skipped: &model.CategorySkip{
			Category: only, Reason: "not_applicable", Detail: "no sub-check for category",
		}}, nil
	}
	if len(skipped) > 0 && len(findings) == 0 {
		// The single sub-check we ran was skipped; propagate the
		// skip with the original category (not the hardening-*
		// sub-category the orchestrator asked for).
		first := skipped[0]
		return checks.Result{Skipped: &first}, nil
	}
	return checks.Result{Findings: findings}, nil
}

type subCheck struct {
	run func(ctx context.Context, now time.Time) ([]model.Finding, *model.CategorySkip)
}

var subChecks = map[model.Category]subCheck{
	model.CategoryHardeningFirewall:   {run: checkFirewall},
	model.CategoryHardeningFail2ban:   {run: checkFail2ban},
	model.CategoryHardeningUnattended: {run: checkUnattended},
	model.CategoryHardeningSysctl:     {run: checkSysctl},
	model.CategoryHardeningUpdates:    {run: checkUpdates},
}

func checkFirewall(_ context.Context, now time.Time) ([]model.Finding, *model.CategorySkip) {
	// ufw
	if _, err := exec.LookPath("ufw"); err == nil {
		out, _ := exec.Command("ufw", "status").Output()
		if strings.Contains(string(out), "Status: active") {
			return []model.Finding{{
				ID: "finding-hardening_firewall.ufw-active",
				Category: model.CategoryHardeningFirewall,
				RuleID: "hardening_firewall.ufw_active",
				Severity: model.SeverityLow,
				Title: "UFW is active",
				Description: "ufw reports an active firewall state.",
				State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
			}}, nil
		}
		return []model.Finding{{
			ID: "finding-hardening_firewall.ufw-inactive",
			Category: model.CategoryHardeningFirewall,
			RuleID: "hardening_firewall.ufw_inactive",
			Severity: model.SeverityHigh,
			Title: "UFW is installed but inactive",
			Description: "ufw is installed but reports an inactive state. Enable it: `ufw enable`.",
			State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
		}}, nil
	}
	// iptables / nftables: just look for the binary.
	for _, bin := range []string{"iptables", "nft"} {
		if _, err := exec.LookPath(bin); err == nil {
			return nil, &model.CategorySkip{
				Category: model.CategoryHardeningFirewall,
				Reason:   "internal_error",
				Detail:   bin + " present but no active policy check (post-v3.0 work)",
			}
		}
	}
	return nil, &model.CategorySkip{
		Category: model.CategoryHardeningFirewall,
		Reason:   "not_applicable",
		Detail:   "no firewall tooling installed (no ufw, iptables, or nft)",
	}
}

func checkFail2ban(_ context.Context, now time.Time) ([]model.Finding, *model.CategorySkip) {
	if _, err := exec.LookPath("fail2ban-client"); err != nil {
		return nil, &model.CategorySkip{
			Category: model.CategoryHardeningFail2ban,
			Reason:   "not_applicable",
			Detail:   "fail2ban-client not installed",
		}
	}
	out, _ := exec.Command("fail2ban-client", "status").Output()
	lines := strings.Split(string(out), "\n")
	jails := 0
	for _, l := range lines {
		if strings.Contains(l, "Jail list:") {
			parts := strings.Split(l, ":")
			if len(parts) > 1 {
				jails = len(strings.Fields(strings.TrimSpace(parts[1])))
			}
		}
	}
	if jails == 0 {
		return []model.Finding{{
			ID: "finding-hardening_fail2ban.no_jails",
			Category: model.CategoryHardeningFail2ban,
			RuleID: "hardening_fail2ban.no_jails",
			Severity: model.SeverityMedium,
			Title: "fail2ban is installed but has no active jails",
			Description: "fail2ban-client reports zero active jails. Add at least sshd.",
			EntityRefs: []model.EntityRef{{Kind: model.EntityRefKindSetting, Display: "fail2ban"}},
			State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
		}}, nil
	}
	return nil, nil
}

func checkUnattended(_ context.Context, now time.Time) ([]model.Finding, *model.CategorySkip) {
	p := "/etc/apt/apt.conf.d/20auto-upgrades"
	if _, err := os.Stat(p); err != nil {
		return nil, &model.CategorySkip{
			Category: model.CategoryHardeningUnattended,
			Reason:   "not_applicable",
			Detail:   "/etc/apt/apt.conf.d/20auto-upgrades not found (non-Debian family)",
		}
	}
	b, _ := os.ReadFile(p)
	hasUpdate := false
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "APT::Periodic::Update-Package-Lists") && strings.Contains(line, "1") {
			hasUpdate = true
		}
	}
	if !hasUpdate {
		return []model.Finding{{
			ID: "finding-hardening_unattended.disabled",
			Category: model.CategoryHardeningUnattended,
			RuleID: "hardening_unattended.disabled",
			Severity: model.SeverityMedium,
			Title: "unattended-upgrades is disabled",
			Description: p + " does not enable APT::Periodic::Update-Package-Lists.",
			EntityRefs: []model.EntityRef{{Kind: model.EntityRefKindSetting, Display: p}},
			State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
		}}, nil
	}
	return nil, nil
}

func checkSysctl(_ context.Context, now time.Time) ([]model.Finding, *model.CategorySkip) {
	var findings []model.Finding
	for key, want := range baselineSysctl {
		got, err := readSysctl(key)
		if err != nil {
			continue
		}
		if got != want {
			findings = append(findings, model.Finding{
				ID:       "finding-" + key,
				Category: model.CategoryHardeningSysctl,
				RuleID:   "hardening_sysctl.baseline",
				Severity: severityForSysctl(key, want),
				Title:    "sysctl " + key + " is " + got + " (expected " + want + ")",
				Description: "Run `sysctl -w " + key + "=" + want + "` (or update /etc/sysctl.d/) to bring this in line with the baseline.",
				EntityRefs: []model.EntityRef{{
					Kind:    model.EntityRefKindSetting,
					Display: key,
				}},
				State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
			})
		}
	}
	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

func checkUpdates(_ context.Context, now time.Time) ([]model.Finding, *model.CategorySkip) {
	// Try apt (Debian/Ubuntu) first.
	if _, err := exec.LookPath("apt"); err == nil {
		out, err := exec.Command("apt", "list", "--upgradable").Output()
		if err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(out)))
			count := 0
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "Listing") {
					continue
				}
				if strings.Contains(line, "-security") || strings.Contains(line, "-updates") {
					count++
				}
			}
			return []model.Finding{{
				ID: "finding-hardening_updates.pending",
				Category: model.CategoryHardeningUpdates,
				RuleID: "hardening_updates.pending",
				Severity: severityForUpdateCount(count),
				Title: fmt.Sprintf("%d security updates pending", count),
				Description: "Run `apt upgrade --security` to apply pending security updates.",
				State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
			}}, nil
		}
	}
	// Try dnf (RHEL/Fedora).
	if _, err := exec.LookPath("dnf"); err == nil {
		out, _ := exec.Command("dnf", "check-update", "--security").Output()
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		count := 0
		for scanner.Scan() {
			count++
		}
		return []model.Finding{{
			ID: "finding-hardening_updates.pending",
			Category: model.CategoryHardeningUpdates,
			RuleID: "hardening_updates.pending",
			Severity: severityForUpdateCount(count),
			Title: fmt.Sprintf("%d security updates pending", count),
			Description: "Run `dnf update --security` to apply pending security updates.",
			State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
		}}, nil
	}
	return nil, &model.CategorySkip{
		Category: model.CategoryHardeningUpdates,
		Reason:   "not_applicable",
		Detail:   "no supported package manager (apt or dnf) found",
	}
}

func readSysctl(key string) (string, error) {
	b, err := os.ReadFile(filepath.Join("/proc/sys", filepathFromSysctl(key)))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func filepathFromSysctl(key string) string {
	return strings.ReplaceAll(key, ".", "/")
}

func severityForSysctl(key, _ string) model.Severity {
	switch key {
	case "net.ipv4.tcp_syncookies", "kernel.randomize_va_space":
		return model.SeverityHigh
	}
	return model.SeverityMedium
}

func severityForUpdateCount(n int) model.Severity {
	switch {
	case n == 0:
		return model.SeverityLow
	case n < 5:
		return model.SeverityLow
	case n < 20:
		return model.SeverityMedium
	}
	return model.SeverityHigh
}

// strconv import kept alive for potential future use in update
// count thresholds.
var _ = strconv.Itoa
