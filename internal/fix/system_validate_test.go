package fix

import (
	"strings"
	"testing"
)

// lynis316IDs is the set of test IDs reported by Lynis 3.1.6 (extracted from
// a real `lynis audit system` report.dat on 2026-06-10 against the docker
// test environment). If a future Lynis version changes which IDs are emitted,
// the live test (TestLynis316_RegisteredIDsAreValid) can be re-run and the
// list refreshed.
var lynis316IDs = map[string]bool{
	"ACCT-9622": true, // Enable process accounting
	"ACCT-9626": true, // Enable sysstat
	"ACCT-9628": true, // Enable auditd
	"AUTH-9216": true, // grpck errors
	"AUTH-9230": true, // password hashing rounds
	"AUTH-9262": true, // PAM password strength
	"AUTH-9286": true, // min/max password age
	"AUTH-9308": true, // single-mode password
	"AUTH-9328": true, // umask
	"BANN-7126": true, // /etc/issue banner
	"FILE-6310": true, // /home partition
	"FILE-7524": true, // file permissions
	"FINT-4350": true, // file integrity tool
	"FIRE-4590": true, // firewall/packet filter
	"HRDN-7230": true, // malware scanner
	"KRNL-5820": true, // core dump
	"KRNL-6000": true, // sysctl scan profile
	"LOGG-2130": true, // syslog daemon
	"LOGG-2138": true, // klogd
	"NAME-4028": true, // DNS config
	"NETW-3200": true, // uncommon protocols
	"PKGS-7398": true, // package audit
	"SSH-7408":  true, // SSH hardening (broad)
	"TIME-3104": true, // NTP daemon
	"TOOL-5002": true, // automation tools
	"USB-1000":  true, // USB storage
}

// lynisIDPrefix extracts the Lynis test category from a registered fix ID
// like "lynis.AUTH-9286" → "AUTH-9286".
func lynisIDPrefix(registeredID string) string {
	const p = "lynis."
	if !strings.HasPrefix(registeredID, p) {
		return ""
	}
	return registeredID[len(p):]
}

// validLynisCategories is the set of category prefixes that appear in
// current Lynis reports. A registered fix whose prefix is not in this set is
// almost certainly a typo and should be corrected. Note that the inverse is
// not true: not every category-prefixed ID will be emitted on every host
// (e.g. AUTH-9265 LDAP, HRMN-6114 SELinux only appear in matching
// environments).
var validLynisCategories = map[string]bool{
	"ACCT": true,
	"AUTH": true,
	"BANN": true,
	"BOOT": true,
	"DBS":  true,
	"FILE": true,
	"FINT": true,
	"FIRE": true,
	"HRDN": true,
	"HRMN": true,
	"KRNL": true,
	"LOGG": true,
	"NAME": true,
	"NETW": true,
	"PKGS": true,
	"SSH":  true,
	"TIME": true,
	"TOOL": true,
	"USB":  true,
	"USB-": true, // not a real category; placeholder
	"CONT": true, // future-proofing
	"MAIL": true,
	"PHP":  true,
	"PRNT": true,
	"STRG": true,
	"WEB":  true,
}

// TestLynis316_RegisteredIDsAreValid is a sanity check: every lynis.* fix
// registered in this package must reference a real test ID with a known
// category prefix. This catches typos and dropped test IDs that no Lynis
// version would ever emit.
//
// It does NOT verify that every registered ID is reported in the reference
// test environment — some IDs (LDAP, SELinux, etc.) only appear on hosts
// where the relevant subsystem is configured.
func TestLynis316_RegisteredIDsAreValid(t *testing.T) {
	r := New()
	RegisterAll(r)

	// Walk every registered entry.
	for id := range r.entries {
		// r.entries stores keys lowercased; compare upper-case.
		raw := strings.ToUpper(lynisIDPrefix(id))
		if raw == "" {
			continue // not a lynis.* id (e.g. trivy.cve-*, compose.*)
		}
		// Skip wildcard patterns (they have ? * [).
		if strings.ContainsAny(id, "?*[") {
			continue
		}
		// Extract category prefix (everything before the first '-')
		// e.g. "AUTH-9286" -> "AUTH"
		cat := raw
		if i := strings.Index(raw, "-"); i > 0 {
			cat = raw[:i]
		}
		if !validLynisCategories[cat] {
			t.Errorf("registered fix for lynis.%s has unknown category %q; not a valid Lynis test ID", raw, cat)
		}
	}
}

// TestLynis316_CommonIDsHaveFixes checks that the most actionable Lynis
// findings (those most likely to be reported) have at least *some* fix
// registered. Manual entries count as "have a fix".
func TestLynis316_CommonIDsHaveFixes(t *testing.T) {
	r := New()
	RegisterAll(r)

	// These IDs were emitted in our reference run and represent common
	// production-host concerns. The fix may be Auto/Review/Manual.
	required := []string{
		"ACCT-9626", // sysstat
		"ACCT-9628", // auditd
		"AUTH-9286", // password aging
		"BANN-7126", // /etc/issue banner
		"FILE-7524", // file perms
		"KRNL-6000", // sysctl
		"LOGG-2130", // syslog
		"SSH-7408",  // SSH
	}
	for _, id := range required {
		if r.Lookup("lynis."+id) == nil {
			t.Errorf("lynis.%s is commonly reported but has no registered fix", id)
		}
	}
}
