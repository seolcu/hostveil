package fix

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// dropInDir is where a persistent kernel parameter belongs on any systemd
// distribution. hostveil writes one file per finding rather than appending
// to a shared one, which is what keeps the fixes independent: applying the
// second never has to read what the first wrote, and rolling one back
// cannot take another's line with it.
const dropInDir = "/etc/sysctl.d/"

// registerSysctl wires the kernel-hardening fixes into the registry.
//
// Unambiguous sysctl findings are Auto: one reversible drop-in records the
// desired value without changing the running kernel underneath an unattended
// operator. Topology-dependent findings are Review, with two genuinely
// independent alternatives rather than two halves of one procedure:
//
//   - write a drop-in — persistent, and takes effect at the next boot or
//     the next `sysctl --system`;
//   - `sysctl -w` — takes effect immediately, and is lost at the next boot.
//
// Neither is strictly better for those topology-dependent controls, which is
// what makes this a choice rather than a sequence. Offering only "do both, in
// order" would be the sequential shape Review exists to refuse.
//
// This is the arrangement fix.Default's register anticipated: the blocker
// was that an edit action could not create a file, so the drop-in
// alternative could not exist and the remaining one had no partner.
func registerSysctl(r *Registry) {
	review := map[string]bool{
		"sysctl.sysrq": true, "sysctl.rp-filter": true,
		"sysctl.send-redirects": true, "sysctl.ipv4-default-rp-filter": true,
		"sysctl.proxy-arp-all": true, "sysctl.proxy-arp-default": true,
		"sysctl.multicast-forwarding": true, "sysctl.bootp-relay": true,
	}
	for _, id := range []string{
		"sysctl.ptrace-scope",
		"sysctl.syncookies",
		"sysctl.accept-redirects",
		"sysctl.protected-links",
		"sysctl.kptr-restrict",
		"sysctl.dmesg-restrict",
		"sysctl.sysrq",
		"sysctl.rp-filter",
		"sysctl.accept-source-route",
		"sysctl.send-redirects",
		"sysctl.suid-dumpable",
		"sysctl.protected-fifos",
		"sysctl.protected-regular",
		"sysctl.unprivileged-bpf",
		"sysctl.perf-events",
		"sysctl.icmp-broadcasts",
		"sysctl.bogus-icmp-errors",
		"sysctl.log-martians",
		"sysctl.aslr",
		"sysctl.core-uses-pid",
		"sysctl.ctrl-alt-del",
		"sysctl.bpf-jit-harden",
		"sysctl.tty-ldisc-autoload",
		"sysctl.ipv6-accept-redirects-all",
		"sysctl.ipv6-accept-redirects-default",
		"sysctl.ipv6-accept-source-route-all",
		"sysctl.ipv6-accept-source-route-default",
		"sysctl.ipv6-send-redirects",
		"sysctl.ipv4-default-accept-redirects",
		"sysctl.ipv4-default-rp-filter",
		"sysctl.proxy-arp-all",
		"sysctl.proxy-arp-default",
		"sysctl.multicast-forwarding",
		"sysctl.bootp-relay",
		"sysctl.tcp-rfc1337",
	} {
		builder := buildSysctl
		if review[id] {
			builder = buildSysctlReview
		}
		r.Register(id, builder)
	}
	for _, id := range []string{"sysctl.module-dccp", "sysctl.module-sctp", "sysctl.module-rds", "sysctl.module-tipc", "sysctl.module-usbstorage"} {
		r.Register(id, buildModuleBlock)
	}
}

func buildModuleBlock(f model.Finding) (Fix, error) {
	path, module := f.Evidence["config"], f.Evidence["module"]
	if path == "" || module == "" {
		return Fix{}, fmt.Errorf("finding %s has incomplete module evidence", f.ID)
	}
	return Fix{Label: "Block optional kernel module " + module, Kind: model.RemediationAuto, Actions: []Action{{Label: "Persist a modprobe install block", Warning: "Confirm this host does not use " + module + " before applying.", Kind: ActionEdit, Path: path, CreateIfMissing: true, TakesEffectOn: "the next reboot", Transform: func(in []byte) ([]byte, error) {
		line := "install " + module + " /bin/false"
		if strings.Contains(string(in), line) {
			return in, nil
		}
		out := append([]byte(nil), bytes.TrimRight(in, "\n")...)
		if len(out) > 0 {
			out = append(out, '\n')
		}
		return append(out, []byte(line+"\n")...), nil
	}}}}, nil
}

// buildSysctl persists the finding's exact key=value pairs. It deliberately
// does not change the running kernel: that keeps unattended application a
// reversible file edit, while TakesEffectOn tells the operator that a reboot
// or an explicit sysctl --system is still required.
func buildSysctl(f model.Finding) (Fix, error) {
	pairs, err := sysctlPairs(f)
	if err != nil {
		return Fix{}, err
	}

	return Fix{
		Label:   "Harden " + strings.Join(keysOf(pairs), ", "),
		Kind:    model.RemediationAuto,
		Actions: []Action{persistSysctl(f, pairs)},
	}, nil
}

// buildSysctlReview retains an immediate, non-persistent alternative for
// settings whose correct persistent value depends on the host being a router,
// relay, or multi-homed. Those choices remain explicitly human-approved.
func buildSysctlReview(f model.Finding) (Fix, error) {
	pairs, err := sysctlPairs(f)
	if err != nil {
		return Fix{}, err
	}
	commands := make([][]string, 0, len(pairs))
	for _, kv := range pairs {
		commands = append(commands, []string{"sysctl", "-w", kv})
	}
	return Fix{
		Label: "Harden " + strings.Join(keysOf(pairs), ", "),
		Kind:  model.RemediationReview,
		Actions: []Action{
			persistSysctl(f, pairs),
			{Label: "Apply it now: " + strings.Join(keysOf(pairs), ", "), Warning: "Changes the running kernel immediately and has no rollback checkpoint.", Kind: ActionExec, Commands: commands},
		},
	}, nil
}

// legacyConfFile is read after every drop-in, so nothing written under
// /etc/sysctl.d can override it. Ubuntu ships /etc/sysctl.d/99-sysctl.conf as
// a symlink to it, which is how a file the operator has been editing for
// years quietly outranks anything hostveil writes.
const legacyConfFile = "/etc/sysctl.conf"

// persistSysctl builds the alternative that survives a reboot.
//
// Which file that is depends on the host. A drop-in only takes effect if
// nothing read after it assigns the same key, and systemd-sysctl reads every
// sysctl.d directory as one list sorted by file name — so a value already set
// in /etc/sysctl.conf, or in a drop-in sorting after ours, wins. Writing the
// drop-in anyway is the worst available outcome: the file appears, the fix
// reports success, a checkpoint is recorded, and the value comes back at the
// next boot with nothing to explain it.
//
// So when the checker named an origin that outranks the drop-in, this edits
// that file instead. The finding's "set-by" evidence carries it as path:line;
// only the path is used, because a line number recorded during the scan is
// not a safe index into the bytes handed to a pure Transform later.
// sysctlEffect is what puts a persisted parameter in force.
//
// Both persist actions carry it, and until they did this fact lived in their
// Warning prose — "The running kernel keeps its current value until one of
// those happens" — where a human could read it and nothing could act on it.
// The sysctl checker reads /proc/sys, so the file this fix writes is not the
// object the domain reports on: exactly the artifact-versus-oracle mismatch
// Action.TakesEffectOn exists to declare, present since before the field did.
//
// It is the first alternative of a Review, so `fix --all --review` takes this
// path — which is the path the measurement harness's reviewed phase takes, and
// that harness never reboots.
const sysctlEffect = "`sysctl --system`, or the next boot"

func persistSysctl(f model.Finding, pairs []string) Action {
	dropIn := dropInDir + "60-hostveil-" + strings.TrimPrefix(f.ID, "sysctl.") + ".conf"
	origin := originPath(f)

	if origin != "" && readAfter(origin, dropIn) && operatorOwned(origin) {
		return Action{
			Label:         "Persist it: correct " + origin,
			Warning:       "Edits a file you wrote. " + origin + " is read after everything in /etc/sysctl.d, so a new file there would be overridden — this changes the line that actually decides the value.",
			TakesEffectOn: sysctlEffect,
			Kind:          ActionEdit,
			Path:          origin,
			// No VerifyCmd: `sysctl -p` would *apply* the file rather than
			// check it, and the transform below only ever rewrites the value
			// of an existing assignment or appends a well-formed line, so it
			// cannot produce syntax the loader would reject.
			Transform: func(in []byte) ([]byte, error) {
				return setSysctlAssignments(in, pairs, sysctlStamp(f)), nil
			},
		}
	}

	body := sysctlDropIn(f, pairs)
	warning := ""
	if origin != "" && readAfter(origin, dropIn) {
		// Reachable only if a distribution ships a late-sorting file setting
		// an unsafe value, which none do — so hostveil does not edit
		// package-owned files under /usr/lib to work around it (an upgrade
		// would undo the change with no checkpoint involved). It says so
		// instead of reporting a success the next boot will contradict.
		warning = "This will not take effect: " + origin + " sets the same parameter and is read after /etc/sysctl.d. " +
			"Change it there, or remove that assignment, before relying on this file."
	}
	return Action{
		Label:           "Persist it: write " + dropIn,
		Warning:         warning,
		TakesEffectOn:   sysctlEffect,
		Kind:            ActionEdit,
		Path:            dropIn,
		CreateIfMissing: true,
		Transform: func(in []byte) ([]byte, error) {
			// Idempotent: a drop-in this fix already wrote is
			// returned unchanged rather than doubled. Applying a
			// fix twice is not an error the user should have to
			// avoid, and a file with the line twice is not wrong
			// so much as it is evidence of a tool that does not
			// know what it has done.
			if bytes.Contains(in, []byte(body)) {
				return in, nil
			}
			if len(in) > 0 && !bytes.HasSuffix(in, []byte("\n")) {
				in = append(in, '\n')
			}
			return append(in, []byte(body)...), nil
		},
	}
}

// originPath is the file the checker found setting the observed value, or ""
// when no file did — in which case the value is the kernel's own default and
// a drop-in is the right answer.
func originPath(f model.Finding) string {
	raw := f.Evidence["set-by"]
	if raw == "" {
		return ""
	}
	// path:line. Cut from the right: a path may contain a colon.
	if i := strings.LastIndex(raw, ":"); i > 0 {
		return raw[:i]
	}
	return raw
}

// readAfter reports whether origin is loaded after dropIn, which is what
// decides whether writing dropIn would change anything.
func readAfter(origin, dropIn string) bool {
	if origin == legacyConfFile {
		return true
	}
	return filepath.Base(origin) > filepath.Base(dropIn)
}

// operatorOwned reports whether a configuration file is the operator's to
// edit. Files under /usr/lib belong to a package and are replaced on upgrade;
// files under /run are regenerated at boot. Editing either would be undone by
// something that leaves no history entry and that rollback cannot reach.
func operatorOwned(path string) bool {
	return path == legacyConfFile || strings.HasPrefix(path, "/etc/")
}

// setSysctlAssignments rewrites each pair's value where the file already
// assigns that key, and appends the ones it does not.
//
// Every assignment of a key is rewritten, not just the last: the last is the
// one that wins today, but leaving an earlier line contradicting it turns the
// file into something whose effect an operator has to derive rather than
// read. The left-hand side is preserved byte for byte, which keeps the
// slash-separated spelling and systemd's leading "-" marker intact.
func setSysctlAssignments(in []byte, pairs []string, stamp string) []byte {
	lines := strings.Split(string(in), "\n")
	seen := map[string]bool{}
	for _, kv := range pairs {
		key, value, _ := strings.Cut(kv, "=")
		for i, line := range lines {
			lhs, _, ok := cutAssignment(line)
			if !ok || !sameSysctlKey(lhs, key) {
				continue
			}
			lines[i] = lhs + "= " + value
			seen[key] = true
		}
	}

	out := strings.Join(lines, "\n")
	var missing []string
	for _, kv := range pairs {
		if key, _, _ := strings.Cut(kv, "="); !seen[key] {
			missing = append(missing, kv)
		}
	}
	if len(missing) == 0 {
		return []byte(out)
	}
	// Appended rather than inserted: this file is read last, so the end of it
	// is the one position guaranteed to win.
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if !strings.Contains(out, stamp) {
		out += stamp
	}
	for _, kv := range missing {
		key, value, _ := strings.Cut(kv, "=")
		out += key + " = " + value + "\n"
	}
	return []byte(out)
}

// cutAssignment splits a configuration line at its "=", returning the
// left-hand side with its original spacing and comment lines rejected.
func cutAssignment(line string) (lhs, rhs string, ok bool) {
	if t := strings.TrimSpace(line); t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
		return "", "", false
	}
	l, r, found := strings.Cut(line, "=")
	if !found {
		return "", "", false
	}
	return l, r, true
}

// sameSysctlKey compares a line's left-hand side with a parameter name,
// ignoring spacing, the leading "-" marker, and dot-versus-slash separators.
// A glob never matches: it selects parameters beyond the one being fixed, so
// rewriting its value would change others silently.
func sameSysctlKey(lhs, key string) bool {
	got := strings.TrimPrefix(strings.TrimSpace(lhs), "-")
	if strings.ContainsAny(got, "*?") {
		return false
	}
	return strings.ReplaceAll(got, "/", ".") == strings.ReplaceAll(key, "/", ".")
}

// sysctlStamp is the comment written above an appended assignment. An
// unattributed line in a file the operator maintains is indistinguishable
// from something a compromise left behind.
func sysctlStamp(f model.Finding) string {
	return fmt.Sprintf("\n# Added by hostveil for %s (%s). Run: hostveil rollback <id> to revert.\n", f.ID, f.Title)
}

// sysctlPairs reads the key=value list the checker recorded.
//
// A finding without it is an error rather than a fix built from a guess:
// the alternative would be deriving the values from the finding ID, which
// is exactly the kind of invented mapping the CVE fixes are declined for.
func sysctlPairs(f model.Finding) ([]string, error) {
	raw := f.Evidence["set"]
	if raw == "" {
		return nil, fmt.Errorf("finding %s carries no 'set' evidence, so there is no value to write", f.ID)
	}
	var out []string
	for _, kv := range strings.Split(raw, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		if k, _, ok := strings.Cut(kv, "="); !ok || k == "" {
			return nil, fmt.Errorf("finding %s has malformed 'set' evidence %q", f.ID, raw)
		}
		out = append(out, kv)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("finding %s has empty 'set' evidence", f.ID)
	}
	return out, nil
}

// sysctlDropIn renders the file body: a comment naming what wrote it and
// why, then one `key = value` line per parameter.
//
// The comment matters more than it looks. This file appears in /etc on a
// host the operator administers, and an unattributed one-line config is
// indistinguishable from something a compromise left behind.
func sysctlDropIn(f model.Finding, pairs []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by hostveil for %s (%s).\n", f.ID, f.Title)
	b.WriteString("# Remove this file to revert, or run: hostveil rollback <id>\n")
	for _, kv := range pairs {
		k, v, _ := strings.Cut(kv, "=")
		fmt.Fprintf(&b, "%s = %s\n", k, v)
	}
	return b.String()
}

func keysOf(pairs []string) []string {
	out := make([]string, 0, len(pairs))
	for _, kv := range pairs {
		k, _, _ := strings.Cut(kv, "=")
		out = append(out, k)
	}
	return out
}
