package fix

import (
	"bytes"
	"fmt"
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
// Every sysctl finding is Review, and the two alternatives are genuinely
// independent rather than two halves of one procedure:
//
//   - write a drop-in — persistent, and takes effect at the next boot or
//     the next `sysctl --system`;
//   - `sysctl -w` — takes effect immediately, and is lost at the next boot.
//
// Neither is strictly better, which is what makes this a choice rather
// than a sequence. An operator hardening a box they are about to reboot
// wants the first; one who cannot reboot a production host today wants the
// second now and the first later. Offering only "do both, in order" would
// be the sequential shape Review exists to refuse.
//
// This is the arrangement fix.Default's register anticipated: the blocker
// was that an edit action could not create a file, so the drop-in
// alternative could not exist and the remaining one had no partner.
func registerSysctl(r *Registry) {
	for _, id := range []string{
		"sysctl.ptrace-scope",
		"sysctl.syncookies",
		"sysctl.accept-redirects",
		"sysctl.protected-links",
		"sysctl.kptr-restrict",
		"sysctl.dmesg-restrict",
		"sysctl.sysrq",
		"sysctl.rp-filter",
	} {
		r.Register(id, buildSysctl)
	}
}

// buildSysctl assembles both alternatives from the finding's "set"
// evidence, which carries the exact key=value pairs the checker audited.
func buildSysctl(f model.Finding) (Fix, error) {
	pairs, err := sysctlPairs(f)
	if err != nil {
		return Fix{}, err
	}

	path := dropInDir + "60-hostveil-" + strings.TrimPrefix(f.ID, "sysctl.") + ".conf"
	body := sysctlDropIn(f, pairs)

	var commands [][]string
	for _, kv := range pairs {
		commands = append(commands, []string{"sysctl", "-w", kv})
	}

	return Fix{
		Label: "Harden " + strings.Join(keysOf(pairs), ", "),
		Kind:  model.RemediationReview,
		Actions: []Action{
			{
				Label:           "Persist it: write " + path,
				Warning:         "Takes effect at the next boot, or immediately if you then run `sysctl --system`. The running kernel keeps its current value until one of those happens.",
				Kind:            ActionEdit,
				Path:            path,
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
			},
			{
				Label: "Apply it now: " + strings.Join(keysOf(pairs), ", "),
				// Exec actions have no checkpoint, and this one genuinely
				// has nothing to undo from: the previous value is in the
				// finding's evidence, not on disk, and a reboot reverts it
				// anyway. Say so rather than implying a rollback exists.
				Warning:  "Changes the running kernel immediately and is lost at the next boot. There is no rollback checkpoint: exec fixes are not file-backed.",
				Kind:     ActionExec,
				Commands: commands,
			},
		},
	}, nil
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
