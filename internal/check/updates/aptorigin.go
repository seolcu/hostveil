package updates

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/seolcu/hostveil/internal/platform"
)

// This file answers, for apt, the question internal/check/sysctl/origin.go
// answers for the kernel: not "what does this one file say" but "what is in
// force, and which file put it there".
//
// It matters for the same reason and on the same shape of host. apt reads
// every file in /etc/apt/apt.conf.d in lexical order and the last assignment
// wins. Cloud images and several hardening guides ship
// 99-disable-auto-upgrades setting `APT::Periodic::Unattended-Upgrade "0";`.
// hostveil read 20auto-upgrades alone — and so did its fix, which wrote "1"
// into that file, after which the checker re-read the same file, saw "1", and
// reported the finding fixed. apt went on reading "0".
//
// Checker and fix shared one wrong oracle, which is exactly what made it
// invisible: the round-trip test in internal/fix closes over the checker, so a
// fix that satisfies a checker looking at the wrong file passes it.
//
// AGENTS.md states the rule this now follows: ask the tool that owns a layered
// configuration for the effective value instead of re-deriving it.

// aptConfDir is where apt reads its fragments from.
const aptConfDir = "/etc/apt/apt.conf.d"

// periodicKey is the option that decides whether unattended upgrades run.
const periodicKey = "APT::Periodic::Unattended-Upgrade"

// aptEffective asks apt what the option resolves to.
//
// `apt-config dump <key>` prints `APT::Periodic::Unattended-Upgrade "1";` when
// the key is set anywhere and nothing when it is not, having applied its own
// precedence over every fragment. That is the same move as reading kernel
// parameters through the file systemd-sysctl will actually apply, and as
// asking `docker compose config` for a merged project.
//
// The third return is whether apt could be asked at all. A host without
// apt-config is not a host with the option unset, and the caller must not
// read it as one.
func aptEffective(ctx context.Context, r platform.CommandRunner) (value string, set, ok bool) {
	if !platform.Has(r, "apt-config") {
		return "", false, false
	}
	out, err := r.Run(ctx, "apt-config", "dump", periodicKey)
	if err != nil {
		return "", false, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, periodicKey) {
			continue
		}
		// APT::Periodic::Unattended-Upgrade "1";
		if a := strings.Index(line, `"`); a >= 0 {
			if b := strings.Index(line[a+1:], `"`); b >= 0 {
				return line[a+1 : a+1+b], true, true
			}
		}
	}
	return "", false, true
}

// aptOrigin names the file whose assignment apt reads last, which is the file
// a fix has to edit. It returns "" when no fragment assigns the key, in which
// case there is nothing outranking the conventional one.
//
// Lexical order over the directory, which is apt's own rule. Files apt ignores
// — anything with an extension other than .conf, and dpkg's backup suffixes —
// are skipped, because naming one as the winner would send a fix to edit a
// file apt never opens.
func aptOrigin(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !aptReadsFragment(e.Name()) {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	winner := ""
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path) //nolint:gosec // a path under apt's own config directory
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			if strings.Contains(line, "Unattended-Upgrade") {
				winner = path
				break
			}
		}
	}
	return winner
}

// aptReadsFragment follows apt's own rule for which files in apt.conf.d it
// parses: a plain name, or one ending in .conf. Everything else — dpkg's
// .dpkg-dist and .ucf-old leftovers, editor backups — is ignored, and a fix
// sent to edit one of those would change nothing.
func aptReadsFragment(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") {
		return false
	}
	// apt accepts a bare name or one ending in .conf, built from alphanumerics
	// with hyphens and underscores. Everything else it skips — which is what
	// keeps 99-disable.dpkg-dist and 99-backup~ out, and both of those sit in
	// apt.conf.d on real hosts.
	base := strings.TrimSuffix(name, ".conf")
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return false
		}
	}
	return base != ""
}
