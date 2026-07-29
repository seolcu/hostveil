package sysctl

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// This file answers a question the running value alone cannot: *which file*
// put it there.
//
// It matters because the obvious remediation is wrong on a common host. The
// fix's persistent alternative writes /etc/sysctl.d/60-hostveil-<id>.conf,
// and a drop-in only takes effect if nothing read later assigns the same key.
// systemd-sysctl merges every sysctl.d directory into one list sorted by
// *filename* and applies them in order, so the last assignment wins — and
// Ubuntu ships /etc/sysctl.d/99-sysctl.conf as a symlink to /etc/sysctl.conf,
// which is where operators have been told to put kernel settings for thirty
// years. On such a host systemd says so out loud and hostveil did not:
//
//	Overwriting earlier assignment of kernel/dmesg_restrict
//	  at '/etc/sysctl.d/99-sysctl.conf:65'.
//
// The drop-in was written, the fix reported success, and the value came back
// at the next boot. So the checker resolves the winner and names it, and the
// fix edits that file instead of writing one that cannot win.
//
// procps' `sysctl --system` orders differently — whole directories in a fixed
// sequence rather than one filename-sorted merge — but agrees on the case
// that matters, reading /etc/sysctl.conf last. The model below follows
// systemd and then puts /etc/sysctl.conf last unconditionally, which is the
// conservative direction: naming a real assignment of the observed value is
// never worse advice than naming none.

// defaultConfDirs is systemd-sysctl's search path, most authoritative first.
// A file in an earlier directory *masks* a same-named file in a later one
// rather than overriding it, which is how a distribution's drop-in is
// disabled by placing an empty file of the same name in /etc.
func defaultConfDirs() []string {
	return []string{
		"/etc/sysctl.d",
		"/run/sysctl.d",
		"/usr/local/lib/sysctl.d",
		"/usr/lib/sysctl.d",
		"/lib/sysctl.d",
	}
}

// defaultConfFile is the legacy single file, applied after every drop-in.
const defaultConfFile = "/etc/sysctl.conf"

// assignment is one `key = value` line in a sysctl configuration file, with
// the rank it was applied at. Higher rank wins: it was read later.
type assignment struct {
	Path  string
	Line  int
	Value int64
	rank  int
}

// String renders the assignment as the file:line an operator can open. It is
// the whole content of the finding's "set-by" evidence, and the fix parses it
// back — keep the two in step.
func (a assignment) String() string { return a.Path + ":" + strconv.Itoa(a.Line) }

// origins resolves, for every key any configuration file assigns, the
// assignment that decides it.
//
// Unreadable files are skipped rather than reported. A missing origin costs
// only the sharper remediation — the fix falls back to the drop-in it wrote
// before — whereas treating it as a coverage gap would degrade the whole
// domain over a file that has nothing to do with the parameters audited.
func origins(dirs []string, confFile string) map[string]assignment {
	out := map[string]assignment{}
	rank := 0
	for _, path := range confFiles(dirs, confFile) {
		rank++
		parseConf(path, rank, out)
	}
	return out
}

// confFiles lists the configuration files in the order they are applied:
// every *.conf across the search path sorted by base name with earlier
// directories masking later ones, then confFile last.
func confFiles(dirs []string, confFile string) []string {
	byName := map[string]string{}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".conf") {
				continue
			}
			if _, taken := byName[name]; !taken {
				byName[name] = filepath.Join(dir, name)
			}
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)

	paths := make([]string, 0, len(names)+1)
	for _, name := range names {
		paths = append(paths, byName[name])
	}
	if confFile != "" {
		if _, err := os.Stat(confFile); err == nil {
			paths = append(paths, confFile)
		}
	}
	return paths
}

// parseConf reads one file's assignments into out, later lines overwriting
// earlier ones exactly as systemd-sysctl does.
//
// Only plain integer values are recorded, because those are the only ones
// the rules audit: readKey rejects anything else as unreadable, so an
// assignment this cannot parse could never match an observed value anyway.
func parseConf(path string, rank int, out map[string]assignment) {
	f, err := os.Open(path) //nolint:gosec // paths come from the fixed sysctl.d search path
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		key, value, ok := parseAssignment(sc.Text())
		if !ok {
			continue
		}
		out[key] = assignment{Path: path, Line: n, Value: value, rank: rank}
	}
}

// parseAssignment splits one configuration line.
//
// The leading "-" is systemd's "apply this but do not complain if it fails"
// marker; it is part of the syntax, not of the key. Slashes are accepted as
// separators because sysctl.d permits kernel/dmesg_restrict for the same
// parameter as kernel.dmesg_restrict, and a rule keyed on dots would miss it.
func parseAssignment(line string) (key string, value int64, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return "", 0, false
	}
	k, v, found := strings.Cut(line, "=")
	if !found {
		return "", 0, false
	}
	k = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(k), "-"))
	if k == "" || strings.ContainsAny(k, "*?") { // glob patterns select many keys; not ours to rewrite
		return "", 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return "", 0, false
	}
	return strings.ReplaceAll(k, "/", "."), n, true
}

// originOf returns the assignment responsible for the values a rule flagged.
//
// It only accepts an assignment whose value is the one actually running. A
// file that sets a *different* value is not why the parameter is weak —
// something set it at runtime instead — and naming it would send the operator
// to edit a line that already says the right thing.
func originOf(keys []string, vals map[string]int64, byKey map[string]assignment) (assignment, bool) {
	var best assignment
	found := false
	for _, k := range keys {
		running, read := vals[k]
		if !read {
			continue // knob absent from this kernel; nothing was audited
		}
		a, ok := byKey[k]
		if !ok || a.Value != running {
			continue
		}
		if !found || a.rank > best.rank {
			best, found = a, true
		}
	}
	return best, found
}
