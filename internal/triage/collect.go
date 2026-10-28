package triage

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/platform"
)

// Options configures one collection.
type Options struct {
	Out     string        // bundle directory; must not exist or be empty
	Since   time.Duration // how far back logs and file changes are read
	Root    string        // filesystem root, "/" outside tests
	Runner  platform.CommandRunner
	Version string
	Now     func() time.Time
	// Exe is this binary's path, hashed into the manifest so the bundle
	// names exactly which collector produced it.
	Exe string
}

// maxFileCopy bounds one copied file. A log larger than this is recorded
// with an error rather than truncated: a partial log presented as a whole
// one would be worse than a missing one.
const maxFileCopy = 512 << 20

// maxWalk bounds how many entries one filesystem walk visits, so a media
// library under /home cannot turn a triage into an hour.
const maxWalk = 400000

// commandTimeout bounds one command. Package verification reads every
// installed file and is the slow one.
const commandTimeout = 10 * time.Minute

type collector struct {
	opts      Options
	out       string
	since     time.Time
	seq       int
	artifacts []Artifact
}

// Collect gathers the evidence bundle. It returns the manifest it wrote.
func Collect(ctx context.Context, opts Options) (*Manifest, error) {
	if opts.Root == "" {
		opts.Root = "/"
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Since <= 0 {
		opts.Since = 30 * 24 * time.Hour
	}
	out, err := filepath.Abs(opts.Out)
	if err != nil {
		return nil, err
	}
	if entries, err := os.ReadDir(out); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s already exists and is not empty; a bundle is never written over another", out)
	}
	if err := os.MkdirAll(filepath.Join(out, "artifacts"), 0o700); err != nil {
		return nil, err
	}

	start := opts.Now().UTC()
	c := &collector{opts: opts, out: out, since: start.Add(-opts.Since)}

	// Phase 1: volatile. What is running and connected now, and who is on.
	c.command(ctx, 1, "uname", "uname", "-a")
	c.command(ctx, 1, "ps", "ps", "-eo", "pid=,ppid=,user:32=,etimes=,args=")
	c.procExe(1)
	c.command(ctx, 1, "ss", "ss", "-tunapH")
	c.command(ctx, 1, "who", "who", "-a")
	c.command(ctx, 1, "last", "last", "-F", "-w")
	c.command(ctx, 1, "lsmod", "lsmod")

	// Phase 2: persistence. What makes something survive a reboot, and
	// whether the system's own files are still the ones it installed.
	c.files(2, "passwd", "/etc/passwd")
	c.files(2, "group", "/etc/group")
	c.shadowSummary(2)
	c.files(2, "sudoers", "/etc/sudoers", "/etc/sudoers.d/*")
	c.files(2, "preload", "/etc/ld.so.preload")
	c.files(2, "cron", "/etc/crontab", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*",
		"/etc/cron.weekly/*", "/etc/cron.monthly/*", "/var/spool/cron/*", "/var/spool/cron/crontabs/*")
	c.files(2, "unit", "/etc/systemd/system/*.service", "/etc/systemd/system/*.timer",
		"/etc/systemd/system/*/*.service", "/etc/systemd/system/*/*.timer", "/etc/rc.local")
	c.files(2, "authorized_keys", c.homeGlobs(".ssh/authorized_keys", ".ssh/authorized_keys2")...)
	c.homeLinks(2)
	c.command(ctx, 2, "auditctl", "auditctl", "-l")
	recent := c.walk(2, "recent-files", recentRoots, func(st fileStat, _ fs.FileMode) bool {
		return !st.mtime.Before(c.since) || !st.ctime.Before(c.since)
	})
	suid := c.walk(2, "suid", suidRoots, func(_ fileStat, m fs.FileMode) bool {
		return m&fs.ModeSetuid != 0 && m.IsRegular()
	})
	// Owners are asked for the setuid files and for the recently changed
	// start-up files: a package installing or upgrading a file leaves its
	// archive's old mtime under a new ctime, which is otherwise exactly
	// what backdating looks like.
	var owned []string
	for _, p := range recent {
		if persistencePath(p) {
			owned = append(owned, p)
		}
	}
	c.packageOwners(ctx, 2, append(suid, owned...))
	c.packageVerify(ctx, 2)

	// Phase 3: logs. Copied as they are, rotated and compressed ones
	// included, so the bundle holds the bytes and not a reading of them.
	c.files(3, "auth-log", "/var/log/auth.log*", "/var/log/secure*")
	c.files(3, "web-log", "/var/log/apache2/*access*.log*", "/var/log/apache2/access.log*",
		"/var/log/nginx/*access*.log*", "/var/log/httpd/*access*")
	c.files(3, "audit-log", "/var/log/audit/audit.log*")
	c.files(3, "fail2ban-log", "/var/log/fail2ban.log*")
	c.command(ctx, 3, "journal-sshd", "journalctl", "-q", "--no-pager", "-o", "short-iso",
		"--since", c.since.Format("2006-01-02 15:04:05"), "-t", "sshd", "-t", "sshd-session")
	c.command(ctx, 3, "journal-boots", "journalctl", "-q", "--no-pager", "--list-boots")
	c.command(ctx, 3, "timedatectl", "timedatectl", "show")
	c.stat(3, "log-sizes", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog", "/var/log/auth.log", "/var/log/syslog")

	m := &Manifest{
		Tool:       "hostveil triage",
		Version:    opts.Version,
		Host:       hostname(),
		Operator:   operator(),
		StartedUTC: start,
		Since:      c.since,
		Artifacts:  c.artifacts,
		Note: "Every artifact was written once and hashed as written. Re-hash with " +
			"`hostveil triage verify <dir>`; record the manifest hash printed at the end of collection somewhere this host cannot reach.",
	}
	if opts.Exe != "" {
		m.BinarySHA256, _ = hashFile(opts.Exe)
	}
	if b, err := os.ReadFile(filepath.Join(out, c.pathOf("uname"))); err == nil { //nolint:gosec // an artifact this run just wrote
		m.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(filepath.Join(out, c.pathOf("timedatectl"))); err == nil { //nolint:gosec // an artifact this run just wrote
		m.ClockSynced = platform.ShowProperty(string(b), "NTPSynchronized")
	}
	return m, nil
}

// recentRoots are where a change in the window is worth a timeline row:
// configuration, installed programs, web roots, home directories, and the
// world-writable places a dropped tool usually lands.
var recentRoots = []string{"/etc", "/usr/bin", "/usr/sbin", "/usr/local", "/opt", "/var/www", "/srv",
	"/root", "/home", "/tmp", "/var/tmp", "/dev/shm", "/var/spool/cron"}

// suidRoots are walked for setuid files. Container and snap image stores
// are left out: they hold other systems' binaries, each legitimately setuid
// inside its own image.
var suidRoots = []string{"/usr", "/bin", "/sbin", "/opt", "/srv", "/home", "/root", "/tmp", "/var/tmp", "/dev/shm", "/var/www", "/var/spool"}

var walkSkip = []string{"/proc", "/sys", "/var/lib/docker", "/var/lib/containerd", "/var/lib/containers", "/var/lib/snapd", "/snap"}

func (c *collector) next(name, ext string) string {
	c.seq++
	return fmt.Sprintf("artifacts/%02d_%s.%s", c.seq, name, ext)
}

func (c *collector) pathOf(name string) string {
	for _, a := range c.artifacts {
		if a.Name == name {
			return a.Path
		}
	}
	return ""
}

func (c *collector) host(p string) string { return filepath.Join(c.opts.Root, p) }

// record writes data as a new artifact and appends it to the manifest.
func (c *collector) record(a Artifact, data []byte) {
	full := filepath.Join(c.out, a.Path)
	_ = os.MkdirAll(filepath.Dir(full), 0o700)
	if err := os.WriteFile(full, data, 0o400); err != nil && a.Error == "" {
		a.Error = "writing the artifact: " + err.Error()
	}
	sum := sha256.Sum256(data)
	a.SHA256 = hex.EncodeToString(sum[:])
	a.Size = int64(len(data))
	a.CollectedAt = c.opts.Now().UTC()
	c.artifacts = append(c.artifacts, a)
}

func (c *collector) command(ctx context.Context, phase int, name string, argv ...string) {
	a := Artifact{Name: name, Path: c.next(name, "txt"), Phase: phase, Kind: "command", Argv: argv}
	if !platform.Has(c.opts.Runner, argv[0]) {
		a.Error = argv[0] + " is not installed"
		c.record(a, nil)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	out, err := c.opts.Runner.Run(cctx, argv[0], argv[1:]...)
	if err != nil {
		// Kept with the output: dpkg --verify and last exit non-zero on
		// ordinary answers, and grep-shaped tools exit 1 for "none".
		a.Error = err.Error()
	}
	c.record(a, out)
}

// procExe lists each process's executable as the kernel resolves it. A
// binary deleted after it started reads "(deleted)", which ps cannot show.
func (c *collector) procExe(phase int) {
	a := Artifact{Name: "proc-exe", Path: c.next("proc-exe", "tsv"), Phase: phase, Kind: "procfs", Source: "/proc/*/exe"}
	entries, err := os.ReadDir(c.host("/proc"))
	if err != nil {
		a.Error = err.Error()
	}
	var b strings.Builder
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		target, err := os.Readlink(c.host("/proc/" + e.Name() + "/exe"))
		if err != nil {
			continue // kernel threads have no exe
		}
		fmt.Fprintf(&b, "%s\t%s\n", e.Name(), target)
	}
	c.record(a, []byte(b.String()))
}

func (c *collector) glob(patterns ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range patterns {
		m, _ := filepath.Glob(c.host(p))
		for _, f := range m {
			rel := "/" + strings.TrimPrefix(strings.TrimPrefix(f, filepath.Clean(c.opts.Root)), "/")
			if seen[rel] {
				continue
			}
			if st, err := os.Lstat(f); err != nil || !st.Mode().IsRegular() {
				continue
			}
			seen[rel] = true
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

// files copies every regular file the patterns match, byte for byte.
func (c *collector) files(phase int, name string, patterns ...string) {
	for _, p := range c.glob(patterns...) {
		a := Artifact{Name: name, Path: "artifacts/files" + p, Phase: phase, Kind: "file", Source: p}
		f, err := os.Open(c.host(p))
		if err != nil {
			a.Error = err.Error()
			c.record(a, nil)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxFileCopy+1))
		_ = f.Close()
		switch {
		case err != nil:
			a.Error = err.Error()
			data = nil
		case len(data) > maxFileCopy:
			a.Error = fmt.Sprintf("larger than %d bytes; not copied rather than copied in part", maxFileCopy)
			data = nil
		}
		c.record(a, data)
	}
}

// homes lists home directories from /etc/passwd, root's included.
func (c *collector) homes() []string {
	b, err := os.ReadFile(c.host("/etc/passwd"))
	if err != nil {
		return []string{"/root"}
	}
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || f[5] == "" || f[5] == "/" || f[5] == "/nonexistent" || seen[f[5]] {
			continue
		}
		seen[f[5]] = true
		out = append(out, f[5])
	}
	return out
}

func (c *collector) homeGlobs(rels ...string) []string {
	var out []string
	for _, h := range c.homes() {
		for _, r := range rels {
			out = append(out, filepath.Join(h, r))
		}
	}
	return out
}

// homeLinks records where each account's shell history points. Linking it
// to /dev/null is how a history is kept from being written at all.
func (c *collector) homeLinks(phase int) {
	a := Artifact{Name: "history-links", Path: c.next("history-links", "tsv"), Phase: phase, Kind: "walk"}
	var b strings.Builder
	for _, h := range c.homes() {
		for _, f := range []string{".bash_history", ".zsh_history", ".ash_history", ".mysql_history"} {
			p := filepath.Join(h, f)
			st, err := os.Lstat(c.host(p))
			if err != nil {
				continue
			}
			target := ""
			if st.Mode()&fs.ModeSymlink != 0 {
				target, _ = os.Readlink(c.host(p))
			}
			fmt.Fprintf(&b, "%s\t%d\t%s\n", p, st.Size(), target)
		}
	}
	c.record(a, []byte(b.String()))
}

// shadowSummary records which accounts have a password, none, or a locked
// one — never the hashes, which have no place in a bundle that may be
// handed to someone else.
func (c *collector) shadowSummary(phase int) {
	a := Artifact{Name: "shadow-summary", Path: c.next("shadow-summary", "tsv"), Phase: phase, Kind: "derived", Source: "/etc/shadow"}
	b, err := os.ReadFile(c.host("/etc/shadow"))
	if err != nil {
		a.Error = err.Error()
		c.record(a, nil)
		return
	}
	var out strings.Builder
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		state := "password"
		switch {
		case f[1] == "":
			state = "empty"
		case strings.HasPrefix(f[1], "!") || strings.HasPrefix(f[1], "*"):
			state = "locked"
		}
		fmt.Fprintf(&out, "%s\t%s\t%s\n", f[0], state, f[2])
	}
	c.record(a, []byte(out.String()))
}

// fileStat is the part of stat(2) the walks record. Filled per platform in
// stat_*.go: the field names differ between Linux and the BSDs.
type fileStat struct {
	dev          uint64
	uid          uint32
	size         int64
	mtime, ctime time.Time
}

const walkHeader = "path\tmode\tuid\tsize\tmtime\tctime\n"

func walkRow(p string, st fileStat, m fs.FileMode) string {
	return fmt.Sprintf("%s\t%s\t%d\t%d\t%s\t%s\n", p, m, st.uid, st.size,
		st.mtime.Format(time.RFC3339), st.ctime.Format(time.RFC3339))
}

// walk lists files under roots that keep matches, without crossing into
// another filesystem from each root. It returns the matching host paths.
func (c *collector) walk(phase int, name string, roots []string, keep func(fileStat, fs.FileMode) bool) []string {
	a := Artifact{Name: name, Path: c.next(name, "tsv"), Phase: phase, Kind: "walk", Source: strings.Join(roots, " ")}
	var (
		b       strings.Builder
		matched []string
		visited int
	)
	b.WriteString(walkHeader)
	errTrunc := errors.New("truncated")
	for _, root := range roots {
		rst, err := os.Lstat(c.host(root))
		if err != nil || !rst.IsDir() {
			continue
		}
		rs, ok := statOf(rst)
		if !ok {
			continue
		}
		dev := rs.dev
		err = filepath.WalkDir(c.host(root), func(full string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			p := "/" + strings.TrimPrefix(strings.TrimPrefix(full, filepath.Clean(c.opts.Root)), "/")
			if d.IsDir() {
				if full == c.out || strings.HasPrefix(full+"/", c.out+"/") {
					return filepath.SkipDir
				}
				for _, s := range walkSkip {
					if p == s {
						return filepath.SkipDir
					}
				}
			}
			visited++
			if visited > maxWalk {
				return errTrunc
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			st, ok := statOf(info)
			if !ok {
				return nil
			}
			if d.IsDir() && st.dev != dev {
				return filepath.SkipDir
			}
			if !d.IsDir() && keep(st, info.Mode()) {
				b.WriteString(walkRow(p, st, info.Mode()))
				matched = append(matched, p)
			}
			return nil
		})
		if errors.Is(err, errTrunc) {
			a.Error = fmt.Sprintf("stopped after %d entries; the listing is incomplete", maxWalk)
			break
		}
	}
	c.record(a, []byte(b.String()))
	return matched
}

func (c *collector) stat(phase int, name string, paths ...string) {
	a := Artifact{Name: name, Path: c.next(name, "tsv"), Phase: phase, Kind: "walk", Source: strings.Join(paths, " ")}
	var b strings.Builder
	b.WriteString(walkHeader)
	for _, p := range paths {
		info, err := os.Lstat(c.host(p))
		if err != nil {
			continue
		}
		if st, ok := statOf(info); ok {
			b.WriteString(walkRow(p, st, info.Mode()))
		}
	}
	c.record(a, []byte(b.String()))
}

// packageOwners asks the package manager who owns each setuid file. One
// that no package installed is the classic leftover of a privilege
// escalation.
func (c *collector) packageOwners(ctx context.Context, phase int, paths []string) {
	tool := []string{"dpkg", "-S"}
	if !platform.Has(c.opts.Runner, "dpkg") && platform.Has(c.opts.Runner, "rpm") {
		tool = []string{"rpm", "-qf"}
	}
	a := Artifact{Name: "pkg-owner", Path: c.next("pkg-owner", "txt"), Phase: phase, Kind: "command", Argv: append(tool, "<setuid and recently changed start-up files>")}
	if !platform.Has(c.opts.Runner, tool[0]) {
		a.Error = "no package manager to ask"
		c.record(a, nil)
		return
	}
	ask := func(p string) string {
		cctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		out, err := c.opts.Runner.Run(cctx, tool[0], append(tool[1:], p)...)
		owner := strings.TrimSpace(string(out))
		if err != nil || owner == "" || strings.Contains(owner, "not owned") {
			return "-"
		}
		if tool[0] == "dpkg" {
			owner, _, _ = strings.Cut(owner, ":")
		}
		return owner
	}
	var b strings.Builder
	seen := map[string]bool{}
	for _, p := range paths {
		if seen[p] {
			continue
		}
		seen[p] = true
		owner := ask(p)
		// On a merged-/usr system dpkg still records many files under the
		// path the package shipped them at, /bin rather than /usr/bin.
		if alias := unmergedPath(p); owner == "-" && alias != "" {
			owner = ask(alias)
		}
		fmt.Fprintf(&b, "%s\t%s\n", p, owner)
	}
	c.record(a, []byte(b.String()))
}

func unmergedPath(p string) string {
	for _, d := range []string{"/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/"} {
		if strings.HasPrefix(p, d) {
			return strings.TrimPrefix(p, "/usr")
		}
	}
	return ""
}

func (c *collector) packageVerify(ctx context.Context, phase int) {
	switch {
	case platform.Has(c.opts.Runner, "dpkg"):
		c.command(ctx, phase, "pkg-verify", "dpkg", "--verify")
	case platform.Has(c.opts.Runner, "rpm"):
		c.command(ctx, phase, "pkg-verify", "rpm", "-Va")
	}
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p) //nolint:gosec // this binary, or an artifact of the bundle being sealed
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, bufio.NewReader(f)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

// operator is the person behind sudo, when there is one.
func operator() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u + " (via sudo)"
	}
	return os.Getenv("USER")
}
