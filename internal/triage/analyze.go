package triage

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// bundle is a collected directory opened for analysis.
type bundle struct {
	dir string
	m   Manifest
}

func openBundle(dir string) (*bundle, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json")) //nolint:gosec // the bundle the operator named
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	return &bundle{dir: dir, m: m}, nil
}

// all returns every artifact with this logical name, oldest log first when
// they are rotations of one log (auth.log.3.gz before auth.log.1 before
// auth.log), so events come out in time order.
func (b *bundle) all(name string) []Artifact {
	var out []Artifact
	for _, a := range b.m.Artifacts {
		// An artifact that failed but still holds output is read: dpkg --verify
		// exits non-zero exactly when it has something to say, and a partial
		// readiness check still found what it found.
		if a.Name == name && (a.Error == "" || a.Size > 0) {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return rotation(out[i].Source) > rotation(out[j].Source) })
	return out
}

var rotationSuffix = regexp.MustCompile(`\.(\d+)(?:\.gz)?$`)

func rotation(p string) int {
	if m := rotationSuffix.FindStringSubmatch(p); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

func (b *bundle) one(name string) (Artifact, string, bool) {
	as := b.all(name)
	if len(as) == 0 {
		return Artifact{}, "", false
	}
	return as[0], b.text(as[0]), true
}

// text reads an artifact, decompressing a rotated .gz log.
func (b *bundle) text(a Artifact) string {
	data, err := os.ReadFile(filepath.Join(b.dir, a.Path))
	if err != nil {
		return ""
	}
	if strings.HasSuffix(a.Path, ".gz") {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return ""
		}
		out, _ := io.ReadAll(io.LimitReader(zr, 4*maxFileCopy))
		return string(out)
	}
	return string(data)
}

type analysis struct {
	owners   map[string]string // path -> package, "-" for none, from pkg-owner
	modified map[string]bool   // paths the package manager says changed
	b        *bundle
	now      time.Time
	since    time.Time
	res      Result
	svcUID   map[string]string // uid -> name of the web-server accounts
}

// Analyze derives indicators, gaps and a timeline from a bundle on disk.
func Analyze(dir string) (*Result, *Manifest, error) {
	b, err := openBundle(dir)
	if err != nil {
		return nil, nil, err
	}
	an := &analysis{b: b, now: b.m.StartedUTC, since: b.m.Since, svcUID: map[string]string{}}
	an.loadPackages()
	an.accounts()
	an.ssh()
	an.web()
	an.processes()
	an.audit()
	an.persistence()
	an.integrity()
	an.antiForensics()
	an.gaps()

	sort.SliceStable(an.res.Indicators, func(i, j int) bool {
		return an.res.Indicators[i].Verdict.rank() < an.res.Indicators[j].Verdict.rank()
	})
	sort.SliceStable(an.res.Timeline, func(i, j int) bool { return an.res.Timeline[i].Time.Before(an.res.Timeline[j].Time) })
	return &an.res, &b.m, nil
}

// IDPrefix namespaces every indicator. An indicator is not a finding — it
// is a conclusion about the past, not a setting to fix — so no indicator ID
// may read as one: none starts with, or contains, a detection domain's name
// followed by a dot (login.*, not ssh.*), which internal/docs enforces.
const IDPrefix = "triage."

func (an *analysis) add(in Indicator) {
	in.ID = IDPrefix + in.ID
	if len(in.Evidence) > 10 {
		in.Evidence = in.Evidence[:10]
	}
	an.res.Indicators = append(an.res.Indicators, in)
}

func (an *analysis) event(t time.Time, source, what, artifact string) {
	if t.IsZero() || t.Before(an.since) {
		return
	}
	an.res.Timeline = append(an.res.Timeline, Event{Time: t, Source: source, What: what, Artifact: artifact})
}

func lines(s string) []string { return strings.Split(strings.TrimRight(s, "\n"), "\n") }

// --- accounts ------------------------------------------------------------

var webServerUsers = map[string]bool{"www-data": true, "apache": true, "nginx": true, "http": true}

func (an *analysis) accounts() {
	a, passwd, ok := an.b.one("passwd")
	if !ok {
		return
	}
	for i, l := range lines(passwd) {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		if webServerUsers[f[0]] {
			an.svcUID[f[2]] = f[0]
		}
		if f[2] == "0" && f[0] != "root" {
			an.add(Indicator{ID: "account.uid0", Verdict: Compromise,
				Title:    "An account other than root has root's user ID",
				Detail:   "Account " + f[0] + " has UID 0, which makes it root under another name. No distribution creates one; it is a classic way to keep root access that survives a password change.",
				Evidence: []Evidence{{Artifact: a.Path, Line: i + 1, Text: l}}})
		}
	}
	if s, text, ok := an.b.one("shadow-summary"); ok {
		shells := loginShells(passwd)
		for i, l := range lines(text) {
			f := strings.Split(l, "\t")
			if len(f) >= 2 && f[1] == "empty" && shells[f[0]] {
				an.add(Indicator{ID: "account.empty-password", Verdict: Compromise,
					Title:    "A login account has an empty password",
					Detail:   "Account " + f[0] + " can log in with no password at all. Distributions never ship one; it is either a serious mistake or a door someone left.",
					Evidence: []Evidence{{Artifact: s.Path, Line: i + 1, Text: f[0] + "\tempty"}}})
			}
		}
	}
}

func loginShells(passwd string) map[string]bool {
	out := map[string]bool{}
	for _, l := range lines(passwd) {
		f := strings.Split(l, ":")
		if len(f) >= 7 && !strings.HasSuffix(f[6], "nologin") && !strings.HasSuffix(f[6], "false") {
			out[f[0]] = true
		}
	}
	return out
}

// --- ssh -----------------------------------------------------------------

var (
	sshFailed   = regexp.MustCompile(`(?:Failed (?:password|publickey) for (?:invalid user )?(\S+)|Invalid user (\S*)) from (\S+)`)
	sshAccepted = regexp.MustCompile(`Accepted (\S+) for (\S+) from (\S+) port \d+(?: ssh2)?(?:: \S+ (SHA256:\S+))?`)
)

// logTime reads the timestamp at the start of a syslog or journal line:
// RFC 3339 (rsyslog's default on current Debian and Ubuntu, and
// journalctl -o short-iso) or the classic "Oct  5 13:01:02", whose year is
// taken as the one that puts it closest before now.
func logTime(line string, now time.Time) time.Time {
	if sp := strings.IndexByte(line, ' '); sp > 0 {
		if t, err := time.Parse(time.RFC3339Nano, line[:sp]); err == nil {
			return t.UTC()
		}
		if t, err := time.Parse("2006-01-02T15:04:05-0700", line[:sp]); err == nil {
			return t.UTC()
		}
	}
	if len(line) >= 15 {
		if t, err := time.ParseInLocation("Jan _2 15:04:05", line[:15], time.Local); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			return t.UTC()
		}
	}
	return time.Time{}
}

type located struct {
	art  Artifact
	line int
	text string
	t    time.Time
}

// sshLines prefers the auth log files and falls back to the journal, which
// on most hosts carries the same events; reading both would count every
// attempt twice.
func (an *analysis) sshLines() []located {
	src := an.b.all("auth-log")
	if len(src) == 0 {
		src = an.b.all("journal-sshd")
	}
	var out []located
	for _, a := range src {
		for i, l := range lines(an.b.text(a)) {
			if !strings.Contains(l, "sshd") {
				continue
			}
			t := logTime(l, an.now)
			if !t.IsZero() && t.Before(an.since) {
				continue
			}
			out = append(out, located{a, i + 1, l, t})
		}
	}
	return out
}

func (an *analysis) authorizedFingerprints() map[string]bool {
	out := map[string]bool{}
	for _, a := range an.b.all("authorized_keys") {
		for _, l := range lines(an.b.text(a)) {
			for _, field := range strings.Fields(l) {
				blob, err := base64.StdEncoding.DecodeString(field)
				if err != nil || len(blob) < 20 {
					continue
				}
				sum := sha256.Sum256(blob)
				out["SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:])] = true
			}
		}
	}
	return out
}

func (an *analysis) ssh() {
	type source struct {
		fails       int
		first, last time.Time
		ev          []Evidence
	}
	failed := map[string]*source{}
	total := 0
	var firstFail, lastFail time.Time
	keys := an.authorizedFingerprints()

	for _, l := range an.sshLines() {
		if m := sshFailed.FindStringSubmatch(l.text); m != nil {
			ip := m[3]
			s := failed[ip]
			if s == nil {
				s = &source{first: l.t}
				failed[ip] = s
				an.event(l.t, "ssh", "first failed login from "+ip, l.art.Path)
			}
			s.fails++
			s.last = l.t
			total++
			if firstFail.IsZero() {
				firstFail = l.t
			}
			lastFail = l.t
			if len(s.ev) < 3 {
				s.ev = append(s.ev, Evidence{Artifact: l.art.Path, Line: l.line, Text: l.text})
			}
			continue
		}
		m := sshAccepted.FindStringSubmatch(l.text)
		if m == nil {
			continue
		}
		method, user, ip, fp := m[1], m[2], m[3], m[4]
		an.event(l.t, "ssh", fmt.Sprintf("login accepted: %s by %s from %s", user, method, ip), l.art.Path)
		ev := Evidence{Artifact: l.art.Path, Line: l.line, Text: l.text}
		if s := failed[ip]; s != nil && s.fails >= 5 {
			an.add(Indicator{ID: "login.after-guessing", Verdict: Compromise,
				Title:  "A login succeeded from an address that had been guessing passwords",
				Detail: fmt.Sprintf("%s logged in as %s from %s after %d failed attempts from the same address. That is what a successful brute force looks like.", method, user, ip, s.fails),
				First:  s.first, Last: l.t, Count: s.fails,
				Evidence: append(append([]Evidence{}, s.ev...), ev)})
			continue
		}
		if method == "password" || strings.HasPrefix(method, "keyboard-interactive") {
			an.add(Indicator{ID: "login.password", Verdict: Suspicious,
				Title:  "Someone logged in over SSH with a password",
				Detail: fmt.Sprintf("%s logged in from %s with a password. If you log in with keys, this was not you.", user, ip),
				First:  l.t, Evidence: []Evidence{ev}})
		}
		if fp != "" && len(keys) > 0 && !keys[fp] {
			an.add(Indicator{ID: "login.key-not-authorized-now", Verdict: Suspicious,
				Title:  "A login used a key that is no longer in any authorized_keys",
				Detail: fmt.Sprintf("%s logged in from %s with key %s, which no authorized_keys file on this host now contains. Either the key was removed since — which is ordinary — or it was added, used, and removed.", user, ip, fp),
				First:  l.t, Evidence: []Evidence{ev}})
		}
	}
	if total > 0 {
		var top []string
		for ip := range failed {
			top = append(top, ip)
		}
		sort.Slice(top, func(i, j int) bool { return failed[top[i]].fails > failed[top[j]].fails })
		var ev []Evidence
		for _, ip := range top[:min(3, len(top))] {
			ev = append(ev, failed[ip].ev[0])
		}
		an.add(Indicator{ID: "login.guessing", Verdict: Attempt,
			Title: "SSH password guessing",
			Detail: fmt.Sprintf("%d failed SSH logins from %d addresses, none followed by a success from the same address. "+
				"Every server reachable from the internet receives these; on its own it shows only that someone tried.", total, len(failed)),
			Count: total, First: firstFail, Last: lastFail, Evidence: ev})
	}
}

// --- web -----------------------------------------------------------------

var (
	accessLine = regexp.MustCompile(`^(?:\S+:\d+ )?(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) `)
	probePath  = regexp.MustCompile(`(?i)(/\.env|/\.git/|/\.htpasswd|/\.aws/|phpmyadmin|/wp-login\.php|/wp-admin|/xmlrpc\.php|/cgi-bin/|\.\./|%2e%2e|/etc/passwd|/actuator|/server-status|/vendor/phpunit)`)
	uploadExec = regexp.MustCompile(`(?i)/(?:uploads?|files|tmp|temp|cache|images?|media|storage|attachments?)/[^?]*\.(?:php\d?|phtml|phar|jsp|aspx?|cgi)(?:[?/]|$)`)
	exportPath = regexp.MustCompile(`(?i)/(?:export|download|backup|dump)(?:/|\b)`)
)

type hit struct {
	ip, method, path string
	status           int
	t                time.Time
	at               located
}

func (an *analysis) webHits() []hit {
	var out []hit
	for _, a := range an.b.all("web-log") {
		for i, l := range lines(an.b.text(a)) {
			m := accessLine.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
			if err != nil || t.Before(an.since) {
				continue
			}
			st, _ := strconv.Atoi(m[5])
			p := m[4]
			if u, err := url.PathUnescape(p); err == nil {
				p = u
			}
			out = append(out, hit{ip: m[1], method: m[3], path: p, status: st, t: t.UTC(), at: located{a, i + 1, l, t.UTC()}})
		}
	}
	return out
}

func (an *analysis) web() {
	hits := an.webHits()
	if len(hits) == 0 {
		return
	}
	errs := map[string]int{}
	exports := map[string][]hit{}
	var probeHits, uploads []hit
	for _, h := range hits {
		if h.status >= 400 && h.status < 500 {
			errs[h.ip]++
		}
		ok := h.status >= 200 && h.status < 300
		if ok && probePath.MatchString(h.path) {
			probeHits = append(probeHits, h)
		}
		if ok && uploadExec.MatchString(h.path) {
			uploads = append(uploads, h)
		}
		if ok && h.method == "GET" && exportPath.MatchString(h.path) {
			exports[h.ip] = append(exports[h.ip], h)
		}
	}

	scanners, probes := 0, 0
	var ev []Evidence
	for ip, n := range errs {
		if n >= 20 {
			scanners++
			probes += n
			if len(ev) < 3 {
				ev = append(ev, Evidence{Text: fmt.Sprintf("%s: %d client errors", ip, n)})
			}
		}
	}
	if scanners > 0 {
		an.add(Indicator{ID: "web.scanning", Verdict: Attempt,
			Title: "Automated scanning of the web server",
			Detail: fmt.Sprintf("%d addresses produced %d client errors (4xx) between them — requests for files that are not there, the shape of a vulnerability scanner. "+
				"On its own it shows only that someone looked.", scanners, probes),
			Count: probes, Evidence: ev})
	}
	if len(probeHits) > 0 {
		var ev []Evidence
		for _, h := range probeHits {
			ev = append(ev, Evidence{Artifact: h.at.art.Path, Line: h.at.line, Text: h.at.text})
			an.event(h.t, "web", fmt.Sprintf("probe answered %d: %s %s from %s", h.status, h.method, h.path, h.ip), h.at.art.Path)
		}
		an.add(Indicator{ID: "web.probe-answered", Verdict: Suspicious,
			Title: "A scanner's request got a successful answer",
			Detail: fmt.Sprintf("%d requests for paths scanners look for (secrets files, admin panels, path traversal) were answered 2xx. "+
				"A page that legitimately exists at such a path is harmless; a .env or .git that is served is a leak to check now.", len(probeHits)),
			Count: len(probeHits), First: probeHits[0].t, Last: probeHits[len(probeHits)-1].t, Evidence: ev})
	}
	if len(uploads) > 0 {
		var ev []Evidence
		for _, h := range uploads {
			ev = append(ev, Evidence{Artifact: h.at.art.Path, Line: h.at.line, Text: h.at.text})
			an.event(h.t, "web", fmt.Sprintf("script in an upload directory answered %d: %s %s from %s", h.status, h.method, h.path, h.ip), h.at.art.Path)
		}
		an.add(Indicator{ID: "web.script-in-upload-dir", Verdict: Compromise,
			Title: "A script in an upload directory was executed",
			Detail: fmt.Sprintf("%d requests ran a server-side script (.php and similar) under a directory meant for uploaded files, and got a successful answer. "+
				"Applications do not keep code there; an uploaded webshell does.", len(uploads)),
			Count: len(uploads), First: uploads[0].t, Last: uploads[len(uploads)-1].t, Evidence: ev})
	}
	for ip, hs := range exports {
		if len(hs) < 20 {
			continue
		}
		an.event(hs[0].t, "web", fmt.Sprintf("bulk export began: %d downloads from %s", len(hs), ip), hs[0].at.art.Path)
		an.add(Indicator{ID: "web.bulk-export", Verdict: Suspicious,
			Title: "One address downloaded many exports",
			Detail: fmt.Sprintf("%s made %d successful export or download requests between %s and %s. A person exporting their own work does a few; a script copying the site does this.",
				ip, len(hs), hs[0].t.Format(time.RFC3339), hs[len(hs)-1].t.Format(time.RFC3339)),
			Count: len(hs), First: hs[0].t, Last: hs[len(hs)-1].t,
			Evidence: []Evidence{{Artifact: hs[0].at.art.Path, Line: hs[0].at.line, Text: hs[0].at.text}}})
	}
}

// --- processes -----------------------------------------------------------

var shellish = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ash": true, "busybox": true,
	"nc": true, "ncat": true, "netcat": true, "socat": true, "perl": true, "python": true, "python3": true,
	"ruby": true, "curl": true, "wget": true}

func scratchPath(p string) bool {
	for _, d := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

func (an *analysis) processes() {
	if a, text, ok := an.b.one("proc-exe"); ok {
		for i, l := range lines(text) {
			pid, exe, ok := strings.Cut(l, "\t")
			if !ok {
				continue
			}
			if scratchPath(exe) || strings.HasSuffix(exe, " (deleted)") {
				an.add(Indicator{ID: "process.exe-unusual", Verdict: Compromise,
					Title:    "A program is running from a temporary directory or was deleted after it started",
					Detail:   "Process " + pid + " runs " + exe + ". Installed software runs from where the package put it; a program run from /tmp or /dev/shm, or one deleted while running, is how dropped tools hide.",
					Evidence: []Evidence{{Artifact: a.Path, Line: i + 1, Text: l}}})
			}
		}
	}
	if a, text, ok := an.b.one("ps"); ok {
		for i, l := range lines(text) {
			f := strings.Fields(l)
			if len(f) < 5 || !webServerUsers[f[2]] {
				continue
			}
			prog := path.Base(f[4])
			if shellish[prog] {
				an.add(Indicator{ID: "process.webuser-shell", Verdict: Compromise,
					Title:    "The web server's account is running a shell or network tool",
					Detail:   "Account " + f[2] + " is running " + strings.Join(f[4:], " ") + ". A web server does not start shells; a webshell does.",
					Evidence: []Evidence{{Artifact: a.Path, Line: i + 1, Text: l}}})
			}
		}
	}
}

// --- audit ---------------------------------------------------------------

var (
	auditSyscall = regexp.MustCompile(`type=SYSCALL msg=audit\((\d+)\.\d+:\d+\).* syscall=(?:59|execve|11) .*?\bsuccess=(\S+).*?\beuid=(\d+).*?\bcomm="([^"]*)" exe="([^"]*)".*?\bkey=(\S+)`)
)

func (an *analysis) audit() {
	var ev []Evidence
	var first, last time.Time
	n := 0
	for _, a := range an.b.all("audit-log") {
		for i, l := range lines(an.b.text(a)) {
			m := auditSyscall.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			who, svc := an.svcUID[m[3]]
			if !svc {
				continue
			}
			sec, _ := strconv.ParseInt(m[1], 10, 64)
			t := time.Unix(sec, 0).UTC()
			if t.Before(an.since) {
				continue
			}
			n++
			if first.IsZero() {
				first = t
			}
			last = t
			an.event(t, "audit", fmt.Sprintf("%s executed %s (%s)", who, m[5], m[4]), a.Path)
			if len(ev) < 10 {
				ev = append(ev, Evidence{Artifact: a.Path, Line: i + 1, Text: l})
			}
		}
	}
	if n > 0 {
		an.add(Indicator{ID: "audit.webuser-exec", Verdict: Compromise,
			Title: "The web server's account started programs",
			Detail: fmt.Sprintf("The audit log recorded %d programs started by a web server account. Unless your web application is known to run programs, "+
				"these are commands run through it — the first ones an attacker types after a remote-code-execution bug.", n),
			Count: n, First: first, Last: last, Evidence: ev})
	}
}

// --- persistence -----------------------------------------------------------

var dangerousCommand = regexp.MustCompile(`(?i)((?:curl|wget)\b[^|;#]*\|\s*(?:ba|da|z)?sh\b|base64\s+(?:-d|--decode)|/dev/(?:tcp|udp)/|\bnc(?:at)?\b[^|;#]*\s-e\s|(?:^|[\s=;"'])(?:/tmp|/var/tmp|/dev/shm)/\S+)`)

func (an *analysis) persistence() {
	for _, name := range []string{"cron", "unit"} {
		for _, a := range an.b.all(name) {
			for i, l := range lines(an.b.text(a)) {
				t := strings.TrimSpace(l)
				if t == "" || strings.HasPrefix(t, "#") {
					continue
				}
				if name == "unit" && !strings.HasPrefix(t, "Exec") {
					continue
				}
				if m := dangerousCommand.FindString(t); m != "" {
					an.add(Indicator{ID: "persistence.download-and-run", Verdict: Compromise,
						Title:    "A scheduled job or service runs a downloaded or hidden program",
						Detail:   a.Source + " runs `" + strings.TrimSpace(m) + "`. Piping a download into a shell, decoding base64, opening /dev/tcp or running from /tmp is what an implant's start-up line looks like, not a package's.",
						Evidence: []Evidence{{Artifact: a.Path, Line: i + 1, Text: l}}})
				}
			}
		}
	}
	if a, text, ok := an.b.one("preload"); ok && strings.TrimSpace(text) != "" {
		an.add(Indicator{ID: "persistence.ld-preload", Verdict: Compromise,
			Title:    "A library is preloaded into every program",
			Detail:   "/etc/ld.so.preload names " + strings.Join(strings.Fields(text), ", ") + ". Every program on the host loads it first. No distribution uses this file; userland rootkits do.",
			Evidence: []Evidence{{Artifact: a.Path, Line: 1, Text: strings.TrimSpace(text)}}})
	}

	// Recent changes to the places persistence lives.
	a, text, ok := an.b.one("recent-files")
	if !ok {
		return
	}
	var ev []Evidence
	for i, l := range lines(text)[1:] {
		f := strings.Split(l, "\t")
		if len(f) < 6 || !persistencePath(f[0]) || an.packaged(f[0]) {
			continue
		}
		// An enablement symlink is the trace of `systemctl enable`, and the
		// unit it points to is judged on its own; passwd- and friends are
		// the copies the account tools keep of the previous version.
		if strings.HasPrefix(f[1], "L") || strings.HasSuffix(f[0], "-") {
			continue
		}
		mt, _ := time.Parse(time.RFC3339, f[4])
		ct, _ := time.Parse(time.RFC3339, f[5])
		an.event(ct, "file", "changed: "+f[0], a.Path)
		ev = append(ev, Evidence{Artifact: a.Path, Line: i + 2, Text: l})
		// Backdating is judged only where it hides something that runs.
		// Shell start-up files are copied from /etc/skel with their original
		// times every time an account is made, so there it is the norm.
		if executesPath(f[0]) && ct.Sub(mt) > 7*24*time.Hour && !ct.Before(an.since) {
			an.add(Indicator{ID: "file.timestamp-mismatch", Verdict: Suspicious,
				Title:    "A file's modification time is older than its last change",
				Detail:   f[0] + " says it was modified " + mt.Format("2006-01-02") + " but its inode changed " + ct.Format("2006-01-02 15:04") + ". Backdating a file with `touch -d` leaves exactly this; so does restoring one from a backup.",
				Evidence: []Evidence{{Artifact: a.Path, Line: i + 2, Text: l}}})
		}
	}
	if len(ev) > 0 {
		an.add(Indicator{ID: "persistence.recent-change", Verdict: Suspicious,
			Title:  "Start-up, login or privilege files changed recently",
			Detail: fmt.Sprintf("%d files that decide what runs at boot or on a schedule, who can log in, or who can become root changed in the window. Each should match something you did.", len(ev)),
			Count:  len(ev), Evidence: ev})
	}
}

// executesPath is the subset of persistencePath whose files are run, by
// cron, systemd, the loader or a login shell's PATH.
func executesPath(p string) bool {
	for _, pre := range []string{"/etc/cron", "/var/spool/cron/", "/etc/systemd/system/", "/etc/ld.so.preload",
		"/etc/rc.local", "/etc/profile.d/", "/usr/local/bin/", "/usr/local/sbin/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

func persistencePath(p string) bool {
	for _, pre := range []string{"/etc/cron", "/var/spool/cron/", "/etc/systemd/system/", "/etc/sudoers", "/etc/passwd", "/etc/shadow",
		"/etc/group", "/etc/ld.so.preload", "/etc/rc.local", "/etc/profile.d/", "/usr/local/bin/", "/usr/local/sbin/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return strings.HasSuffix(p, "/.ssh/authorized_keys") || strings.HasSuffix(p, "/.bashrc") || strings.HasSuffix(p, "/.profile")
}

// --- integrity -------------------------------------------------------------

var dpkgVerifyLine = regexp.MustCompile(`^([.?A-Za-z0-9]{9})\s+(c?)\s*(/\S+)`)

func (an *analysis) loadPackages() {
	an.owners, an.modified = map[string]string{}, map[string]bool{}
	if _, text, ok := an.b.one("pkg-owner"); ok {
		for _, l := range lines(text) {
			if p, owner, ok := strings.Cut(l, "\t"); ok {
				an.owners[p] = owner
			}
		}
	}
	if _, text, ok := an.b.one("pkg-verify"); ok {
		for _, l := range lines(text) {
			if m := dpkgVerifyLine.FindStringSubmatch(l); m != nil {
				an.modified[m[3]] = true
			}
		}
	}
}

// packaged reports whether the package manager installed p unchanged —
// which explains an old mtime under a new ctime, and a recent change made
// by an upgrade.
func (an *analysis) packaged(p string) bool {
	o, ok := an.owners[p]
	return ok && o != "-" && !an.modified[p]
}

func (an *analysis) integrity() {
	suid := map[string]bool{}
	if _, text, ok := an.b.one("suid"); ok {
		for _, l := range lines(text)[1:] {
			p, _, _ := strings.Cut(l, "\t")
			suid[p] = true
		}
	}
	if a, text, ok := an.b.one("pkg-owner"); ok {
		for i, l := range lines(text) {
			p, owner, ok := strings.Cut(l, "\t")
			if ok && owner == "-" && suid[p] {
				an.add(Indicator{ID: "integrity.setuid-unpackaged", Verdict: Compromise,
					Title:    "A setuid program no package installed",
					Detail:   p + " runs as its owner whoever starts it, and no installed package claims it. A setuid copy of a shell left behind is the classic way back to root.",
					Evidence: []Evidence{{Artifact: a.Path, Line: i + 1, Text: l}}})
			}
		}
	}
	a, text, ok := an.b.one("pkg-verify")
	if !ok {
		return
	}
	var ev []Evidence
	for i, l := range lines(text) {
		m := dpkgVerifyLine.FindStringSubmatch(l)
		if m == nil || m[2] == "c" || !strings.Contains(m[1], "5") {
			continue
		}
		p := m[3]
		if strings.HasPrefix(p, "/usr/bin/") || strings.HasPrefix(p, "/usr/sbin/") || strings.HasPrefix(p, "/bin/") ||
			strings.HasPrefix(p, "/sbin/") || strings.HasPrefix(p, "/usr/lib/") || strings.HasPrefix(p, "/lib/") {
			ev = append(ev, Evidence{Artifact: a.Path, Line: i + 1, Text: l})
		}
	}
	if len(ev) > 0 {
		an.add(Indicator{ID: "integrity.package-file-modified", Verdict: Compromise,
			Title:  "Installed programs no longer match their packages",
			Detail: fmt.Sprintf("%d programs or libraries have contents different from what their package installed (the package manager's own checksum disagrees). Replacing system binaries is how rootkits hide.", len(ev)),
			Count:  len(ev), Evidence: ev})
	}
}

// --- anti-forensics --------------------------------------------------------

func (an *analysis) antiForensics() {
	if a, text, ok := an.b.one("history-links"); ok {
		for i, l := range lines(text) {
			f := strings.Split(l, "\t")
			if len(f) >= 3 && f[2] == "/dev/null" {
				an.add(Indicator{ID: "antiforensic.history-disabled", Verdict: Suspicious,
					Title:    "A shell history is linked to /dev/null",
					Detail:   f[0] + " points at /dev/null, so nothing typed in that account's shell is kept. Some people do this on purpose; intruders do it routinely.",
					Evidence: []Evidence{{Artifact: a.Path, Line: i + 1, Text: l}}})
			}
		}
	}
	if a, text, ok := an.b.one("log-sizes"); ok {
		for i, l := range lines(text)[1:] {
			f := strings.Split(l, "\t")
			if len(f) >= 4 && f[3] == "0" && (strings.HasSuffix(f[0], "/wtmp") || strings.HasSuffix(f[0], "/auth.log")) {
				an.add(Indicator{ID: "antiforensic.log-emptied", Verdict: Suspicious,
					Title:    "A login record is empty",
					Detail:   f[0] + " is empty. It is written on every login; an empty one on a host that has been up and used means it was cleared, by rotation just now or by hand.",
					Evidence: []Evidence{{Artifact: a.Path, Line: i + 2, Text: l}}})
			}
		}
	}
}

// --- gaps ------------------------------------------------------------------

// readinessGaps maps each forensic-readiness finding to the investigation
// question it leaves unanswerable.
var readinessGaps = map[string]string{
	"forensic.journald-volatile":      "What happened before the last reboot?",
	"forensic.journald-retention":     "Does the journal reach back 90 days?",
	"forensic.logrotate-short":        "Do the authentication and web logs reach back 90 days?",
	"forensic.auditd-missing":         "What programs did the web server's account run?",
	"forensic.service-exec-unaudited": "What programs did the web server's account run?",
	"forensic.time-unsynced":          "Can the times in these logs be trusted and lined up with anyone else's?",
	"forensic.weblog-no-size":         "Did a request carry an unusually large body, as exploit payloads do?",
	"forensic.no-remote-log":          "If the logs here were edited, is there an untouched copy?",
}

func (an *analysis) gaps() {
	if _, text, ok := an.b.one("readiness"); ok {
		var fs []struct{ ID, Title, Description string }
		_ = json.Unmarshal([]byte(text), &fs)
		seen := map[string]bool{}
		for _, f := range fs {
			q, ok := readinessGaps[f.ID]
			if !ok || seen[q] {
				continue
			}
			seen[q] = true
			an.res.Gaps = append(an.res.Gaps, Gap{Question: q, Reason: f.Title, Finding: f.ID})
		}
	}
	// Coverage the logs actually have, whatever the configuration says.
	if l := an.sshLines(); len(l) == 0 {
		an.res.Gaps = append(an.res.Gaps, Gap{Question: "Who logged in over SSH, and from where?",
			Reason: "No SSH log entries were collected for the window: no auth log, and the journal had none."})
	} else if first := l[0].t; !first.IsZero() && first.Sub(an.since) > 48*time.Hour {
		an.res.Gaps = append(an.res.Gaps, Gap{Question: "Who logged in over SSH, and from where, across the whole window?",
			Reason: "The oldest SSH log entry is from " + first.Format("2006-01-02") + "; everything before it was not kept."})
	}
}
