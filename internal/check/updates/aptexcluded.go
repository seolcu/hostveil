package updates

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// This file answers a question the rest of the domain cannot: unattended-
// upgrades is switched on, but which of the waiting upgrades will it ever
// install?
//
// It installs only from repositories its origin patterns allow, and the
// distribution's default allows the distribution and nothing else. Every
// repository added by hand — Tailscale, Docker, a web server's own repo, and
// on a Raspberry Pi the archive that ships the kernel, libc and openssl —
// is left out unless someone writes a pattern for it. Nothing reports that:
// the timer runs, the log says it found nothing to do, and the packages wait.
// A Pi measured for this sat 55 packages and one kernel line behind for 96
// days while `updates.pending-security` counted one, because its count only
// reads suites ending in -security and the Pi archive has no such suite.
//
// The rule is unattended-upgrades' own, reproduced rather than approximated:
// a pattern is a comma-separated list of key=value tests on the release
// record apt keeps for each source, every test must pass, values are
// fnmatch globs after ${distro_id} and ${distro_codename} are substituted,
// and the legacy Allowed-Origins form "origin:archive" means o=…,a=….
// apt itself is asked for every input — the patterns through apt-config, the
// release records and each package's candidate source through apt-cache —
// so the answer follows the layered configuration the same way
// aptorigin.go's does.

// Keys apt-config is asked for. Both lists are read: Allowed-Origins is the
// legacy form Ubuntu still ships, Origins-Pattern the one everything else uses.
const (
	originsPatternKey = "Unattended-Upgrade::Origins-Pattern"
	allowedOriginsKey = "Unattended-Upgrade::Allowed-Origins"
)

// aptRelease is the part of a source's release record a pattern can test.
type aptRelease struct {
	Origin, Archive, Codename, Label, Component, Site string
}

// excludedGroup is one repository whose upgrades unattended-upgrades skips.
type excludedGroup struct {
	Release  aptRelease
	Packages []string
}

// excludedOrigins returns the repositories holding upgrades that
// unattended-upgrades will not install, given `apt list --upgradable`'s
// output. distroID is os-release's ID and codename its VERSION_CODENAME;
// both are what ${distro_id} and ${distro_codename} stand for.
//
// An error means the question could not be answered, never that the answer
// is "none".
func excludedOrigins(ctx context.Context, r platform.CommandRunner, upgradable, distroID, codename string) ([]excludedGroup, error) {
	names := upgradableNames(upgradable)
	if len(names) == 0 {
		return nil, nil
	}
	if codename == "" {
		return nil, fmt.Errorf("cannot tell which repositories unattended-upgrades installs from: no VERSION_CODENAME in os-release to substitute for ${distro_codename}")
	}
	if !platform.Has(r, "apt-config") || !platform.Has(r, "apt-cache") {
		return nil, fmt.Errorf("cannot tell which repositories unattended-upgrades installs from: apt-config or apt-cache is missing")
	}
	dump, err := r.Run(ctx, "apt-config", "dump", originsPatternKey, allowedOriginsKey)
	if err != nil {
		return nil, fmt.Errorf("cannot read unattended-upgrades' origin patterns: %w", err)
	}
	patterns := uuPatterns(string(dump), distroIDName(distroID), codename)

	policy, err := r.Run(ctx, "apt-cache", "policy")
	if err != nil {
		return nil, fmt.Errorf("cannot read apt's source list: %w", err)
	}
	releases := policyReleases(string(policy))

	cands, err := r.Run(ctx, "apt-cache", append([]string{"policy"}, names...)...)
	if err != nil {
		return nil, fmt.Errorf("cannot read the upgrades' candidate sources: %w", err)
	}

	byOrigin := map[aptRelease][]string{}
	for pkg, sources := range candidateSources(string(cands)) {
		var rels []aptRelease
		for _, s := range sources {
			if rel, ok := releases[s]; ok {
				rels = append(rels, rel)
			}
		}
		if len(rels) == 0 || anyAllowed(rels, patterns) {
			continue
		}
		// unattended-upgrades installs a version when any of the sources
		// carrying it is allowed, so the first is as good a name as any for
		// the repository it is waiting in.
		rel := rels[0]
		if distroOwn(rel.Origin, distroIDName(distroID)) {
			// The distribution's own pockets outside the default — Ubuntu's
			// -updates, Debian's stable-updates — are left out on purpose by
			// the distribution, and only security fixes are this domain's
			// business; updates.pending-security counts those.
			continue
		}
		byOrigin[rel] = append(byOrigin[rel], pkg)
	}

	groups := make([]excludedGroup, 0, len(byOrigin))
	for rel, pkgs := range byOrigin {
		sort.Strings(pkgs)
		groups = append(groups, excludedGroup{Release: rel, Packages: pkgs})
	}
	sort.Slice(groups, func(i, j int) bool {
		if len(groups[i].Packages) != len(groups[j].Packages) {
			return len(groups[i].Packages) > len(groups[j].Packages)
		}
		return groups[i].Release.Origin < groups[j].Release.Origin
	})
	return groups, nil
}

// upgradableNames reads the package names out of `apt list --upgradable`:
// "name/suite[,suite] version arch [upgradable from: …]".
func upgradableNames(out string) []string {
	var names []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		name, rest, ok := strings.Cut(strings.TrimSpace(line), "/")
		if !ok || name == "" || !strings.Contains(rest, "upgradable from:") || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}

// uuPatterns turns apt-config's dump of both keys into normalized patterns,
// each a list of key/value tests. Allowed-Origins entries are converted the
// way unattended-upgrades converts them, to o=<before the colon>,a=<after>.
func uuPatterns(dump, distroID, codename string) [][][2]string {
	subst := strings.NewReplacer("${distro_id}", distroID, "${distro_codename}", codename)
	var out [][][2]string
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		var legacy bool
		switch {
		case strings.HasPrefix(line, originsPatternKey+"::"):
		case strings.HasPrefix(line, allowedOriginsKey+"::"):
			legacy = true
		default:
			continue
		}
		value, ok := quoted(line)
		if !ok || value == "" {
			continue
		}
		value = subst.Replace(value)
		if legacy {
			o, a, ok := splitUnescaped(value, ':')
			if !ok {
				o, a, ok = strings.Cut(value, " ")
			}
			if !ok {
				continue
			}
			out = append(out, [][2]string{{"o", strings.ReplaceAll(o, `\:`, ":")}, {"a", a}})
			continue
		}
		var tests [][2]string
		for _, tok := range splitEscapedCommas(value) {
			k, v, ok := strings.Cut(tok, "=")
			if !ok {
				continue
			}
			tests = append(tests, [2]string{strings.TrimSpace(k), strings.TrimSpace(v)})
		}
		if len(tests) > 0 {
			out = append(out, tests)
		}
	}
	return out
}

// quoted returns the value between the first pair of double quotes, which is
// how apt-config dump prints every value.
func quoted(line string) (string, bool) {
	a := strings.Index(line, `"`)
	if a < 0 {
		return "", false
	}
	b := strings.LastIndex(line, `"`)
	if b <= a {
		return "", false
	}
	return line[a+1 : b], true
}

// splitUnescaped splits s at the first sep not preceded by a backslash.
func splitUnescaped(s string, sep byte) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep && (i == 0 || s[i-1] != '\\') {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// splitEscapedCommas splits a pattern on commas, keeping "\," as a literal
// comma inside a value.
func splitEscapedCommas(s string) []string {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == ',' {
			cur.WriteByte(',')
			i++
			continue
		}
		if s[i] == ',' {
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(s[i])
	}
	return append(parts, cur.String())
}

// anyAllowed reports whether any of the releases passes any pattern.
func anyAllowed(rels []aptRelease, patterns [][][2]string) bool {
	for _, rel := range rels {
		for _, p := range patterns {
			if patternMatches(p, rel) {
				return true
			}
		}
	}
	return false
}

// patternMatches applies one pattern to one release: every test must pass.
// A key unattended-upgrades does not know makes it reject the whole config,
// so it is treated here as a test that fails rather than one that passes.
func patternMatches(tests [][2]string, rel aptRelease) bool {
	for _, t := range tests {
		var field string
		switch t[0] {
		case "o", "origin":
			field = rel.Origin
		case "l", "label":
			field = rel.Label
		case "a", "archive", "suite":
			field = rel.Archive
		case "c", "component":
			field = rel.Component
		case "n", "codename":
			field = rel.Codename
		case "site":
			field = rel.Site
		default:
			return false
		}
		if !fnmatch(t[1], field) {
			return false
		}
	}
	return true
}

// fnmatch is Python's fnmatch.fnmatchcase, which is what unattended-upgrades
// calls: * and ? match any character including '/', unlike path.Match, and an
// origin such as "cloudsmith/caddy/stable" depends on that.
func fnmatch(pattern, s string) bool {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '[':
			end := strings.IndexByte(pattern[i+1:], ']')
			if end < 0 {
				b.WriteString(`\[`)
				continue
			}
			class := pattern[i+1 : i+1+end]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
			i += end + 1
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return pattern == s
	}
	return re.MatchString(s)
}

// policyReleases maps each source line of `apt-cache policy` — "URL dist/comp
// arch Packages", the same text a package's version table prints — to the
// release record printed under it.
func policyReleases(out string) map[string]aptRelease {
	rels := map[string]aptRelease{}
	var current string
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "release "):
			if current == "" {
				continue
			}
			rel := rels[current]
			for _, kv := range strings.Split(strings.TrimPrefix(t, "release "), ",") {
				k, v, _ := strings.Cut(kv, "=")
				switch k {
				case "o":
					rel.Origin = v
				case "a":
					rel.Archive = v
				case "n":
					rel.Codename = v
				case "l":
					rel.Label = v
				case "c":
					rel.Component = v
				}
			}
			rels[current] = rel
		case strings.HasPrefix(t, "origin "):
			if current == "" {
				continue
			}
			rel := rels[current]
			rel.Site = strings.TrimPrefix(t, "origin ")
			rels[current] = rel
		default:
			current = ""
			if src, ok := sourceLine(t); ok {
				current = src
				rels[current] = aptRelease{}
			}
		}
	}
	// The dpkg status file has a record too (a=now) and is no repository.
	for k, rel := range rels {
		if rel.Origin == "" {
			delete(rels, k)
		}
	}
	return rels
}

// sourceLine reads "<priority> <source>" and returns the source, which is a
// URL line or a local path.
func sourceLine(t string) (string, bool) {
	prio, rest, ok := strings.Cut(t, " ")
	if !ok || prio == "" {
		return "", false
	}
	for _, r := range prio {
		if !unicode.IsDigit(r) && r != '-' {
			return "", false
		}
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", false
	}
	return rest, true
}

// candidateSources reads `apt-cache policy <pkg>…` and returns, for each
// package whose candidate differs from what is installed, the sources that
// carry the candidate version.
func candidateSources(out string) map[string][]string {
	res := map[string][]string{}
	var pkg, installed, candidate string
	inCandidate := false
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if line[0] != ' ' && strings.HasSuffix(line, ":") {
			// "libc6:" or, on a multiarch host, "libc6:arm64:".
			pkg, installed, candidate, inCandidate = strings.TrimSuffix(line, ":"), "", "", false
			continue
		}
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "Installed:"):
			installed = strings.TrimSpace(strings.TrimPrefix(t, "Installed:"))
		case strings.HasPrefix(t, "Candidate:"):
			candidate = strings.TrimSpace(strings.TrimPrefix(t, "Candidate:"))
		case t == "Version table:":
		case strings.HasPrefix(line, "        "):
			// A source row, indented eight: "<priority> <URL or path>". Told
			// apart from a version row by its indent rather than its shape,
			// because a version can be all digits (20260626) and read as a
			// priority.
			if !inCandidate || pkg == "" || candidate == "" || candidate == "(none)" || candidate == installed {
				continue
			}
			if src, ok := sourceLine(t); ok && !strings.HasPrefix(src, "/") {
				res[pkg] = append(res[pkg], src)
			}
		default:
			// A version row, "     <version> <priority>", or " *** " for the
			// installed one.
			if fields := strings.Fields(strings.TrimPrefix(t, "*** ")); len(fields) == 2 {
				inCandidate = fields[0] == candidate
			}
		}
	}
	return res
}

// distroIDName is what unattended-upgrades substitutes for ${distro_id}: the
// distributor name lsb_release prints, "Ubuntu" or "Debian", which os-release
// spells in lower case.
func distroIDName(id string) string {
	if id == "" {
		return ""
	}
	return strings.ToUpper(id[:1]) + id[1:]
}

// distroOwn reports whether an origin is the distribution itself: "Ubuntu",
// "Debian", and Ubuntu's ESM pockets, which are named after it.
func distroOwn(origin, distroID string) bool {
	return distroID != "" && strings.HasPrefix(origin, distroID)
}

// osReleaseCodename reads VERSION_CODENAME from an os-release file.
func osReleaseCodename(path string) string {
	data, err := os.ReadFile(path) //nolint:gosec // os-release, a fixed system path or a test fixture
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "VERSION_CODENAME="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// originPattern renders the Origins-Pattern line that allows rel: origin and
// codename (archive where there is no codename), and the label when it is a
// plain value. A label such as cloudsmith's "source=none" carries an '='
// that unattended-upgrades' parser would split on, and origin plus codename
// already name the repository.
func originPattern(rel aptRelease) string {
	esc := func(v string) string { return strings.ReplaceAll(v, ",", `\,`) }
	p := "origin=" + esc(rel.Origin)
	switch {
	case rel.Codename != "":
		p += ",codename=" + esc(rel.Codename)
	case rel.Archive != "":
		p += ",archive=" + esc(rel.Archive)
	}
	if rel.Label != "" && !strings.ContainsAny(rel.Label, `="`) {
		p += ",label=" + esc(rel.Label)
	}
	return p
}

// excludedFinding reports every skipped repository in one finding: the fix is
// one config file whichever of them the operator decides to trust.
func excludedFinding(groups []excludedGroup) model.Finding {
	var desc, patterns []string
	total := 0
	for _, g := range groups {
		total += len(g.Packages)
		sample := g.Packages
		more := ""
		if len(sample) > 5 {
			more = fmt.Sprintf(" and %d more", len(sample)-5)
			sample = sample[:5]
		}
		desc = append(desc, fmt.Sprintf("%s (%d: %s%s)", g.Release.Origin, len(g.Packages), strings.Join(sample, " "), more))
		patterns = append(patterns, originPattern(g.Release))
	}
	core := ""
	for _, g := range groups {
		for _, p := range g.Packages {
			if strings.HasPrefix(p, "linux-image") || p == "libc6" || strings.HasPrefix(p, "libssl") || p == "openssl" || p == "openssh-server" {
				core = " Some of them are the kernel or a core library, which is where security fixes land."
				break
			}
		}
	}
	return model.NewFinding("updates.origin-excluded",
		fmt.Sprintf("%d waiting update(s) come from repositories automatic updates never install from", total),
		model.SeverityMedium, model.SourceUpdates, model.RemediationReview,
		model.WithDescription("unattended-upgrades is enabled, but it only installs from repositories its origin patterns allow, and by default that is the distribution alone. These updates come from repositories added later — a vendor's own repo, or on a Raspberry Pi the archive that ships its kernel and libraries — so they will wait until someone installs them by hand, while the timer runs every day and reports nothing to do. They are not counted as security updates because these repositories have no -security suite to tell them apart."+core),
		model.WithHowToFix("Decide which of these repositories you trust to update unattended, and add a line for each to `Unattended-Upgrade::Origins-Pattern` in a file under /etc/apt/apt.conf.d, e.g. `\""+patterns[0]+"\";`. Check with `sudo unattended-upgrade --dry-run --debug`. Or install them now: `sudo apt update && sudo apt full-upgrade`."),
		model.WithEvidence("repositories", strings.Join(desc, model.EvidenceSeparator)),
		model.WithEvidence("patterns", strings.Join(patterns, "\n")),
	)
}
