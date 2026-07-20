package agent

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// userHome is one account that could plausibly own an agent runtime.
type userHome struct {
	Name string
	Home string
}

// skeletonHomes are the placeholder home directories system accounts are
// given. They are shared by many accounts and never hold a user's config, so
// probing them would produce duplicate work and misattributed findings.
var skeletonHomes = map[string]bool{
	"/":            true,
	"/nonexistent": true,
	"/dev/null":    true,
	"/bin/false":   true,
	"":             true,
}

// homes parses /etc/passwd for the accounts a person might actually log in as
// and run an agent under: root, plus the regular-user UID range. The nobody
// UID (65534) and the service accounts below 1000 are excluded — an agent
// runtime under those is not a configuration hostveil should be guessing at.
//
// Results are deduplicated by home directory, because two accounts sharing a
// home would otherwise produce two identical findings for one config file.
func homes(passwdPath string) ([]userHome, error) {
	b, err := os.ReadFile(passwdPath) //nolint:gosec // caller-supplied system path
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var out []userHome
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 6 {
			continue
		}
		uid, err := strconv.Atoi(strings.TrimSpace(fields[2]))
		if err != nil {
			continue
		}
		if uid != 0 && (uid < 1000 || uid >= 65534) {
			continue
		}
		home := filepath.Clean(strings.TrimSpace(fields[5]))
		if skeletonHomes[home] || seen[home] {
			continue
		}
		seen[home] = true
		out = append(out, userHome{Name: fields[0], Home: home})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// install is one runtime found under one user's home.
type install struct {
	user userHome
	rt   Runtime
}

// subject identifies the install for a finding's Service field, so two users
// each running the same runtime produce two distinct Finding.Key()s rather
// than deduplicating to one.
func (i install) subject() string { return i.rt.Name + "@" + i.user.Name }

// path resolves a home-relative path from the runtime registry.
func (i install) path(rel string) string { return filepath.Join(i.user.Home, rel) }

// installs stats each runtime's markers under each home. It only ever stats
// paths named in the registry — no home directory is ever walked, so the
// checker learns that a runtime exists without reading anything it was not
// explicitly pointed at.
//
// unreadable collects homes that could not be stat'ed at all, which the
// caller reports as partial coverage: an unreadable home may hide a runtime,
// and silently returning fewer installs would let that pass for "none".
func installs(hs []userHome, rts []Runtime) (found []install, unreadable []string) {
	for _, h := range hs {
		if _, err := os.Stat(h.Home); err != nil {
			if !os.IsNotExist(err) {
				unreadable = append(unreadable, h.Home)
			}
			continue
		}
		for _, rt := range rts {
			for _, m := range rt.Markers {
				if _, err := os.Stat(filepath.Join(h.Home, m)); err == nil {
					found = append(found, install{user: h, rt: rt})
					break
				}
			}
		}
	}
	return found, unreadable
}
