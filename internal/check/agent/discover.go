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
	b, err := os.ReadFile(passwdPath) //nolint:gosec // G304: caller-supplied system path
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
		// The home stats fine and its markers still may not. Statting a
		// directory needs only search permission on its *parent*, so a home
		// mode 0700 owned by someone else passes the check above and denies
		// everything underneath it — which is the ordinary shape of a
		// multi-user host scanned without root.
		blind := false
		for _, rt := range rts {
			switch installed, err := hasMarker(h.Home, rt); {
			case err != nil:
				blind = true
			case installed:
				found = append(found, install{user: h, rt: rt})
			}
		}
		if blind {
			unreadable = append(unreadable, h.Home)
		}
	}
	return found, unreadable
}

// hasMarker reports whether rt is installed under home.
//
// A non-nil error means the question could not be answered, which is not the
// same as answering no — and treating it as no is what let an unreadable home
// report as an account with nothing installed. Only os.IsNotExist is a real
// negative; anything else is a blind spot the caller has to account for.
//
// A runtime found through one marker is installed regardless of what the
// others say, so a positive wins outright. Otherwise any unanswerable marker
// makes the whole answer unanswerable.
func hasMarker(home string, rt Runtime) (bool, error) {
	var blind error
	for _, m := range rt.Markers {
		switch _, err := os.Stat(filepath.Join(home, m)); {
		case err == nil:
			return true, nil
		case !os.IsNotExist(err):
			blind = err
		}
	}
	return false, blind
}
