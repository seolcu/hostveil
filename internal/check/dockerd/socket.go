package dockerd

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/seolcu/hostveil/internal/platform"
)

// socket is the local unix socket's identity: how open it is, and which
// group holds it.
type socket struct {
	path  string
	perm  fs.FileMode
	gid   uint32
	group string // resolved name, or the numeric gid if it has none
}

// member is one account that holds the socket's group.
type member struct {
	name string
	// system marks an account that does not log in interactively — a service
	// identity rather than a person. It is what separates an administrator who
	// chose this from a credential nobody is watching.
	system bool
}

// readSocket stats the daemon's unix socket.
//
// A missing socket is not a failure. A daemon answered `docker version` or
// this checker would not be running at all, so if there is nothing at this
// path the client is reaching it another way — DOCKER_HOST pointing at a
// remote daemon, or a socket somewhere non-standard. There is no local
// socket to judge, which is a different thing from failing to judge one.
func (c *Checker) readSocket() (s socket, known, absent bool, reason string) {
	fi, err := os.Stat(c.SocketPath)
	switch {
	case err == nil:
	case os.IsNotExist(err):
		return socket{}, false, true, ""
	default:
		return socket{}, false, false,
			fmt.Sprintf("cannot inspect %s — its permissions and owning group were not audited", c.SocketPath)
	}

	s = socket{path: c.SocketPath, perm: fi.Mode().Perm()}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		// No unix ownership information available. The mode is still a real
		// answer, so the rule that needs it stands; the group rule reports
		// separately that it could not be resolved.
		return s, true, false, ""
	}
	s.gid = st.Gid
	s.group = c.groupName(st.Gid)
	return s, true, false, ""
}

// groupName resolves a gid to its name via /etc/group, falling back to the
// numeric id.
//
// The socket's group is resolved by gid rather than by looking up the name
// "docker", because the name is not fixed: daemon.json's "group" key and the
// socket unit's SocketGroup both set it, so `"group": "wheel"` is legal and
// means every member of wheel is root on this host. Asking for "docker" by
// name would report a clean host in exactly the case worth catching.
func (c *Checker) groupName(gid uint32) string {
	f, err := os.Open(c.GroupPath)
	if err != nil {
		return strconv.FormatUint(uint64(gid), 10)
	}
	defer func() { _ = f.Close() }()

	want := strconv.FormatUint(uint64(gid), 10)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) >= 3 && fields[2] == want {
			return fields[0]
		}
	}
	return want
}

// readMembers lists the accounts that hold the socket's group, excluding
// root — which already has this authority by every other route, so naming it
// here would be noise in a finding that is about everyone else.
//
// Membership comes from two places and both count: the group's own member
// list in /etc/group, and any account in /etc/passwd whose *primary* group is
// this gid. An account added with `useradd -g docker` appears only in the
// second, and a checker that read only the first would miss it entirely.
func (c *Checker) readMembers(gid uint32) ([]member, bool, string) {
	secondary, err := c.secondaryMembers(gid)
	if err != nil {
		return nil, false, fmt.Sprintf("cannot read %s — the accounts holding the Docker socket's group were not audited", c.GroupPath)
	}
	accounts, err := c.accounts()
	if err != nil {
		return nil, false, fmt.Sprintf("cannot read %s — the accounts holding the Docker socket's group were not audited", c.PasswdPath)
	}

	held := map[string]bool{}
	for _, n := range secondary {
		held[n] = true
	}
	for _, a := range accounts {
		if a.gid == gid {
			held[a.name] = true
		}
	}
	delete(held, "root")

	var out []member
	for name := range held {
		m := member{name: name}
		if a, ok := accounts[name]; ok {
			m.system = a.system()
		} else {
			// Named in /etc/group but absent from /etc/passwd: the account was
			// removed and the membership outlived it. Not a login, so it is
			// treated as the service-account case.
			m.system = true
		}
		out = append(out, m)
	}
	// Sorted so evidence is stable across scans; map iteration is not.
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, true, ""
}

// secondaryMembers reads the group's explicit member list from /etc/group.
func (c *Checker) secondaryMembers(gid uint32) ([]string, error) {
	f, err := os.Open(c.GroupPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	want := strconv.FormatUint(uint64(gid), 10)
	var names []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 4 || fields[2] != want {
			continue
		}
		for _, n := range strings.Split(fields[3], ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
	}
	return names, sc.Err()
}

// account is one /etc/passwd entry, reduced to what decides whether its
// holder is a person.
type account struct {
	name  string
	uid   uint32
	gid   uint32
	shell string
}

// system reports whether this account is a service identity rather than a
// human login. Both signals are needed: a distribution reserves uids below
// 1000 for services, and an account created above that range with a nologin
// shell (the shape most CI runners and agents take) is just as much a
// credential nobody logs into and nobody watches.
// The shell half is platform.IsNonLoginShell, shared with the account
// domain, which asks the same question to decide whether an empty password
// is a login risk. This copy tested the path's suffix and so handled a
// nologin anywhere; the other matched whole paths against a fixed list and
// did not. Sharing settles it at the more portable of the two, and picks up
// /bin/true, which ends a session as firmly as /bin/false.
func (a account) system() bool {
	return a.uid < 1000 || platform.IsNonLoginShell(a.shell)
}

func (c *Checker) accounts() (map[string]account, error) {
	f, err := os.Open(c.PasswdPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	out := map[string]account{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 7 {
			continue
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		gid, err := strconv.ParseUint(fields[3], 10, 32)
		if err != nil {
			continue
		}
		out[fields[0]] = account{
			name:  fields[0],
			uid:   uint32(uid),
			gid:   uint32(gid),
			shell: fields[6],
		}
	}
	return out, sc.Err()
}
