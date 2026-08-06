package dockerd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/platform"
)

// maxConfigBytes bounds the daemon.json read. The real file is a handful of
// lines; anything approaching this is not a configuration file, and reading
// it unbounded during a scan is how one strange path stalls a domain.
const maxConfigBytes = 1 << 20

// config is the daemon's socket and TLS configuration, merged from
// daemon.json and the service unit's ExecStart.
//
// Only the settings `docker info` cannot report are collected here. Anything
// the running daemon can be asked about directly is read from there instead,
// because this file records what the operator asked for and `docker info`
// records what the daemon is doing — and after an edit-without-restart those
// are different answers to different questions.
type config struct {
	hosts     []string
	tls       bool
	tlsVerify bool

	inFile bool // daemon.json contributed
	inUnit bool // the unit's ExecStart contributed
}

// origin names where the operator will find the settings this finding is
// about, which is not always where they expect: a packaged unit carrying
// `-H` on its ExecStart is invisible to anyone reading daemon.json.
func (c config) origin() string {
	switch {
	case c.inFile && c.inUnit:
		return "daemon.json and the service unit"
	case c.inUnit:
		return "the service unit's ExecStart"
	default:
		return "daemon.json"
	}
}

// exposedEndpoints lists the configured TCP endpoints reachable from off this
// host, in sorted order so a repeat scan produces no delta nobody caused.
//
// Unix and fd sockets are not endpoints in this sense — they are the local
// socket, judged by its permissions instead. A loopback TCP socket is
// deliberately clean: it is the documented way to put a proxy in front of the
// daemon, and it is reachable by nothing the unix socket was not.
func (c config) exposedEndpoints() []string {
	var out []string
	for _, h := range c.hosts {
		host, _, ok := splitEndpoint(h)
		if !ok {
			continue
		}
		// A bare wildcard, an empty host, or a name we cannot resolve to a
		// loopback literal all mean "reachable from somewhere else".
		if (platform.Listener{Addr: host}).Loopback() {
			continue
		}
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// splitEndpoint parses a Docker host string such as "tcp://0.0.0.0:2375".
// Anything that is not TCP is not an endpoint this domain judges, and is
// rejected rather than guessed at.
func splitEndpoint(h string) (host string, port int, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(h), "tcp://")
	if !found {
		return "", 0, false
	}
	hostPart, portPart, err := net.SplitHostPort(rest)
	if err != nil {
		// "tcp://0.0.0.0" with no port is legal and means the default.
		return strings.Trim(rest, "[]"), 2375, true
	}
	p, err := strconv.Atoi(portPart)
	if err != nil {
		return "", 0, false
	}
	return hostPart, p, true
}

// readConfig merges daemon.json with the unit's ExecStart flags.
//
// Both are read because either alone is a partial view: the packaged unit
// ships `-H fd://` on ExecStart while an operator adding a TCP socket may
// edit either, and Docker refuses to start when `hosts` is set in both at
// once — so in a reachable daemon at most one of them is carrying the
// setting, and the checker cannot know in advance which.
//
// It reports not-known only when neither source could be consulted. An absent
// daemon.json is a complete answer, not a failed read: it means no options
// are set there, which is the default state of most hosts.
func (c *Checker) readConfig(ctx context.Context, env platform.Env) (config, bool, string) {
	var cfg config
	var failed []string

	fileCfg, err := readDaemonJSON(c.DaemonConfig)
	switch {
	case err == nil:
		cfg = fileCfg
		cfg.inFile = fileCfg.inFile
	case os.IsNotExist(err):
		// No file, no options. A complete answer.
	default:
		failed = append(failed, fmt.Sprintf("cannot read %s", c.DaemonConfig))
	}

	unitHosts, unitTLS, unitVerify, unitReason := c.readUnit(ctx, env)
	if unitReason == "" {
		cfg.inUnit = true
		cfg.hosts = append(cfg.hosts, unitHosts...)
		cfg.tls = cfg.tls || unitTLS
		cfg.tlsVerify = cfg.tlsVerify || unitVerify
	}

	// The substitution runs one way only, and the guard here used to run it
	// both ways.
	//
	// Having parsed the unit does make up for an unreadable daemon.json — the
	// unit carries the socket flags and the TLS flags alike, and `hosts` set in
	// both places stops Docker from starting at all, so in a daemon that
	// answered at most one of them holds it. That direction stays.
	//
	// The reverse was never claimed and is not true. An absent daemon.json is a
	// complete answer *about that file* — no options are set there, the default
	// state of most hosts — and says nothing whatever about the unit, which is
	// where every mainstream package puts the listening socket. Requiring both
	// sources to fail therefore never fired on the ordinary shape of the
	// failure: no daemon.json plus an unreadable unit reported "audited, no
	// sockets configured", which is the exact conclusion readUnit exists to
	// prevent.
	//
	// A daemon.json that does carry `hosts` does not cover for it either. That
	// exclusion binds `hosts` and nothing else, while `tlsverify` lives on the
	// unit just as often and has no such rule — so trusting the file alone
	// there reports an unauthenticated API, the worst thing this domain can
	// find, on a
	// host running mutual TLS.
	if unitReason != "" {
		if len(failed) > 0 {
			return config{}, false, failed[0] + " and " + unitReason +
				" — the API socket and TLS settings were not audited"
		}
		return config{}, false, unitReason + " — the API socket and TLS settings were not audited"
	}
	return cfg, true, ""
}

// daemonJSON is the narrow view of daemon.json this domain needs. Docker
// accepts dozens of keys; decoding into a struct rather than a map means an
// unrelated key added by a future Docker release cannot change what is read.
type daemonJSON struct {
	Hosts     []string `json:"hosts"`
	TLS       *bool    `json:"tls"`
	TLSVerify *bool    `json:"tlsverify"`
	TLSCert   string   `json:"tlscert"`
}

func readDaemonJSON(path string) (config, error) {
	b, err := platform.ReadFileNoFollow(path, maxConfigBytes)
	if err != nil {
		return config{}, err
	}
	// An empty file is valid to dockerd and means no options set.
	if len(strings.TrimSpace(string(b))) == 0 {
		return config{inFile: true}, nil
	}
	var d daemonJSON
	if err := json.Unmarshal(b, &d); err != nil {
		return config{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	cfg := config{hosts: d.Hosts, inFile: true}
	// A certificate without the `tls` switch still means the operator set up
	// TLS: dockerd turns it on implicitly. Reading only the boolean would
	// grade a TLS-serving daemon as if it were plaintext.
	cfg.tls = (d.TLS != nil && *d.TLS) || d.TLSCert != ""
	cfg.tlsVerify = d.TLSVerify != nil && *d.TLSVerify
	// tlsverify implies tls, in dockerd and here.
	cfg.tls = cfg.tls || cfg.tlsVerify
	return cfg, nil
}

// readUnit pulls daemon flags off the service unit's ExecStart.
//
// This is not redundant with daemon.json. Every mainstream package ships the
// daemon's listening socket as a flag on the unit, so a checker that read
// only the file would conclude that a host with a TCP socket on its ExecStart
// had no sockets configured at all.
// LoadState is asked for alongside ExecStart because `systemctl show` on a
// unit that does not exist **exits 0 and prints nothing** for ExecStart. Reading
// err == nil as "inspected, and it carries no flags" is a claim the command
// never made: the unit was not read, it was not there. Only LoadState
// distinguishes the two, and it is the whole reason this asks for a property it
// does not otherwise use.
//
// That matters wherever the daemon's unit is not literally docker.service — a
// snap install (snap.docker.dockerd.service), a rootless daemon whose unit
// lives in the user manager, or a host where something else starts it. On any
// of those, a TCP socket on the real unit was invisible while this domain
// reported its API rules fully audited.
//
// The reason is returned rather than a bool so readConfig can say *which*
// source it lost; a host with no systemd at all and a host whose systemctl
// refused are both gaps, but not the same one to an operator.
func (c *Checker) readUnit(ctx context.Context, env platform.Env) (hosts []string, tls, verify bool, reason string) {
	if env.ServiceManager != platform.SMSystemd {
		return nil, false, false, "this host does not run systemd, so the daemon's own start-up flags could not be read"
	}
	out, err := env.Runner.Run(ctx, "systemctl", "show", c.Unit, "--property=LoadState,ExecStart", "--no-pager")
	if err != nil {
		return nil, false, false, "cannot inspect the " + c.Unit + " unit"
	}
	if state := showProperty(string(out), "LoadState"); state != "loaded" {
		return nil, false, false, "systemd has no " + c.Unit + " (LoadState=" + state + "), so the daemon's start-up flags could not be read"
	}
	for _, argv := range execStartArgv(string(out)) {
		h, t, v := parseDaemonFlags(argv)
		hosts = append(hosts, h...)
		tls = tls || t
		verify = verify || v
	}
	return hosts, tls, verify, ""
}

// showProperty reads one Key=Value line out of `systemctl show` output.
// Records are keyed by name because systemd prints the properties in an order
// of its own, not the order they were asked for.
func showProperty(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// execStartArgv extracts each argv list from `systemctl show --property=
// ExecStart` output, which renders as:
//
//	ExecStart={ path=/usr/bin/dockerd ; argv[]=/usr/bin/dockerd -H fd:// ; ... }
//
// A unit may have several ExecStart entries — a drop-in that clears the
// packaged one with a bare `ExecStart=` and adds its own is the standard way
// to change the daemon's flags — so every argv list is returned.
func execStartArgv(out string) []string {
	var argvs []string
	rest := out
	for {
		i := strings.Index(rest, "argv[]=")
		if i < 0 {
			return argvs
		}
		rest = rest[i+len("argv[]="):]
		end := strings.Index(rest, " ; ")
		if end < 0 {
			// Last field before the closing brace.
			if j := strings.Index(rest, " }"); j >= 0 {
				end = j
			} else {
				argvs = append(argvs, rest)
				return argvs
			}
		}
		argvs = append(argvs, rest[:end])
		rest = rest[end:]
	}
}

// parseDaemonFlags reads the socket and TLS flags out of one dockerd argv.
func parseDaemonFlags(argv string) (hosts []string, tls, verify bool) {
	fields := strings.Fields(argv)
	for i := 0; i < len(fields); i++ {
		arg := fields[i]
		// A flag's value may be attached with "=" or be the next field.
		name, val, attached := strings.Cut(arg, "=")
		next := func() (string, bool) {
			if attached {
				return val, true
			}
			if i+1 < len(fields) {
				i++
				return fields[i], true
			}
			return "", false
		}
		switch name {
		case "-H", "--host":
			if v, ok := next(); ok {
				hosts = append(hosts, v)
			}
		case "--tlsverify":
			// `--tlsverify=false` is an explicit opt-out; a bare flag is on.
			verify = !attached || val != "false"
		case "--tls":
			tls = !attached || val != "false"
		case "--tlscert", "--tlscacert", "--tlskey":
			if _, ok := next(); ok {
				tls = true
			}
		}
	}
	return hosts, tls, verify || false
}
