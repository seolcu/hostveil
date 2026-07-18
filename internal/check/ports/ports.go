// Package ports implements a native host listening-port checker. It reads
// the host's TCP listening sockets with `ss` and flags services bound to a
// non-loopback address — the natively-installed exposed database, admin
// panel, or app that the Compose-only exposure checks never see, because it
// isn't a container at all.
package ports

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/check/firewall"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Checker reports host services listening on non-loopback addresses.
type Checker struct{}

// New returns a ports checker.
func New() *Checker { return &Checker{} }

// Source identifies the ports domain.
func (*Checker) Source() model.Source { return model.SourcePorts }

// Available requires the `ss` tool (iproute2); without it the domain is
// skipped cleanly rather than guessed at.
func (*Checker) Available(_ context.Context, env platform.Env) (bool, string) {
	if !platform.Has(env.Runner, "ss") {
		return false, "ss (iproute2) is not installed"
	}
	return true, ""
}

// datastorePorts maps well-known datastore ports to a human name. Mirrors
// the datastore intuition the Compose checker encodes for images: a
// database reachable from the network is a top-tier exposure.
var datastorePorts = map[int]string{
	3306:  "MySQL/MariaDB",
	5432:  "PostgreSQL",
	6379:  "Redis",
	27017: "MongoDB",
	9200:  "Elasticsearch",
	9300:  "Elasticsearch (transport)",
	5984:  "CouchDB",
	11211: "Memcached",
	1433:  "Microsoft SQL Server",
	8086:  "InfluxDB",
	9042:  "Cassandra",
	2379:  "etcd",
	26257: "CockroachDB",
}

// adminPorts maps well-known admin/management-UI ports to a human name.
var adminPorts = map[int]string{
	9000: "Portainer",
	9443: "Portainer (HTTPS)",
}

// listener is one parsed TCP listening socket.
type listener struct {
	addr string
	port int
	proc string
}

// Check reads listening TCP sockets and flags non-loopback exposure.
func (*Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	out, err := env.Runner.Run(ctx, "ss", "-H", "-tlnp")
	if err != nil {
		return nil, fmt.Errorf("listing listening sockets with ss: %w", err)
	}

	var findings []model.Finding
	generic := map[int]listener{} // exposed, non-sensitive; deduped by port
	seenDS := map[int]bool{}      // avoid duplicate findings for v4+v6 of same port

	for _, line := range strings.Split(string(out), "\n") {
		l, ok := parseListener(line)
		if !ok || isLoopback(l.addr) {
			continue
		}
		switch {
		case datastorePorts[l.port] != "":
			if seenDS[l.port] {
				continue
			}
			seenDS[l.port] = true
			findings = append(findings, exposedFinding(l, "ports.exposed-datastore",
				"Datastore reachable from the network: "+datastorePorts[l.port],
				"A database listening on a non-loopback address is reachable from every network this host is on. Datastores rarely need to accept remote connections directly; exposing one invites credential-stuffing and data theft.",
				model.SeverityHigh))
		case adminPorts[l.port] != "":
			if seenDS[l.port] {
				continue
			}
			seenDS[l.port] = true
			findings = append(findings, exposedFinding(l, "ports.exposed-admin",
				"Admin panel reachable from the network: "+adminPorts[l.port],
				"A management UI listening on a non-loopback address lets anyone who can reach this host attempt to log in and control your services. Bind it to localhost and reach it over an SSH tunnel or VPN.",
				model.SeverityHigh))
		default:
			if l.port == 22 { // SSH is expected to be reachable; not a finding here
				continue
			}
			if _, dup := generic[l.port]; !dup {
				generic[l.port] = l
			}
		}
	}

	// Generic non-loopback listeners are only worth flagging when there is
	// no host firewall acting as a backstop — otherwise every expected web
	// server would be noise. When there is no firewall, surface them once,
	// aggregated, at low severity.
	if len(generic) > 0 && !firewall.Active(ctx, env.Runner) {
		findings = append(findings, genericFinding(generic))
	}
	return findings, nil
}

func exposedFinding(l listener, id, title, desc string, sev model.Severity) model.Finding {
	opts := []model.FindingOption{
		// Attribute the finding to this specific listener so two different
		// exposed datastores (e.g. Redis and Postgres) get distinct Keys and
		// are each counted, rather than deduplicated to one by (source, id).
		model.WithService(listenerSubject(l)),
		model.WithDescription(desc),
		model.WithHowToFix(fmt.Sprintf("Bind %s to 127.0.0.1 instead of %s, or restrict access with a host firewall / VPN. If it must be remote, put it behind an authenticated reverse proxy.", portLabel(l), l.addr)),
		model.WithEvidence("port", strconv.Itoa(l.port)),
		model.WithEvidence("address", l.addr),
	}
	if l.proc != "" {
		opts = append(opts, model.WithEvidence("process", l.proc))
	}
	return model.NewFinding(id, title, sev, model.SourcePorts, model.RemediationReview, opts...)
}

// listenerSubject identifies a listener for the finding's Service field:
// the process name qualified by port when known (unique across same-named
// processes on different ports), else just the port.
func listenerSubject(l listener) string {
	if l.proc != "" {
		return fmt.Sprintf("%s:%d", l.proc, l.port)
	}
	return "port " + strconv.Itoa(l.port)
}

func genericFinding(generic map[int]listener) model.Finding {
	ports := make([]int, 0, len(generic))
	for p := range generic {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	parts := make([]string, len(ports))
	for i, p := range ports {
		if proc := generic[p].proc; proc != "" {
			parts[i] = fmt.Sprintf("%d (%s)", p, proc)
		} else {
			parts[i] = strconv.Itoa(p)
		}
	}
	list := strings.Join(parts, ", ")
	return model.NewFinding("ports.exposed", "Services exposed to the network with no firewall",
		model.SeverityLow, model.SourcePorts, model.RemediationManual,
		model.WithDescription("These services listen on a non-loopback address and no host firewall is active, so they are reachable from any network this host is on. Even if each is meant to be public, a firewall that denies inbound by default is your backstop when one is accidentally exposed."),
		model.WithHowToFix("Enable a host firewall that defaults to denying inbound traffic (allow SSH first), and bind any service that does not need to be public to 127.0.0.1. Exposed ports: "+list+"."),
		model.WithEvidence("ports", list),
	)
}

func portLabel(l listener) string {
	if l.proc != "" {
		return fmt.Sprintf("%s (port %d)", l.proc, l.port)
	}
	return "port " + strconv.Itoa(l.port)
}

// parseListener parses one `ss -H -tlnp` row into a listener. The local
// address:port is the 4th whitespace-separated field; the process column
// (from -p) is the last. A malformed row is skipped, never an error.
func parseListener(line string) (listener, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return listener{}, false
	}
	addr, portStr, ok := splitHostPort(fields[3])
	if !ok {
		return listener{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return listener{}, false
	}
	l := listener{addr: addr, port: port}
	if len(fields) >= 6 {
		l.proc = procName(fields[len(fields)-1])
	}
	return l, true
}

// splitHostPort splits a "host:port" where host may be a bracketed IPv6
// literal ("[::]:22") or a wildcard ("*:22"). Port is taken after the last
// colon so IPv6 addresses split correctly.
func splitHostPort(s string) (host, port string, ok bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 || i == len(s)-1 {
		return "", "", false
	}
	host = strings.Trim(s[:i], "[]")
	port = s[i+1:]
	return host, port, true
}

// isLoopback reports whether an address is a loopback / host-only bind that
// is not reachable from the network. Everything else — the 0.0.0.0/:: /*
// wildcards and specific LAN/public IPs — counts as exposed.
func isLoopback(addr string) bool {
	switch addr {
	case "127.0.0.1", "::1", "%lo":
		return true
	}
	return strings.HasPrefix(addr, "127.")
}

// procName extracts the program name from ss's process column, e.g.
// `users:(("redis-server",pid=999,fd=6))` -> "redis-server".
func procName(field string) string {
	i := strings.Index(field, `("`)
	if i < 0 {
		return ""
	}
	rest := field[i+2:]
	if j := strings.Index(rest, `"`); j >= 0 {
		return rest[:j]
	}
	return ""
}
