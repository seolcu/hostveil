package platform

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Listener is one TCP socket the host is listening on.
type Listener struct {
	Addr string // bind address as ss reported it, e.g. "0.0.0.0", "::1", "*"
	Port int
	Proc string // program name from ss's -p column; "" when unknown
}

// Loopback reports whether the bind address is a loopback / host-only bind
// that is not reachable from the network. Everything else — the 0.0.0.0, ::
// and * wildcards, and specific LAN or public IPs — counts as exposed. An
// IPv6 zone suffix (e.g. "::1%lo") is stripped before parsing.
func (l Listener) Loopback() bool {
	addr := l.Addr
	if i := strings.IndexByte(addr, '%'); i >= 0 {
		addr = addr[:i]
	}
	if ip := net.ParseIP(addr); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// Listeners lists the host's listening TCP sockets via `ss -tlnp`.
//
// Callers should gate on Has(r, "ss") first; a missing tool surfaces here as
// an ordinary error, and it is the caller's domain that decides whether that
// means skipped, degraded, or fatal.
func Listeners(ctx context.Context, r CommandRunner) ([]Listener, error) {
	// No `-H`: it is a relatively recent flag, so we skip the header row
	// ourselves (parseListener rejects it) and stay compatible with older
	// iproute2 rather than hard-erroring on an unknown flag.
	out, err := r.Run(ctx, "ss", "-tlnp")
	if err != nil {
		return nil, fmt.Errorf("listing listening sockets with ss: %w", err)
	}
	var ls []Listener
	for _, line := range strings.Split(string(out), "\n") {
		if l, ok := parseListener(line); ok {
			ls = append(ls, l)
		}
	}
	return ls, nil
}

// parseListener parses one `ss -tlnp` row into a Listener. The local
// address:port is the 4th whitespace-separated field; the process column
// (from -p) is the last. The header row and any malformed row are skipped,
// never an error.
func parseListener(line string) (Listener, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 || fields[0] == "State" { // "State" == header row
		return Listener{}, false
	}
	addr, portStr, ok := splitHostPort(fields[3])
	if !ok {
		return Listener{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return Listener{}, false
	}
	l := Listener{Addr: addr, Port: port}
	if len(fields) >= 6 {
		l.Proc = procName(fields[len(fields)-1])
	}
	return l, true
}

// splitHostPort splits ss's "host:port" local-address field. It defers to
// net.SplitHostPort, which correctly handles bracketed IPv6 literals
// ("[::]:22", "[fe80::1%lo]:6379") and wildcards ("*:22"). A field it cannot
// parse is rejected rather than turned into a malformed address.
func splitHostPort(s string) (host, port string, ok bool) {
	h, p, err := net.SplitHostPort(s)
	if err != nil || p == "" {
		return "", "", false
	}
	return h, p, true
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
