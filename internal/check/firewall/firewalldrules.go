package firewall

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/platform"
)

// FirewalldView is what firewalld does with inbound TCP to a port on the
// default zone, read the order firewalld applies it: rich rules with a
// negative priority, then the zone's ports and services, then rich rules at
// priority zero or above, then the zone's target.
//
// It exists because the ports checker read only ufw, so on a Fedora host
// whose firewalld refused a datastore's port it still reported the port
// reachable from the network — and told the operator to enable ufw.
//
// It answers "blocked" only when it understood everything that could open
// the port. A source-bound zone, another active zone, a forward or a source
// port, a rich rule it cannot read: any of those and the answer is "not
// known to be blocked", which keeps the finding. Being wrong in that
// direction costs a finding; the other direction hides an exposure.
type FirewalldView struct {
	// Active is whether firewalld is running and answered.
	Active bool
	// Zone is the default zone, the one a rule must go into to apply to
	// traffic arriving on the host's own interfaces.
	Zone string

	targetAccept bool
	open         []portRange
	rules        []richRule
	unclear      bool
}

type portRange struct{ lo, hi int }

func (p portRange) has(port int) bool { return port >= p.lo && port <= p.hi }

// richRule is a rich rule this reads: a port, a protocol, an action, a
// priority and optionally a family. Anything else is unclear.
type richRule struct {
	priority int
	ports    portRange
	accept   bool
}

// dockerZone is the zone Docker binds its bridges to. Its target accepts,
// but what arrives there is from containers on this host, not off it.
const dockerZone = "docker"

// ReadFirewalld reads the default zone. A firewalld that is not running, or
// will not answer, is a view that blocks nothing.
func ReadFirewalld(ctx context.Context, r platform.CommandRunner) FirewalldView {
	var v FirewalldView
	if !platform.Has(r, "firewall-cmd") {
		return v
	}
	if _, err := r.Run(ctx, "firewall-cmd", "--state"); err != nil {
		return v
	}
	zone, err := r.Run(ctx, "firewall-cmd", "--get-default-zone")
	if err != nil || strings.TrimSpace(string(zone)) == "" {
		return v
	}
	v.Zone = strings.TrimSpace(string(zone))
	all, err := r.Run(ctx, "firewall-cmd", "--zone="+v.Zone, "--list-all")
	if err != nil {
		return v
	}
	v.Active = true
	services := v.parseListAll(string(all))
	for _, s := range services {
		info, err := r.Run(ctx, "firewall-cmd", "--info-service="+s)
		if err != nil {
			v.unclear = true
			continue
		}
		v.parseService(string(info))
	}
	if active, err := r.Run(ctx, "firewall-cmd", "--get-active-zones"); err != nil {
		v.unclear = true
	} else if otherActiveZones(string(active), v.Zone) {
		v.unclear = true
	}
	return v
}

// Blocks reports whether inbound TCP to port is refused on the default zone,
// for both address families.
func (v FirewalldView) Blocks(port int) bool {
	if !v.Active || v.unclear {
		return false
	}
	rules := append([]richRule(nil), v.rules...)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].priority < rules[j].priority })
	for _, r := range rules {
		if r.priority < 0 && r.ports.has(port) {
			return !r.accept
		}
	}
	for _, p := range v.open {
		if p.has(port) {
			return false
		}
	}
	for _, r := range rules {
		if r.priority >= 0 && r.ports.has(port) {
			return !r.accept
		}
	}
	return !v.targetAccept
}

// parseListAll reads `firewall-cmd --zone=Z --list-all` and returns the
// services it names, whose ports are looked up separately.
func (v *FirewalldView) parseListAll(out string) []string {
	var services []string
	inRich := false
	for _, line := range strings.Split(out, "\n") {
		if inRich && strings.HasPrefix(line, "\t") {
			if r, ok := parseRichRule(strings.TrimSpace(line)); ok {
				v.rules = append(v.rules, r)
			} else {
				v.unclear = true
			}
			continue
		}
		inRich = false
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "target":
			v.targetAccept = strings.EqualFold(val, "ACCEPT")
		case "services":
			services = strings.Fields(val)
		case "ports":
			v.addPorts(val)
		case "protocols", "sources", "source-ports", "forward-ports":
			// Each of these can admit traffic to a port without naming it.
			if val != "" {
				v.unclear = true
			}
		case "rich rules":
			inRich = true
		}
	}
	return services
}

// parseService reads the ports of `firewall-cmd --info-service=S`. A service
// that includes others, or opens by protocol or source port, is unclear.
func (v *FirewalldView) parseService(out string) {
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "ports":
			v.addPorts(val)
		case "protocols", "source-ports", "includes":
			if val != "" {
				v.unclear = true
			}
		}
	}
}

// addPorts reads "22/tcp 8080-8090/tcp 53/udp", keeping TCP.
func (v *FirewalldView) addPorts(val string) {
	for _, f := range strings.Fields(val) {
		spec, proto, _ := strings.Cut(f, "/")
		if proto != "tcp" {
			continue
		}
		if p, ok := parsePortRange(spec); ok {
			v.open = append(v.open, p)
		} else {
			v.unclear = true
		}
	}
}

func parsePortRange(spec string) (portRange, bool) {
	lo, hi, isRange := strings.Cut(spec, "-")
	a, err := strconv.Atoi(lo)
	if err != nil {
		return portRange{}, false
	}
	if !isRange {
		return portRange{a, a}, true
	}
	b, err := strconv.Atoi(hi)
	if err != nil || b < a {
		return portRange{}, false
	}
	return portRange{a, b}, true
}

// parseRichRule reads the one shape of rich rule that decides a port by
// itself, as firewalld lists it:
//
//	rule priority="-100" port port="6379" protocol="tcp" reject
//	rule family="ipv4" port port="8080-8090" protocol="tcp" accept
//
// A family limits a rule to one of the two, and this answers for both, so a
// rule with one is read only when it accepts — the direction that can never
// make a port look more closed than it is. Anything with a source, a
// destination, a service, logging or a limit is not this shape.
func parseRichRule(rule string) (richRule, bool) {
	var r richRule
	fields := strings.Fields(rule)
	if len(fields) < 2 || fields[0] != "rule" {
		return r, false
	}
	family, port, proto := "", "", ""
	action := ""
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		k, val, hasVal := strings.Cut(f, "=")
		val = strings.Trim(val, `"`)
		switch {
		case hasVal && k == "priority":
			p, err := strconv.Atoi(val)
			if err != nil {
				return r, false
			}
			r.priority = p
		case hasVal && k == "family":
			family = val
		case f == "port":
		case hasVal && k == "port":
			port = val
		case hasVal && k == "protocol":
			proto = val
		case f == "accept" || f == "reject" || f == "drop":
			if action != "" || i != len(fields)-1 {
				return r, false
			}
			action = f
		default:
			return r, false
		}
	}
	if port == "" || proto != "tcp" || action == "" {
		return r, false
	}
	pr, ok := parsePortRange(port)
	if !ok {
		return r, false
	}
	r.ports, r.accept = pr, action == "accept"
	if family != "" && !r.accept {
		return r, false
	}
	return r, true
}

// otherActiveZones reports whether any zone other than def and Docker's has
// interfaces or sources bound to it. Traffic arriving there is decided by
// that zone, which this did not read.
func otherActiveZones(out, def string) bool {
	zone := ""
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			zone, _, _ = strings.Cut(strings.TrimSpace(line), " ")
			continue
		}
		if zone != def && zone != dockerZone {
			return true
		}
	}
	return false
}

// Shield is the running host firewall as the ports checker asks it about one
// exposed port: whether it already refuses the port, and which front end a
// rule closing it would go into.
type Shield struct {
	// Name is "ufw" or "firewalld" when one of them is running and readable,
	// and empty when neither is — the case where there is no rule to write.
	Name string
	// Zone is firewalld's default zone, where a rule must go.
	Zone string
	ufw  UFWView
	fwd  FirewalldView
}

// ReadShield asks ufw first and firewalld second, the order Probe does.
func ReadShield(ctx context.Context, r platform.CommandRunner) Shield {
	if u := ReadUFW(ctx, r); u.Active {
		return Shield{Name: "ufw", ufw: u}
	}
	if f := ReadFirewalld(ctx, r); f.Active {
		return Shield{Name: "firewalld", Zone: f.Zone, fwd: f}
	}
	return Shield{}
}

// Blocks reports whether the running firewall refuses inbound TCP to port.
func (s Shield) Blocks(port int) bool {
	switch s.Name {
	case "ufw":
		return s.ufw.Blocks(port)
	case "firewalld":
		return s.fwd.Blocks(port)
	}
	return false
}
