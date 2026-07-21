package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// defaultDaemonConfig is where the Docker daemon reads its options.
const defaultDaemonConfig = "/etc/docker/daemon.json"

// publishedPortRE matches the host side of a public port mapping in
// `docker ps` output: "0.0.0.0:6379->6379/tcp" and its IPv6 twin
// ":::6379->6379/tcp". A mapping published to 127.0.0.1 is deliberately not
// matched — it is reachable only from the host, so no firewall is being
// bypassed.
var publishedPortRE = regexp.MustCompile(`(?:0\.0\.0\.0|\[::\]|::):(\d+)->`)

// checkDockerBypass reports container ports that are reachable from the
// network even though ufw is active.
//
// Docker publishes a port by writing DNAT into nat/PREROUTING and an accept
// rule into the filter table's DOCKER chain. Both are traversed before ufw's
// rules in the INPUT chain, so `ufw deny 6379` has no effect on a container
// started with `-p 6379:6379`. The port is open to the internet while every
// tool the operator would think to check reports the firewall as active.
//
// This is the single most common real exposure on a self-hosted Docker host,
// and until this check existed hostveil actively rewarded it: an active ufw
// scored the firewall axis full marks, and the ports checker suppresses its
// generic exposure finding precisely because a firewall is up. A host with
// Postgres open to the world scored better than one with no firewall and
// nothing running.
//
// It reports nothing unless every condition holds, because a Critical finding
// that fires on a correctly configured host is worse than none:
//
//   - ufw is the active firewall. firewalld and plain nftables interact with
//     Docker differently and the ufw-docker remediation does not apply.
//   - at least one container publishes a port to a non-loopback address.
//   - the DOCKER-USER chain is empty, i.e. the operator has not already
//     installed the ufw-docker rules that close this.
//   - Docker is managing iptables at all. With "iptables": false in
//     daemon.json it adds no rules and ufw governs normally.
func checkDockerBypass(ctx context.Context, r platform.CommandRunner, daemonConfig string) ([]model.Finding, error) {
	if ok, _ := platform.DockerReachable(ctx, r); !ok {
		return nil, nil
	}
	if dockerIptablesDisabled(daemonConfig) {
		return nil, nil
	}

	published, err := publishedPorts(ctx, r)
	if err != nil || len(published) == 0 {
		return nil, err
	}

	// Whether the operator already closed this is the one thing we cannot
	// guess. Claiming the bypass without reading DOCKER-USER would accuse
	// every host that has already applied ufw-docker.
	mitigated, err := dockerUserChainFiltered(ctx, r)
	if err != nil {
		return nil, &check.PartialError{
			Reason: "cannot read the DOCKER-USER firewall chain — re-run with sudo to check whether published container ports bypass ufw",
		}
	}
	if mitigated {
		return nil, nil
	}

	list := describePorts(published)
	return []model.Finding{
		model.NewFinding("firewall.docker-bypass", "Container ports bypass the ufw firewall",
			model.SeverityCritical, model.SourceFirewall, model.RemediationManual,
			model.WithDescription("ufw is active, but Docker publishes container ports by writing its own rules ahead of ufw's. Traffic to a published port is accepted before ufw ever sees it, so `ufw deny` on these ports does nothing and they are reachable from any network this host is on — including the internet, on a VPS. The firewall looks correct in `ufw status` while these ports are open."),
			model.WithHowToFix("Either publish only to loopback (`-p 127.0.0.1:6379:6379`, or `ports: [\"127.0.0.1:6379:6379\"]` in Compose) and reach the service over an SSH tunnel or VPN, or install the ufw-docker rules in /etc/ufw/after.rules so the DOCKER-USER chain enforces your ufw policy. Published ports: "+list+"."),
			model.WithEvidence("published", list),
			model.WithEvidence("firewall", "ufw"),
		),
	}, nil
}

// dockerIptablesDisabled reports whether daemon.json turns off Docker's
// iptables management. An unreadable or absent file means the default, which
// is that Docker does manage iptables.
func dockerIptablesDisabled(path string) bool {
	data, err := os.ReadFile(path) //nolint:gosec // operator-controlled daemon config, read-only
	if err != nil {
		return false
	}
	var cfg struct {
		Iptables *bool `json:"iptables"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false
	}
	return cfg.Iptables != nil && !*cfg.Iptables
}

// publishedPort is one container port reachable from off-host.
type publishedPort struct {
	container string
	port      int
}

// publishedPorts lists container ports mapped to a non-loopback host address.
// A docker that cannot be listed is treated as nothing published rather than
// as an error: DockerReachable already gated this, so a failure here is a
// daemon that went away mid-scan, not a blind spot worth a finding.
func publishedPorts(ctx context.Context, r platform.CommandRunner) ([]publishedPort, error) {
	out, err := r.Run(ctx, "docker", "ps", "--format", "{{.Names}}\t{{.Ports}}")
	if err != nil {
		return nil, nil
	}

	seen := map[publishedPort]bool{}
	var ports []publishedPort
	for _, line := range strings.Split(string(out), "\n") {
		name, portSpec, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok {
			continue
		}
		for _, m := range publishedPortRE.FindAllStringSubmatch(portSpec, -1) {
			n, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			// A container publishing on both IPv4 and IPv6 lists the same
			// host port twice; it is one exposure.
			p := publishedPort{container: name, port: n}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	return ports, nil
}

// dockerUserChainFiltered reports whether DOCKER-USER carries any rule beyond
// the default, which is the chain declaration plus an unconditional RETURN.
// That chain is the documented place to enforce host policy on container
// traffic, so anything in it means the operator has addressed this.
func dockerUserChainFiltered(ctx context.Context, r platform.CommandRunner) (bool, error) {
	if !platform.Has(r, "iptables") {
		return false, fmt.Errorf("iptables not installed")
	}
	out, err := r.Run(ctx, "iptables", "-S", "DOCKER-USER")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		switch line = strings.TrimSpace(line); {
		case line == "", strings.HasPrefix(line, "-N "):
			continue // chain declaration
		case line == "-A DOCKER-USER -j RETURN":
			continue // Docker's own default; filters nothing
		default:
			return true, nil
		}
	}
	return false, nil
}

// describePorts renders the exposure list deterministically, so the finding
// and its evidence do not churn between scans and produce a spurious delta.
func describePorts(ports []publishedPort) string {
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].port != ports[j].port {
			return ports[i].port < ports[j].port
		}
		return ports[i].container < ports[j].container
	})
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d (%s)", p.port, p.container)
	}
	return strings.Join(parts, ", ")
}
