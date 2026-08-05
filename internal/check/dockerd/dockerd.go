// Package dockerd audits the Docker daemon itself — the process that runs
// every container the compose and CVE domains have opinions about, and the
// one part of that stack hostveil could not see.
//
// The worst finding here is the worst finding hostveil has. A daemon
// listening on a TCP socket without TLS client verification is root on the
// host for anyone who can reach the port: no credentials, no exploit, one
// HTTP request that creates a container with / bind-mounted into it.
// Membership in the socket's group is the same authority from a local
// account, and unlike sudo it prompts for nothing and records nothing.
//
// # Three sources that disagree
//
// The hardest part of this domain is not the rules, it is deciding what to
// believe. Docker's configuration lives in three places that routinely
// contradict each other, so each rule names one of them and the package doc
// is where that reasoning lives.
//
//   - `docker info` is the truth for effective daemon state. It reports what
//     the daemon actually loaded, after the file and the flags were merged.
//     The three default-hardening rules (no-new-privileges, userns-remap,
//     live-restore) read only from here. Reading daemon.json for them would
//     report the operator's intention as though it were the machine's
//     behaviour — the file may have been edited since the last restart, and a
//     flag on the unit may be overriding it outright.
//
//   - daemon.json and the service unit's ExecStart are the truth for what
//     `docker info` does not report at all, and for where a human goes to
//     change it. `docker info` carries no listening addresses and no TLS
//     settings whatsoever, so the socket rules have nowhere else to read
//     from. Both are consulted and unioned: the packaged unit puts `-H fd://`
//     on ExecStart while an operator adding a TCP socket may reach for
//     either, and a checker that read only one would miss the other
//     configuration style completely.
//
//   - `ss` is the truth for what is actually listening. It turns a socket
//     finding from a reading of intent into an observed fact and supplies the
//     endpoint an operator can go and verify. It does not gate any finding:
//     it can see the door but not the lock, so it can neither confirm nor
//     deny the TLS half, and its absence is not lost ground.
//
// # What is deliberately not audited
//
// The logging driver and its rotation options. It is the one candidate rule
// that is availability rather than security — a full disk, not a way in — and
// more decisively it cannot be answered honestly from here: `docker info`
// reports the driver but never its log-opts, so `json-file` with a max-size
// is indistinguishable from `json-file` without one, and a per-service
// `logging:` block in a compose file overrides both. A rule blind to two of
// the three places the answer lives would fire on correctly configured hosts,
// which is the same objection the sysctl domain records for ip_forward.
package dockerd

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Checker reports weak Docker daemon configuration.
type Checker struct {
	// DaemonConfig is the daemon's JSON configuration file.
	DaemonConfig string
	// SocketPath is the unix socket the daemon listens on locally. Its mode
	// and owning group are both findings in their own right.
	SocketPath string
	// GroupPath and PasswdPath resolve the socket's owning group to the
	// accounts that hold it.
	GroupPath  string
	PasswdPath string
	// Unit is the systemd service whose ExecStart may carry daemon flags
	// that daemon.json never mentions.
	Unit string
}

// New returns a dockerd checker pointed at the real host paths.
func New() *Checker {
	return &Checker{
		DaemonConfig: "/etc/docker/daemon.json",
		SocketPath:   "/var/run/docker.sock",
		GroupPath:    "/etc/group",
		PasswdPath:   "/etc/passwd",
		Unit:         "docker.service",
	}
}

// Source identifies the dockerd domain.
func (*Checker) Source() model.Source { return model.SourceDockerd }

// Available requires a daemon that actually answers, not merely a `docker`
// binary on PATH. The distinction is the whole point: a client that cannot
// reach the socket reports no daemon configuration at all, and a domain that
// accepted that would score a perfect Docker-daemon axis on precisely the
// host whose daemon nobody could examine.
func (*Checker) Available(ctx context.Context, env platform.Env) (bool, string) {
	if ok, reason := platform.DockerReachable(ctx, env.Runner); !ok {
		return false, reason + " — the daemon's configuration cannot be read"
	}
	return true, ""
}

// Check gathers the daemon's configuration from every source that has part
// of it, then runs the rules that source supports.
//
// Coverage is counted in rules, not in sources, because that is the unit a
// user loses when something cannot be read: losing `docker info` costs the
// three default-hardening rules and leaves the four socket and group rules —
// including two of the three Criticals — genuinely answered. Reporting that
// as an outright error would exclude the axis *and discard those findings*,
// which is strictly worse than reporting it degraded.
func (c *Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	f := c.gather(ctx, env)

	var findings []model.Finding
	findings = append(findings, f.apiFindings()...)
	findings = append(findings, f.socketFindings()...)
	findings = append(findings, f.groupFindings()...)
	findings = append(findings, f.defaultsFindings()...)

	cov := f.coverage()
	return findings, cov.Err()
}

// facts is everything the checker managed to learn, plus what it could not.
// Each "known" flag is what separates "the answer is no" from "there was no
// answer" — the distinction this whole domain turns on.
type facts struct {
	cfg      config
	cfgKnown bool
	// cfgReason explains a config that could not be determined from either
	// daemon.json or the unit.
	cfgReason string

	info       info
	infoKnown  bool
	infoReason string

	sock       socket
	sockKnown  bool
	sockAbsent bool // reachable daemon, no local socket: DOCKER_HOST elsewhere
	sockReason string

	members       []member
	membersKnown  bool
	membersReason string

	// listeners corroborates the config. Never gates a finding.
	listeners []platform.Listener
}

// gather reads every source. Nothing here fails the scan: each source
// records what it learned or why it could not, and the rules decide what
// that costs.
func (c *Checker) gather(ctx context.Context, env platform.Env) *facts {
	f := &facts{}

	f.cfg, f.cfgKnown, f.cfgReason = c.readConfig(ctx, env)
	f.info, f.infoKnown, f.infoReason = readInfo(ctx, env.Runner)
	f.sock, f.sockKnown, f.sockAbsent, f.sockReason = c.readSocket()

	// The group is only resolvable once the socket has named it: the owning
	// group is whatever daemon.json's "group" key or the socket unit set, so
	// it is not necessarily called "docker" at all.
	if f.sockKnown {
		f.members, f.membersKnown, f.membersReason = c.readMembers(f.sock.gid)
	}

	// A missing or failing `ss` is not partial coverage. The configuration is
	// the authoritative statement of what the daemon was asked to do; the
	// listener only corroborates it and supplies an endpoint a human can go
	// and check. Losing a confidence booster is not losing ground.
	f.listeners, _ = platform.Listeners(ctx, env.Runner)

	return f
}

// rootless reports whether this is a rootless daemon, which changes what two
// rules mean rather than merely how bad they are.
func (f *facts) rootless() bool { return f.infoKnown && f.info.rootless }

// coverage translates what could not be read into the rule count it cost.
func (f *facts) coverage() check.Coverage {
	var cov check.Coverage

	// The two socket-configuration rules.
	if f.cfgKnown {
		cov.Covered(2)
	} else {
		cov.Missed(2, f.cfgReason)
	}

	// The three daemon-default rules.
	if f.infoKnown {
		cov.Covered(3)
	} else {
		cov.Missed(3, f.infoReason)
	}

	// The socket mode rule. A daemon reached over DOCKER_HOST with no local
	// socket has nothing to judge — that is not applicable, not uncovered,
	// so it leaves the denominator rather than lowering the fraction.
	if !f.sockAbsent {
		if f.sockKnown {
			cov.Covered(1)
		} else {
			cov.Missed(1, f.sockReason)
		}
	}

	// The group-membership rule. A rootless daemon's socket confers only that
	// user's own containers, so there is no root-equivalent group to audit.
	if !f.sockAbsent && !f.rootless() {
		switch {
		case f.membersKnown:
			cov.Covered(1)
		case f.sockKnown:
			cov.Missed(1, f.membersReason)
		default:
			// Already reported by the socket rule; the group could not be
			// resolved because the socket could not be, and saying so twice
			// tells the operator nothing new. The rule is still uncovered.
			cov.Missed(1, "")
		}
	}
	return cov
}

// apiFindings judges the daemon's network-facing sockets.
//
// The ordering is the argument: TLS with client verification is a correctly
// secured remote daemon and produces nothing at all. Anything less is graded
// by what an attacker who reaches the port can do, which is why the absence
// of TLS is Critical while its presence without verification is one rung
// below — the operator has demonstrably thought about the socket, and the
// remaining work is incremental rather than a rethink.
func (f *facts) apiFindings() []model.Finding {
	if !f.cfgKnown {
		return nil
	}
	exposed := f.cfg.exposedEndpoints()
	if len(exposed) == 0 {
		return nil
	}
	// Mutual TLS: reaching the port is not enough, a client certificate the
	// daemon's CA signed is required. This is the supported way to run a
	// remote daemon and it is not a finding.
	if f.cfg.tlsVerify {
		return nil
	}

	ev := []model.FindingOption{
		model.WithEvidence("endpoints", strings.Join(exposed, model.EvidenceSeparator)),
		model.WithEvidence("configured in", f.cfg.origin()),
	}
	if obs := f.observed(exposed); obs != "" {
		ev = append(ev, model.WithEvidence("listening", obs))
	}

	if f.cfg.tls {
		return []model.Finding{model.NewFinding(
			"dockerd.api-tls-unverified",
			"Docker API is encrypted but does not verify clients",
			model.SeverityExposed, model.SourceDockerd, model.RemediationManual,
			append(ev,
				model.WithDescription("The daemon serves its API over TLS but does not require a client certificate, so the traffic is confidential and the authorization is nonexistent. TLS without client verification authenticates the server to the client and nothing in the other direction: anyone who can reach the port still gets full control of the daemon, and full control of the daemon is root on this host."),
				model.WithHowToFix("Set `\"tlsverify\": true` alongside a `\"tlscacert\"` naming the CA that signed your client certificates, then restart the daemon. Docker treats `tlsverify` as the switch that turns encryption into authentication; without it the `tls` setting is only encryption."),
			)...,
		)}
	}

	// Rootless no longer changes the level, and that is the taxonomy working
	// rather than information being lost. Under Critical/High the split was
	// about blast radius — host root against one user's containers — which is
	// a guess at how bad, not a statement about how urgent. On the urgency
	// scale both answers are the same one: an unauthenticated API on a TCP
	// port is reachable now, by anyone who can route to it, with nothing to
	// break first. The difference it does make is still reported, in the
	// description and the evidence, where a reader can weigh it.
	desc := "The Docker daemon accepts API requests over TCP with no TLS client verification. The API has no authentication of its own, so anyone who can reach this port is root on this host: a single request can create a container with the host filesystem mounted inside it. This is not an escalation path that needs a vulnerability — it is the daemon working as documented, exposed to the network."
	if f.rootless() {
		desc = "The rootless Docker daemon accepts API requests over TCP with no TLS client verification. The API has no authentication of its own, so anyone who can reach this port gets full control of this user's containers and any file the user can read. Rootless keeps it from being immediate root on the host, which bounds the damage without making the port any harder to reach."
	}
	sev := model.SeverityExposed
	return []model.Finding{model.NewFinding(
		"dockerd.api-unauthenticated",
		"Docker API is exposed over TCP without authentication",
		sev, model.SourceDockerd, model.RemediationManual,
		append(ev,
			model.WithDescription(desc),
			model.WithHowToFix("Remove the `tcp://` endpoint and administer the daemon over SSH instead (`DOCKER_HOST=ssh://user@host`), which is the supported remote path and needs no new listening port. If the socket must stay, put it behind mutual TLS: `\"tlsverify\": true` with `\"tlscacert\"`, `\"tlscert\"`, and `\"tlskey\"`, and restrict the port at the firewall as well."),
		)...,
	)}
}

// observed renders the endpoints `ss` confirms are actually listening. It is
// evidence only — a daemon that was configured for a socket it failed to
// open is still misconfigured, so this never decides whether a finding
// exists.
func (f *facts) observed(exposed []string) string {
	want := map[int]bool{}
	for _, e := range exposed {
		if _, port, ok := splitEndpoint(e); ok {
			want[port] = true
		}
	}
	var seen []string
	for _, l := range f.listeners {
		if want[l.Port] && !l.Loopback() {
			seen = append(seen, fmt.Sprintf("%s:%d", l.Addr, l.Port))
		}
	}
	sort.Strings(seen)
	return strings.Join(seen, model.EvidenceSeparator)
}

// socketFindings judges the local unix socket's permissions.
//
// The trigger is the world-*write* bit and nothing else. Connecting to a unix
// socket requires write permission on it, so a world-readable socket grants
// nobody anything and flagging it would be noise on a host that is fine.
func (f *facts) socketFindings() []model.Finding {
	if !f.sockKnown || f.sock.perm&0o002 == 0 {
		return nil
	}
	return []model.Finding{model.NewFinding(
		"dockerd.socket-world-writable",
		"Docker socket is writable by every account on this host",
		model.SeverityExposed, model.SourceDockerd, model.RemediationManual,
		model.WithDescription("Every local account can connect to the Docker socket, and the Docker API grants whoever reaches it the ability to start a container with the host filesystem mounted inside. Any unprivileged user, and any process running as one — a web application, a compromised service account — can therefore become root on this host without a password and without an exploit."),
		model.WithHowToFix("Restore the socket to group-only access. The mode is set by systemd, not by the daemon, so a `chmod` is undone at the next restart: put `[Socket]` / `SocketMode=0660` in a drop-in under /etc/systemd/system/docker.socket.d/, then `systemctl daemon-reload && systemctl restart docker.socket`. Grant access by adding accounts to the socket's group rather than by widening the mode."),
		model.WithEvidence("path", f.sock.path),
		model.WithEvidence("mode", fmt.Sprintf("%04o", f.sock.perm)),
	)}
}

// groupFindings reports the accounts that hold the socket's group, which is
// root-equivalent authority on this host.
//
// This finding lives in the dockerd domain rather than in account hygiene for
// three reasons, in ascending order of weight. The account checker gates on a
// readable /etc/passwd and has no way to ask whether Docker is even here, so
// it would report root-equivalence on a host where the group is a leftover of
// a package that has been removed. Behind a reachable daemon the claim is
// exactly true, and a host with no Docker gets the axis excluded rather than
// scored. And the group is not necessarily named "docker" at all — it is
// whichever group owns the socket, which daemon.json's "group" key can set to
// anything — so answering correctly needs a daemon fact that account hygiene
// has no business knowing.
func (f *facts) groupFindings() []model.Finding {
	if !f.membersKnown || len(f.members) == 0 || f.rootless() {
		return nil
	}

	var names, service []string
	for _, m := range f.members {
		names = append(names, m.name)
		if m.system {
			service = append(service, m.name)
		}
	}

	// A human administrator in the docker group is the ordinary shape of a
	// self-hosted server, and a High that fires on almost every correctly-run
	// host teaches people to ignore the domain. It stays a finding because
	// most operators genuinely do not know the membership is equivalent to
	// passwordless sudo that leaves no audit record — but the severity says
	// "know this", not "you are breached".
	//
	// A service account is a different claim. Nobody deliberately grants a CI
	// runner or a monitoring agent the ability to become root, and a
	// credential that never logs in is one nobody is watching.
	sev, extra := model.SeverityWeak, ""
	if len(service) > 0 {
		sev = model.SeverityExposed
		extra = fmt.Sprintf(" Among them %s %s no interactive login, so %s a credential that can become root and that nobody is watching.",
			plural(len(service), "is", "are"), joinNames(service),
			plural(len(service), "it is", "they are"))
	}

	return []model.Finding{model.NewFinding(
		"dockerd.group-members",
		fmt.Sprintf("%s can control the Docker daemon", plural(len(names), "One account", fmt.Sprintf("%d accounts", len(names)))),
		sev, model.SourceDockerd, model.RemediationManual,
		model.WithDescription(fmt.Sprintf("Membership in the %q group is root on this host. Anyone in it can start a container that mounts / and read or write any file, with no password prompt, no sudoers entry, and no entry in the sudo log. It is a privilege grant that looks like a convenience setting.%s", f.sock.group, extra)),
		model.WithHowToFix(fmt.Sprintf("Remove any account that does not need to administer containers: `gpasswd -d <user> %s`. For accounts that do, consider rootless Docker, which gives them a daemon of their own with no path to host root. Do not remove the account you are currently administering this host with until you have confirmed another route in.", f.sock.group)),
		model.WithEvidence("group", f.sock.group),
		model.WithEvidence("members", strings.Join(names, model.EvidenceSeparator)),
	)}
}

// defaultsFindings covers the daemon-wide defaults that harden every
// container ever started on this host. All three are read from `docker info`
// because all three are questions about the running daemon.
func (f *facts) defaultsFindings() []model.Finding {
	if !f.infoKnown {
		return nil
	}
	var out []model.Finding

	if !f.info.noNewPrivileges {
		out = append(out, model.NewFinding(
			"dockerd.no-new-privileges",
			"Containers can gain privileges through setuid binaries",
			model.SeverityWeak, model.SourceDockerd, model.RemediationManual,
			model.WithDescription("The daemon does not apply no-new-privileges by default, so a process inside a container can still gain privileges by executing a setuid binary. That is the step that turns a foothold in an application container into root inside that container, and root inside a container is the starting point for every escape technique that follows."),
			model.WithHowToFix("Add `\"no-new-privileges\": true` to /etc/docker/daemon.json and restart the daemon. It becomes the default for every container; a service that genuinely needs setuid escalation can still opt out with `security_opt: [\"no-new-privileges:false\"]`."),
			model.WithEvidence("security options", f.info.securityOptions()),
		))
	}

	if !f.info.usernsRemap && !f.info.rootless {
		out = append(out, model.NewFinding(
			"dockerd.userns-remap",
			"Container root is host root",
			model.SeverityHardening, model.SourceDockerd, model.RemediationManual,
			model.WithDescription("User-namespace remapping is not enabled, so uid 0 inside a container is uid 0 on the host. Any container escape, any bind mount the operator did not think through, and any misconfigured volume therefore lands with real root privileges rather than with an unprivileged subordinate uid."),
			model.WithHowToFix("Set `\"userns-remap\": \"default\"` in /etc/docker/daemon.json and restart the daemon. Weigh it first: remapping changes the ownership of every bind mount, and containers using `--privileged`, host networking, or host PID cannot use it — which is why this is a Low and not an instruction."),
			model.WithEvidence("security options", f.info.securityOptions()),
		))
	}

	// Swarm mode does not support live restore, so on a swarm node this is
	// not a setting the operator declined — it is one Docker refuses. Flagging
	// it there would be a guaranteed false positive.
	if !f.info.liveRestore && !f.info.swarmActive {
		out = append(out, model.NewFinding(
			"dockerd.live-restore",
			"Restarting the daemon stops every container",
			model.SeverityHardening, model.SourceDockerd, model.RemediationManual,
			model.WithDescription("Without live-restore, containers do not survive a daemon restart. The security cost is indirect and worth stating as such: it makes upgrading Docker an outage, so daemon updates get deferred, and a deferred daemon update is an unpatched daemon holding root on this host."),
			model.WithHowToFix("Add `\"live-restore\": true` to /etc/docker/daemon.json. Unlike the other daemon defaults this one is picked up by `systemctl reload docker`, so enabling it does not itself require an outage. It is unsupported in swarm mode."),
			model.WithEvidence("live restore", "disabled"),
		))
	}
	return out
}

// plural picks between a singular and a plural form. The findings here count
// accounts, and "1 accounts can control the Docker daemon" is the kind of
// detail that makes a reader trust the rest of the report less.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// joinNames renders a list of accounts as English prose.
func joinNames(names []string) string {
	switch len(names) {
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	default:
		return strings.Join(names[:len(names)-1], ", ") + ", and " + names[len(names)-1]
	}
}
