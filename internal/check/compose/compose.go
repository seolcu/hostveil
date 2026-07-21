// Package compose implements the Docker Compose static-audit checker —
// hostveil's crown jewel. It inspects each service in every discovered
// compose project for the misconfigurations most likely to get a
// self-hoster hacked, and emits plain-language findings.
package compose

import (
	"context"
	"sort"
	"strings"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
	"github.com/seolcu/hostveil/internal/secretkey"
)

// Checker audits discovered Docker Compose projects.
type Checker struct{}

// New returns a compose Checker.
func New() *Checker { return &Checker{} }

// Source identifies the compose domain.
func (*Checker) Source() model.Source { return model.SourceCompose }

// Available requires a reachable Docker daemon; without one there is nothing
// to audit. Probing the daemon rather than just the CLI turns an
// unreachable socket into a clean skip with an actionable reason, instead of
// a domain error reading "exit status 1".
func (*Checker) Available(ctx context.Context, env platform.Env) (bool, string) {
	if ok, reason := platform.DockerReachable(ctx, env.Runner); !ok {
		return false, reason + " — nothing to audit"
	}
	return true, ""
}

// Check audits every container on the host: those described by a compose
// file, and those started directly with `docker run`.
//
// Compose projects were the only thing this checker looked at, so a
// hand-started container was invisible to all fifteen rules. Since compose
// carries the largest single axis weight, that meant the most dangerous
// object on the box could be published to 0.0.0.0, privileged, and mounting
// the Docker socket while the axis scored it as if it were not there.
func (*Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	projects, err := compose.Discover(ctx, env.Runner)
	if err != nil {
		return nil, err
	}
	var findings []model.Finding
	for _, p := range projects {
		for _, name := range sortedServiceNames(p) {
			for _, fnd := range auditService(p.Services[name]) {
				// Record where the fix layer should apply the change.
				fnd.Metadata = mergeMeta(fnd.Metadata, map[string]string{
					"file":    p.File,
					"service": name,
				})
				findings = append(findings, fnd)
			}
		}
	}

	standalone, err := compose.DiscoverContainers(ctx, env.Runner)
	if err != nil {
		// The compose half of the domain was covered, so this is a partial
		// result, not a failure. Returning an ordinary error would discard
		// findings already gathered and exclude the axis entirely.
		return findings, &check.PartialError{
			Reason:  "cannot inspect containers started outside Compose — audited compose projects only",
			Covered: len(projects),
		}
	}
	for _, c := range standalone {
		findings = append(findings, auditContainer(c)...)
	}
	return findings, nil
}

// runtimeOnlyRules are the rules that mean the same thing for a container
// the daemon describes as they do for a service a compose file describes.
//
// Two of the fifteen are deliberately absent, both because the daemon's
// record cannot support the claim the rule would make:
//
//   - dr005 (hardcoded secret in the environment) — `docker inspect` reports
//     the resolved environment, which merges the image's own ENV defaults and
//     anything loaded from an env_file. Flagging that would accuse an
//     operator who did exactly the right thing, and tell them to do the thing
//     they already did.
//   - dr004 (loads secrets from an env_file) — a running container has no
//     env_file; the values were resolved when it was created and the daemon
//     keeps no record of where they came from.
//
// ds009 (runs as root) is kept, and is more accurate here than for compose:
// Config.User reflects the effective user including an image's baked-in
// USER, so a container reported as root really is running as root. The
// compose rule has to guess from the file alone, which is part of why its
// fix is declined.
var runtimeOnlyRules = []rule{
	rulePrivileged,
	ruleDockerSocket,
	ruleExposedDatastore,
	ruleExposedAdminPanel,
	ruleHostNetwork,
	ruleSensitiveHostMount,
	ruleDangerousCaps,
	ruleNoNewPrivileges,
	ruleRunsAsRoot,
	rulePortAllInterfaces,
	ruleNoRestart,
	ruleNoHealthcheck,
	ruleNoResourceLimits,
}

// auditContainer audits a container with no compose file behind it.
//
// Every finding is forced to Manual. The remediations these rules describe
// are all file edits — "bind the port to 127.0.0.1", "add security_opt" —
// and there is no file. Engine.classify takes whichever of the checker and
// the registry demands more human involvement, so declaring Manual here
// keeps the registry from offering a fix that would have nothing to edit.
// Without it a UI would show a fix button leading nowhere, which is exactly
// what the classify rule exists to prevent.
func auditContainer(c compose.Container) []model.Finding {
	var out []model.Finding
	for _, rule := range runtimeOnlyRules {
		f, ok := rule(c.Service)
		if !ok {
			continue
		}
		f.Remediation = model.RemediationManual
		f.HowToFix = "This container was started with `docker run`, not Compose, so there is no file to edit. " +
			"Recreate it with the corrected flag, or move it into a compose file where hostveil can fix it for you. " + f.HowToFix
		f.Evidence = mergeMeta(f.Evidence, map[string]string{"managed_by": "docker run"})
		out = append(out, f)
	}
	return out
}

func mergeMeta(base, add map[string]string) map[string]string {
	if base == nil {
		base = map[string]string{}
	}
	for k, v := range add {
		base[k] = v
	}
	return base
}

func sortedServiceNames(p compose.Project) []string {
	names := make([]string, 0, len(p.Services))
	for name := range p.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// auditService runs every rule against one service and returns its findings.
func auditService(s compose.Service) []model.Finding {
	var out []model.Finding
	for _, rule := range rules {
		if f, ok := rule(s); ok {
			out = append(out, f)
		}
	}
	return out
}

type rule func(compose.Service) (model.Finding, bool)

// rules is the ordered set of compose checks. Each returns a finding when
// the service trips it. IDs preserve the v2 ds/dr naming for continuity.
var rules = []rule{
	rulePrivileged,
	ruleDockerSocket,
	ruleExposedDatastore,
	ruleExposedAdminPanel,
	ruleHostNetwork,
	ruleSensitiveHostMount,
	ruleDangerousCaps,
	ruleNoNewPrivileges,
	ruleRunsAsRoot,
	rulePortAllInterfaces,
	ruleNoRestart,
	ruleNoHealthcheck,
	ruleNoResourceLimits,
	ruleInlineSecret,
	ruleEnvFile,
}

func f(id, title string, sev model.Severity, rem model.RemediationKind, svc string, opts ...model.FindingOption) model.Finding {
	base := []model.FindingOption{model.WithService(svc)}
	return model.NewFinding("compose."+id, title, sev, model.SourceCompose, rem, append(base, opts...)...)
}

func rulePrivileged(s compose.Service) (model.Finding, bool) {
	if !s.Privileged {
		return model.Finding{}, false
	}
	return f("ds001", "Container runs in privileged mode", model.SeverityHigh, model.RemediationReview, s.Name,
		model.WithDescription("Privileged mode gives the container almost all of the host's root capabilities. If it is compromised, the attacker effectively owns the host."),
		model.WithHowToFix("Remove `privileged: true`. If the container needs a specific capability, add just that one with `cap_add` instead."),
	), true
}

func ruleDockerSocket(s compose.Service) (model.Finding, bool) {
	for _, v := range s.Volumes {
		src := strings.TrimSuffix(v.Source, "/")
		if src == "/var/run/docker.sock" || src == "/run/docker.sock" {
			return f("ds016", "Docker socket mounted into container", model.SeverityCritical, model.RemediationReview, s.Name,
				model.WithDescription("Mounting the Docker socket lets the container create other containers and mount the host filesystem — it is equivalent to giving it root on the host, even read-only."),
				model.WithHowToFix("Remove the docker.sock volume. If the container genuinely needs Docker access, put a socket-proxy in front of it that allows only the specific API calls it needs."),
				model.WithEvidence("mount", v.Source),
			), true
		}
	}
	return model.Finding{}, false
}

var datastoreImages = map[string]bool{
	"redis": true, "mongo": true, "mongodb": true, "memcached": true,
	"elasticsearch": true, "couchdb": true, "etcd": true,
	"postgres": true, "mysql": true, "mariadb": true,
}

func ruleExposedDatastore(s compose.Service) (model.Finding, bool) {
	if !datastoreImages[imageBasename(s.Image)] {
		return model.Finding{}, false
	}
	for _, p := range s.Ports {
		if p.ExposedOnAllInterfaces() {
			return f("ds018", "Datastore exposed on all network interfaces", model.SeverityCritical, model.RemediationAuto, s.Name,
				model.WithDescription("A database or cache published on 0.0.0.0 is reachable from the internet if the host has a public IP. Many datastores have no authentication by default, so anyone can read, wipe, or plant data — a common route to full host takeover."),
				model.WithHowToFix("Bind the port to 127.0.0.1 (e.g. `127.0.0.1:6379:6379`) so only the host can reach it, and set a strong password. Do not expose datastores to the internet."),
				model.WithEvidence("image", s.Image),
				model.WithEvidence("port", p.HostPort),
			), true
		}
	}
	return model.Finding{}, false
}

var adminPanelImages = map[string]bool{
	"portainer": true, "portainer-ce": true, "portainer-ee": true,
	"phpmyadmin": true, "adminer": true, "mongo-express": true,
}

func ruleExposedAdminPanel(s compose.Service) (model.Finding, bool) {
	if !adminPanelImages[imageBasename(s.Image)] {
		return model.Finding{}, false
	}
	for _, p := range s.Ports {
		if p.ExposedOnAllInterfaces() {
			return f("ds019", "Admin panel exposed on all network interfaces", model.SeverityHigh, model.RemediationAuto, s.Name,
				model.WithDescription("Management UIs like this one are high-value targets. Exposed to the internet they invite credential-stuffing and known-CVE exploitation that can hand over your whole stack."),
				model.WithHowToFix("Bind the port to 127.0.0.1 and reach it over a VPN or SSH tunnel, or put it behind an authenticating reverse proxy."),
				model.WithEvidence("image", s.Image),
				// buildBindLoopback needs the host port; without it the fix
				// fails to build and classify silently demotes ds019 to Manual.
				model.WithEvidence("port", p.HostPort),
			), true
		}
	}
	return model.Finding{}, false
}

func ruleHostNetwork(s compose.Service) (model.Finding, bool) {
	if s.NetworkMode != "host" {
		return model.Finding{}, false
	}
	return f("dr001", "Container uses host network mode", model.SeverityHigh, model.RemediationReview, s.Name,
		model.WithDescription("`network_mode: host` removes network isolation: the container shares the host's interfaces and can bind any port, bypassing Docker's published-port controls and your firewall assumptions."),
		model.WithHowToFix("Remove `network_mode: host` and publish only the specific ports the service needs."),
	), true
}

var sensitiveHostPaths = []string{"/", "/etc", "/root", "/home", "/boot", "/proc", "/sys", "/run", "/var/run"}

func ruleSensitiveHostMount(s compose.Service) (model.Finding, bool) {
	for _, v := range s.Volumes {
		if !v.Bind || v.ReadOnly {
			continue
		}
		src := strings.TrimSuffix(v.Source, "/")
		if src == "" {
			src = "/"
		}
		if isSensitivePath(src) {
			return f("ds017", "Sensitive host path mounted read-write", model.SeverityHigh, model.RemediationReview, s.Name,
				model.WithDescription("A read-write bind mount of a sensitive host directory lets a compromised container tamper with host files — including adding SSH keys or cron jobs to gain persistence."),
				model.WithHowToFix("Mount only the exact subdirectory the service needs, and add `:ro` to make it read-only if the service does not write to it."),
				model.WithEvidence("mount", v.Source),
			), true
		}
	}
	return model.Finding{}, false
}

func isSensitivePath(src string) bool {
	for _, p := range sensitiveHostPaths {
		if src == p {
			return true
		}
	}
	return strings.HasSuffix(src, "/.ssh")
}

var dangerousCaps = map[string]bool{
	"SYS_ADMIN": true, "NET_ADMIN": true, "SYS_RAWIO": true,
	"SYS_PTRACE": true, "SYS_MODULE": true, "ALL": true,
}

func ruleDangerousCaps(s compose.Service) (model.Finding, bool) {
	for _, c := range s.CapAdd {
		if dangerousCaps[strings.ToUpper(strings.TrimPrefix(strings.ToUpper(c), "CAP_"))] {
			return f("ds005", "Container adds a dangerous Linux capability", model.SeverityHigh, model.RemediationReview, s.Name,
				model.WithDescription("Capabilities like SYS_ADMIN or SYS_MODULE let a container manipulate the kernel or host devices, which can be escalated to a full container escape."),
				model.WithHowToFix("Remove the capability from `cap_add` unless the service truly needs it. Prefer granting the narrowest capability that works."),
				model.WithEvidence("capability", c),
			), true
		}
	}
	return model.Finding{}, false
}

func ruleNoNewPrivileges(s compose.Service) (model.Finding, bool) {
	for _, o := range s.SecurityOpt {
		if strings.Contains(strings.ReplaceAll(o, " ", ""), "no-new-privileges:true") {
			return model.Finding{}, false
		}
	}
	return f("ds006", "Missing no-new-privileges hardening", model.SeverityMedium, model.RemediationAuto, s.Name,
		model.WithDescription("Without `no-new-privileges`, a process in the container can gain extra privileges through setuid binaries, widening the blast radius of a compromise."),
		model.WithHowToFix("Add `security_opt: [\"no-new-privileges:true\"]` to the service."),
	), true
}

func ruleRunsAsRoot(s compose.Service) (model.Finding, bool) {
	u := strings.TrimSpace(s.User)
	if u != "" && u != "0" && u != "root" && u != "0:0" && u != "root:root" {
		return model.Finding{}, false
	}
	return f("ds009", "Container runs as root", model.SeverityMedium, model.RemediationReview, s.Name,
		model.WithDescription("Running as root inside the container means a container escape lands as root on the host. Most services do not need root."),
		model.WithHowToFix("Set a non-root `user:` (e.g. a UID like `1000:1000`) if the image supports it."),
	), true
}

func rulePortAllInterfaces(s compose.Service) (model.Finding, bool) {
	// Skip services already flagged by the datastore/admin-panel rules to
	// avoid a duplicate, lower-severity finding for the same port.
	if datastoreImages[imageBasename(s.Image)] || adminPanelImages[imageBasename(s.Image)] {
		return model.Finding{}, false
	}
	for _, p := range s.Ports {
		if p.ExposedOnAllInterfaces() {
			return f("dr002", "Port published on all network interfaces", model.SeverityMedium, model.RemediationAuto, s.Name,
				model.WithDescription("A port bound to 0.0.0.0 is reachable from any network the host is on, including the internet if the host has a public IP. Only expose what needs to be public."),
				model.WithHowToFix("If the service is only used locally or behind a reverse proxy, bind the port to 127.0.0.1 (e.g. `127.0.0.1:8080:80`)."),
				model.WithEvidence("port", p.HostPort),
			), true
		}
	}
	return model.Finding{}, false
}

func ruleNoRestart(s compose.Service) (model.Finding, bool) {
	if r := strings.TrimSpace(s.Restart); r != "" && r != "no" {
		return model.Finding{}, false
	}
	return f("ds008", "No restart policy set", model.SeverityLow, model.RemediationAuto, s.Name,
		model.WithDescription("Without a restart policy the service stays down after a crash or reboot, which can silently take a security service (or your whole app) offline."),
		model.WithHowToFix("Add `restart: unless-stopped` so the service comes back automatically."),
	), true
}

func ruleNoHealthcheck(s compose.Service) (model.Finding, bool) {
	if s.Healthcheck != nil {
		return model.Finding{}, false
	}
	return f("ds012", "No healthcheck defined", model.SeverityLow, model.RemediationManual, s.Name,
		model.WithDescription("A healthcheck lets Docker detect a hung or broken container. Without one, a failed service can appear healthy while it is actually down."),
		model.WithHowToFix("Add a `healthcheck:` appropriate to the service (it depends on what the app exposes, so this cannot be filled in automatically)."),
	), true
}

func ruleNoResourceLimits(s compose.Service) (model.Finding, bool) {
	hasMem := s.MemLimit != "" || (s.Deploy != nil && s.Deploy.Resources.Limits.Memory != "")
	if hasMem {
		return model.Finding{}, false
	}
	return f("ds010", "No memory limit set", model.SeverityLow, model.RemediationReview, s.Name,
		model.WithDescription("Without a memory limit, one runaway or attacker-triggered container can exhaust host RAM and take every other service down with it."),
		model.WithHowToFix("Set a memory limit, e.g. `mem_limit: 512m` (Compose v2) or under `deploy.resources.limits.memory`."),
	), true
}

func ruleInlineSecret(s compose.Service) (model.Finding, bool) {
	for k, v := range s.Environment {
		// The heuristic is shared with the agent checker; keeping one copy
		// stops the two domains from drifting on what counts as a secret.
		if !secretkey.Matches(k) || !secretkey.LooksLiteral(v) {
			continue
		}
		return f("dr005", "Hardcoded secret in compose environment", model.SeverityHigh, model.RemediationReview, s.Name,
			model.WithDescription("A secret written directly in the compose file is stored in plaintext, easily leaked via backups or version control, and shared with anyone who can read the file."),
			model.WithHowToFix("Move the value to a `.env` file or Docker secret and reference it as `${VAR}` in the compose file."),
			model.WithEvidence("variable", k),
		), true
	}
	return model.Finding{}, false
}

func ruleEnvFile(s compose.Service) (model.Finding, bool) {
	if len(s.EnvFile) == 0 {
		return model.Finding{}, false
	}
	return f("dr004", "Service loads secrets from an env_file", model.SeverityLow, model.RemediationManual, s.Name,
		model.WithDescription("Env files often hold credentials. Make sure the file is not world-readable and is excluded from version control and backups that leave the host."),
		model.WithHowToFix("Verify the env_file has 0600 permissions and is listed in .gitignore. This one needs a human eye, so hostveil does not change it automatically."),
	), true
}

// imageBasename returns the lowercase image name without registry, path,
// or tag/digest (e.g. "docker.io/library/redis:7" -> "redis").
func imageBasename(image string) string {
	if image == "" {
		return ""
	}
	name := image
	if i := strings.IndexAny(name, "@:"); i >= 0 {
		// strip tag/digest, but keep a registry port (host:5000/img) intact:
		// only strip after the last path segment.
		if slash := strings.LastIndex(name, "/"); slash >= 0 {
			seg := name[slash+1:]
			if j := strings.IndexAny(seg, "@:"); j >= 0 {
				seg = seg[:j]
			}
			name = seg
		} else if j := strings.IndexByte(name, ':'); j >= 0 {
			name = name[:j]
		}
	}
	if slash := strings.LastIndex(name, "/"); slash >= 0 {
		name = name[slash+1:]
	}
	return strings.ToLower(name)
}
