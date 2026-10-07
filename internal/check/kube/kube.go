// Package kube audits a single-node Kubernetes host: k3s, and k0s.
//
// Not a cluster manager. The homelab pattern this is for is one box running
// one node, and the question is the one every other domain asks — what on
// this host would let someone in, or let a foothold become more — scoped to
// what a single-host audit can actually see: the credentials the
// distribution writes to disk, and the flags it starts the API server and
// kubelet with. What runs inside the cluster (RBAC, pod security, network
// policy) is the cluster's own business and needs a different tool.
//
// # Reading the effective configuration
//
// k3s takes its settings from three places and the last one wins:
// /etc/rancher/k3s/config.yaml, then config.yaml.d/*.yaml in name order, then
// the command line — which is the unit's ExecStart, plus the K3S_* variables
// the install script writes to k3s.service.env. Reading only the file would
// miss `curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE=644 sh -`, the
// line nearly every tutorial copies, so the command line is read the way the
// dockerd domain reads its daemon's: through `systemctl show`, trusting it
// only when LoadState says the unit was actually loaded.
package kube

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Checker reports weaknesses in a k3s or k0s node's own configuration.
type Checker struct {
	// Root prefixes every path read; "" means the real host.
	Root string
}

// New returns a checker reading the host's own files.
func New() *Checker { return &Checker{} }

// Source identifies the Kubernetes domain.
func (*Checker) Source() model.Source { return model.SourceKube }

func (c *Checker) path(p string) string {
	if c.Root == "" {
		return p
	}
	return filepath.Join(c.Root, p)
}

func (c *Checker) isDir(p string) bool {
	fi, err := os.Stat(c.path(p))
	return err == nil && fi.IsDir()
}

const (
	k3sEtc     = "/etc/rancher/k3s"
	k3sServer  = "/var/lib/rancher/k3s/server"
	k0sEtc     = "/etc/k0s"
	k0sData    = "/var/lib/k0s"
	k3sEnvFile = "/etc/systemd/system/k3s.service.env"
	k3sOpenRC  = "/etc/init.d/k3s"
	// k3sOpenRCEnv is where the installer keeps the K3S_* variables on a
	// host without systemd.
	k3sOpenRCEnv = "/etc/rancher/k3s/k3s.env"
)

// Available requires a k3s or k0s installation. Neither exists on macOS, so
// the ordinary answer is already the right one there and the domain is not
// gated on platform.AuditableOS.
func (c *Checker) Available(context.Context, platform.Env) (bool, string) {
	if c.isDir(k3sEtc) || c.isDir(k0sEtc) || c.isDir(k0sData) {
		return true, ""
	}
	return false, "no single-node Kubernetes found — no k3s (" + k3sEtc + ") or k0s (" + k0sEtc + ")"
}

// Check audits whichever distributions are installed.
func (c *Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	var cov check.Coverage
	var out []model.Finding
	if c.isDir(k3sEtc) {
		out = append(out, c.auditK3s(ctx, env, &cov)...)
	}
	if c.isDir(k0sEtc) || c.isDir(k0sData) {
		out = append(out, c.auditK0s(ctx, env, &cov)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, cov.Err()
}

// --- k3s ---------------------------------------------------------------------

// k3sConfig is the effective value of the few settings this domain reads, and
// where each came from.
type k3sConfig struct {
	role string // "server", "agent", or "" when the command line was not read

	kubeconfig, kubeconfigFrom string
	mode, modeFrom             string

	apiserverArgs, kubeletArgs []string
	argsFrom                   map[string]string

	secretsEncryption     bool
	secretsEncryptionFrom string

	// cmdlineFrom names where the command line was read: the systemd unit
	// or the openrc script, which is also how k3s is restarted.
	cmdlineFrom string
}

func (c *Checker) auditK3s(ctx context.Context, env platform.Env, cov *check.Coverage) []model.Finding {
	cfg, gaps := c.k3sEffective(ctx, env)
	for _, g := range gaps {
		cov.Missed(0, g)
	}
	cov.Covered(1)

	var out []model.Finding
	kubeconfig := cfg.kubeconfig
	if kubeconfig == "" {
		kubeconfig = k3sEtc + "/k3s.yaml"
	}
	if f, gap := c.readableCredential(kubeconfig, kubeconfigFinding(cfg)); gap != "" {
		cov.Missed(0, gap)
	} else if f != nil {
		out = append(out, *f)
	}

	server := cfg.role == "server" || (cfg.role == "" && c.isDir(k3sServer))
	if !server {
		return out
	}
	for _, name := range []string{"token", "node-token"} {
		p := k3sServer + "/" + name
		if f, gap := c.readableCredential(p, tokenFinding(p)); gap != "" {
			cov.Missed(0, gap)
		} else if f != nil {
			out = append(out, *f)
		}
	}
	if f := anonymousFinding("k3s", cfg.apiserverArgs, cfg.kubeletArgs, cfg.argsFrom); f != nil {
		k3sFixable(f, cfg, "kube-apiserver-arg", "kubelet-arg")
		out = append(out, *f)
	}
	// k3s answers whether Secrets are encrypted, and its answer wins over the
	// configuration's. The setting alone does not turn encryption on for a
	// cluster that already exists — that takes `k3s secrets-encrypt enable`
	// and a key rotation — so a host carrying `secrets-encryption: true` can
	// still store every Secret in plain base64, and reading the setting
	// reported it fixed. That is what 3.33.0's fix left behind, and what
	// scripts/e2e/individual.sh found on a real cluster. Without an answer
	// (no k3s binary, not root, server down) the configuration is all there is.
	encrypted, known := k3sSecretsEncrypted(ctx, env.Runner)
	if !known {
		encrypted = cfg.secretsEncryption
	}
	if !encrypted && (known || cfg.role != "") {
		// From the configuration, only judged when the command line was read:
		// the flag can be set there alone, and "not in any file" is not "not set".
		f := secretsFinding()
		k3sFixable(&f, cfg, "secrets-encryption")
		out = append(out, f)
	}
	return out
}

// k3sEffective resolves the settings in k3s's own order: config.yaml, the
// drop-ins in name order, the environment file, then the command line.
func (c *Checker) k3sEffective(ctx context.Context, env platform.Env) (k3sConfig, []string) {
	cfg := k3sConfig{argsFrom: map[string]string{}}
	var gaps []string

	files := []string{k3sEtc + "/config.yaml"}
	drops, _ := filepath.Glob(c.path(k3sEtc + "/config.yaml.d/*.yaml"))
	sort.Strings(drops)
	for _, d := range drops {
		files = append(files, strings.TrimPrefix(d, strings.TrimSuffix(c.Root, "/")))
	}
	for _, f := range files {
		b, err := platform.ReadFileBounded(c.path(f), 1<<20)
		if err != nil {
			if !os.IsNotExist(err) {
				gaps = append(gaps, "could not read "+f+" — the k3s settings in it were not audited")
			}
			continue
		}
		var m map[string]any
		if err := yaml.Unmarshal(b, &m); err != nil {
			gaps = append(gaps, "could not parse "+f+" — the k3s settings in it were not audited")
			continue
		}
		cfg.apply(m, f)
	}

	for _, envFile := range []string{k3sEnvFile, k3sOpenRCEnv} {
		b, err := platform.ReadFileBounded(c.path(envFile), 1<<20)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"'`)
			switch k {
			case "K3S_KUBECONFIG_MODE":
				cfg.mode, cfg.modeFrom = v, envFile
			case "K3S_KUBECONFIG_OUTPUT":
				cfg.kubeconfig, cfg.kubeconfigFrom = v, envFile
			}
		}
	}

	argv, from, gap := c.k3sCommandLine(ctx, env)
	if gap != "" {
		gaps = append(gaps, gap)
	} else {
		cfg.cmdlineFrom = from
		cfg.applyFlags(argv, from)
	}
	return cfg, gaps
}

// apply folds one config file into the effective settings. A key with a `+`
// suffix appends to what earlier files set; without it, it replaces.
func (cfg *k3sConfig) apply(m map[string]any, from string) {
	for rawKey, v := range m {
		key, appendTo := strings.CutSuffix(rawKey, "+")
		switch key {
		case "write-kubeconfig-mode":
			cfg.mode, cfg.modeFrom = scalar(v), from
		case "write-kubeconfig", "output-kubeconfig":
			cfg.kubeconfig, cfg.kubeconfigFrom = scalar(v), from
		case "secrets-encryption":
			cfg.secretsEncryption, cfg.secretsEncryptionFrom = truthy(scalar(v)), from
		case "kube-apiserver-arg":
			cfg.apiserverArgs = merge(cfg.apiserverArgs, list(v), appendTo)
			cfg.argsFrom["kube-apiserver-arg"] = from
		case "kubelet-arg":
			cfg.kubeletArgs = merge(cfg.kubeletArgs, list(v), appendTo)
			cfg.argsFrom["kubelet-arg"] = from
		}
	}
}

// applyFlags folds the command line in. Flags win over every file, and a
// repeatable flag given on the command line replaces the files' list rather
// than adding to it — upstream's own rule.
func (cfg *k3sConfig) applyFlags(argv []string, from string) {
	var apiserver, kubelet []string
	sawAPI, sawKubelet := false, false
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if i <= 1 && (a == "server" || a == "agent") {
			cfg.role = a
			continue
		}
		if !strings.HasPrefix(a, "--") {
			continue
		}
		name, val, attached := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		value := func() string {
			if attached {
				return val
			}
			if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "--") {
				i++
				return argv[i]
			}
			return ""
		}
		switch name {
		case "write-kubeconfig-mode":
			cfg.mode, cfg.modeFrom = value(), from
		case "write-kubeconfig", "output-kubeconfig", "o":
			cfg.kubeconfig, cfg.kubeconfigFrom = value(), from
		case "secrets-encryption":
			if attached {
				cfg.secretsEncryption = truthy(val)
			} else {
				cfg.secretsEncryption = true
			}
			cfg.secretsEncryptionFrom = from
		case "kube-apiserver-arg":
			apiserver, sawAPI = append(apiserver, value()), true
		case "kubelet-arg":
			kubelet, sawKubelet = append(kubelet, value()), true
		}
	}
	if sawAPI {
		cfg.apiserverArgs, cfg.argsFrom["kube-apiserver-arg"] = apiserver, from
	}
	if sawKubelet {
		cfg.kubeletArgs, cfg.argsFrom["kubelet-arg"] = kubelet, from
	}
}

// k3sCommandLine returns the argv k3s is started with: the systemd unit's
// ExecStart, or the openrc script's command_args on a host without systemd.
func (c *Checker) k3sCommandLine(ctx context.Context, env platform.Env) ([]string, string, string) {
	if platform.Has(env.Runner, "systemctl") {
		out, err := env.Runner.Run(ctx, "systemctl", "show", "k3s.service", "--property=LoadState,ExecStart", "--no-pager")
		if err == nil && platform.ShowProperty(string(out), "LoadState") == "loaded" {
			var argv []string
			for _, a := range platform.ExecStartArgv(string(out)) {
				argv = append(argv, strings.Fields(a)...)
			}
			return trimBinary(argv), "the k3s.service command line", ""
		}
	}
	if b, err := platform.ReadFileBounded(c.path(k3sOpenRC), 1<<20); err == nil {
		if argv, ok := openrcArgs(string(b)); ok {
			return argv, k3sOpenRC, ""
		}
	}
	return nil, "", "neither a loaded k3s.service nor " + k3sOpenRC + " says how k3s is started — flags given on its command line were not audited"
}

// openrcArgs reads command_args out of the openrc script the k3s installer
// writes. It spans several lines — one single-quoted argument per line,
// joined by backslash-newline — and ends in a redirect to the log file:
//
//	command_args="server \
//		'--kube-apiserver-arg=anonymous-auth=true' \
//	    >>/var/log/k3s.log 2>&1"
//
// Reading the first line alone saw a bare `server` and every flag after it
// went unaudited, which is how this was first written; the fixture in the
// tests is the installer's real output.
func openrcArgs(script string) ([]string, bool) {
	i := strings.Index(script, "command_args=\"")
	if i < 0 {
		return nil, false
	}
	rest := script[i+len("command_args=\""):]
	end := strings.Index(rest, "\"")
	if end < 0 {
		return nil, false
	}
	body := strings.ReplaceAll(rest[:end], "\\\n", " ")
	var argv []string
	for _, w := range shellWords(body) {
		if strings.HasPrefix(w, ">") || strings.HasPrefix(w, "2>") {
			break
		}
		argv = append(argv, w)
	}
	return argv, true
}

// shellWords splits on whitespace outside single quotes — the only quoting
// the installer uses, so a value with a space in it stays one argument.
func shellWords(s string) []string {
	var out []string
	var b strings.Builder
	in, quoted := false, false
	for _, r := range s {
		switch {
		case r == '\'':
			quoted = !quoted
			in = true
		case !quoted && (r == ' ' || r == '\t' || r == '\n'):
			if in {
				out = append(out, b.String())
				b.Reset()
				in = false
			}
		default:
			b.WriteRune(r)
			in = true
		}
	}
	if in {
		out = append(out, b.String())
	}
	return out
}

// trimBinary drops the program path so argv[0] is the subcommand.
func trimBinary(argv []string) []string {
	if len(argv) > 0 && !strings.HasPrefix(argv[0], "-") && argv[0] != "server" && argv[0] != "agent" {
		return argv[1:]
	}
	return argv
}

// --- k0s ---------------------------------------------------------------------

const (
	k0sAdminConf = k0sData + "/pki/admin.conf"
	k0sConfig    = k0sEtc + "/k0s.yaml"
)

// auditK0s reads the admin kubeconfig k0s writes and the API server arguments
// in its configuration. k0s runs with built-in defaults when it has no
// configuration file, which is a complete answer, not a gap.
func (c *Checker) auditK0s(_ context.Context, _ platform.Env, cov *check.Coverage) []model.Finding {
	var out []model.Finding
	cov.Covered(1)
	if f, gap := c.readableCredential(k0sAdminConf, k0sKubeconfigFinding()); gap != "" {
		cov.Missed(0, gap)
	} else if f != nil {
		out = append(out, *f)
	}

	b, err := platform.ReadFileBounded(c.path(k0sConfig), 1<<20)
	switch {
	case os.IsNotExist(err):
		return out
	case err != nil:
		cov.Missed(0, "could not read "+k0sConfig+" — the API server's arguments were not audited")
		return out
	}
	var doc struct {
		Spec struct {
			API struct {
				ExtraArgs map[string]any `yaml:"extraArgs"`
			} `yaml:"api"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		cov.Missed(0, "could not parse "+k0sConfig+" — the API server's arguments were not audited")
		return out
	}
	var args []string
	for k, v := range doc.Spec.API.ExtraArgs {
		args = append(args, k+"="+scalar(v))
	}
	if f := anonymousFinding("k0s", args, nil, map[string]string{"kube-apiserver-arg": k0sConfig + " (spec.api.extraArgs)"}); f != nil {
		f.WhyNoFix = "k0s takes this from spec.api.extraArgs in its own cluster config, which Hostveil does not edit."
		out = append(out, *f)
	}
	return out
}

// --- shared ------------------------------------------------------------------

// readableCredential reports a credential file anyone on the host can read.
//
// World-readable only. A group bit is how k3s's write-kubeconfig-group and
// k0s's own 0640 hand the file to an administrators' group on purpose, the
// same trade the docker group is; reading everyone else in is not a choice
// anybody makes on purpose. Lstat, so a symlink is judged as the link it is
// rather than as whatever it points at.
func (c *Checker) readableCredential(p string, build func(os.FileMode) model.Finding) (*model.Finding, string) {
	fi, err := os.Lstat(c.path(p))
	switch {
	case os.IsNotExist(err):
		return nil, ""
	case err != nil:
		return nil, "could not stat " + p + " — whether it is readable by every account was not audited; re-run with sudo"
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o004 == 0 {
		return nil, ""
	}
	f := build(fi.Mode().Perm())
	f.Evidence["path"] = p
	return &f, ""
}

func kubeconfigFinding(cfg k3sConfig) func(os.FileMode) model.Finding {
	return func(mode os.FileMode) model.Finding {
		fix := "Set `write-kubeconfig-mode: \"0600\"` in /etc/rancher/k3s/config.yaml (or `write-kubeconfig-group` to hand it to an administrators' group), and restart k3s — it rewrites the file at start, so a chmod alone lasts until the next restart. "
		if cfg.modeFrom != "" && cfg.modeFrom != k3sEtc+"/config.yaml" {
			fix = "The mode is set in " + cfg.modeFrom + " (`" + cfg.mode + "`), which wins over config.yaml — change it there to `0600`, then restart k3s. It rewrites the file at start, so a chmod alone lasts until the next restart. "
		}
		fix += "Anyone who needs kubectl should get their own kubeconfig rather than a copy of this one."
		opts := []model.FindingOption{
			model.WithDescription("The admin kubeconfig k3s writes is readable by every account on this host. It holds cluster-admin credentials, so any local user — or any service running as one — can do anything in the cluster, including run a privileged pod that mounts the host's filesystem, which is root on this machine. `--write-kubeconfig-mode 644` is in most k3s tutorials because it makes kubectl work without sudo."),
			model.WithHowToFix(fix),
			model.WithEvidence("mode", "0"+strconvOct(mode)),
		}
		if cfg.modeFrom != "" {
			opts = append(opts, model.WithEvidence("set-in", cfg.modeFrom))
		}
		return model.NewFinding("kube.kubeconfig-readable",
			"The cluster-admin kubeconfig is readable by every account",
			model.SeverityMedium, model.SourceKube, model.RemediationReview, opts...)
	}
}

func k0sKubeconfigFinding() func(os.FileMode) model.Finding {
	return func(mode os.FileMode) model.Finding {
		return model.NewFinding("kube.kubeconfig-readable",
			"The cluster-admin kubeconfig is readable by every account",
			model.SeverityMedium, model.SourceKube, model.RemediationReview,
			model.WithDescription("k0s's admin kubeconfig is readable by every account on this host. It holds cluster-admin credentials, so any local user can do anything in the cluster, including run a privileged pod that mounts the host's filesystem — root on this machine. k0s writes it 0640 itself, so this was loosened after the fact."),
			model.WithHowToFix("`chmod 0640 "+k0sAdminConf+"`, and give anyone who needs kubectl a kubeconfig of their own (`k0s kubeconfig create <user>`) rather than a copy of this one."),
			model.WithEvidence("mode", "0"+strconvOct(mode)),
		)
	}
}

func tokenFinding(p string) func(os.FileMode) model.Finding {
	return func(mode os.FileMode) model.Finding {
		return model.NewFinding("kube.token-readable",
			"The k3s join token is readable by every account",
			model.SeverityMedium, model.SourceKube, model.RemediationReview,
			model.WithDescription("The token that lets a machine join this cluster is readable by every account on the host. A node that joins is trusted with the workloads scheduled onto it and the secrets they mount, and a server token joins as another control-plane node — so a local user can hand the cluster to a machine of their choosing."),
			model.WithHowToFix("`chmod 0600 "+p+"`, then rotate the token (`k3s token rotate`) since it has been readable: anything that copied it can still use it."),
			model.WithEvidence("mode", "0"+strconvOct(mode)),
		)
	}
}

// anonymousFinding reports anonymous-auth turned on explicitly. Both
// distributions default it off for the API server, so only an explicit true
// is a finding — and it is Medium, not High: anonymous requests are still
// authorised by RBAC, so what they reach is whatever someone bound to
// system:anonymous or system:unauthenticated, which is the second mistake
// this one waits for.
func anonymousFinding(dist string, apiserver, kubelet []string, from map[string]string) *model.Finding {
	var where []string
	if hasArg(apiserver, "anonymous-auth", "true") {
		where = append(where, "kube-apiserver-arg in "+from["kube-apiserver-arg"])
	}
	if hasArg(kubelet, "anonymous-auth", "true") {
		where = append(where, "kubelet-arg in "+from["kubelet-arg"])
	}
	if len(where) == 0 {
		return nil
	}
	f := model.NewFinding("kube.anonymous-auth",
		"Kubernetes accepts unauthenticated requests",
		model.SeverityMedium, model.SourceKube, model.RemediationManual,
		model.WithDescription("`anonymous-auth=true` is set ("+strings.Join(where, "; ")+"), so requests with no credential at all are accepted as the system:anonymous user instead of being refused. "+
			"What they can do is then decided by RBAC alone, so a single binding that grants system:anonymous or system:unauthenticated anything — often added while debugging and never removed — is the whole cluster to anyone who can reach the port. "+dist+" turns this off by default."),
		model.WithHowToFix("Remove the `anonymous-auth=true` argument and restart "+dist+". Health checks that need unauthenticated access are served by the /livez, /readyz and /healthz endpoints, which remain reachable without it."),
		model.WithEvidence("set-in", strings.Join(where, "; ")),
	)
	return &f
}

// k3sDropInDir is where a hostveil drop-in goes: read after config.yaml and
// in name order with the others, so a 99- name is applied last among files.
// Only the command line outranks it.
const k3sDropInDir = k3sEtc + "/config.yaml.d"

// k3sFixable turns a k3s finding Review when a file hostveil writes would
// decide the setting, and records how to restart k3s. When the command line
// sets one of keys, the command line wins over every file, so a drop-in would
// change nothing and the finding says so instead.
func k3sFixable(f *model.Finding, cfg k3sConfig, keys ...string) {
	for _, k := range keys {
		from := cfg.argsFrom[k]
		if k == "secrets-encryption" {
			from = cfg.secretsEncryptionFrom
		}
		if from == "the k3s.service command line" || from == k3sOpenRC {
			f.Remediation = model.RemediationManual
			f.WhyNoFix = "This is set on the k3s command line (" + from + "), which wins over every config file, so a file Hostveil writes would change nothing."
			return
		}
	}
	if cfg.role == "" {
		f.Remediation = model.RemediationManual
		f.WhyNoFix = "Hostveil could not read how k3s is started, so it cannot tell whether a config file it writes would be overridden."
		return
	}
	f.Remediation = model.RemediationReview
	if f.Metadata == nil {
		f.Metadata = map[string]string{}
	}
	f.Metadata["k3s_dropin_dir"] = k3sDropInDir
	f.Metadata["k3s_restart"] = "systemd"
	if cfg.cmdlineFrom == k3sOpenRC {
		f.Metadata["k3s_restart"] = "openrc"
	}
}

func secretsFinding() model.Finding {
	return model.NewFinding("kube.secrets-unencrypted",
		"Kubernetes Secrets are stored unencrypted",
		model.SeverityLow, model.SourceKube, model.RemediationManual,
		model.WithDescription("k3s stores Secrets in its datastore as plain base64 unless secrets encryption is turned on. Anything that can read the datastore or a backup of it — a copied /var/lib/rancher/k3s, an etcd snapshot shipped off the host — reads every password and API key the cluster holds. It is off by default and on in the k3s CIS hardening guide."),
		model.WithHowToFix("Set `secrets-encryption: true` in /etc/rancher/k3s/config.yaml and restart k3s, then `k3s secrets-encrypt rotate-keys` (or rewrite existing Secrets) so the ones written before the change are encrypted too."),
	)
}

func strconvOct(m os.FileMode) string { return strconv.FormatUint(uint64(m.Perm()), 8) }

// hasArg reports whether the effective value of a component flag is value.
// A flag given twice takes its last value — that is how the component parses
// it, and it is how a k3s `+` drop-in turns an earlier setting off — so the
// last occurrence decides, not any occurrence.
func hasArg(args []string, name, value string) bool {
	found := false
	for _, a := range args {
		k, v, _ := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		if k == name {
			found = strings.EqualFold(strings.TrimSpace(v), value)
		}
	}
	return found
}

func merge(have, add []string, appendTo bool) []string {
	if appendTo {
		return append(have, add...)
	}
	return add
}

func list(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, scalar(e))
		}
		return out
	default:
		return []string{scalar(v)}
	}
}

func scalar(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		// Only ever shown to the operator, never compared: the file's real
		// mode decides the finding, so how YAML chose to read an unquoted
		// 0644 does not matter here.
		return fmt.Sprint(t)
	}
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// k3sSecretsEncrypted asks k3s itself. known is false when it could not say.
func k3sSecretsEncrypted(ctx context.Context, r platform.CommandRunner) (encrypted, known bool) {
	if !platform.Has(r, "k3s") {
		return false, false
	}
	out, err := r.Run(ctx, "k3s", "secrets-encrypt", "status")
	if err != nil {
		return false, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Encryption Status:"); ok {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "enabled":
				return true, true
			case "disabled":
				return false, true
			}
		}
	}
	return false, false
}
