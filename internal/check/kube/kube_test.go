package kube

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/checktest"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

type file struct {
	body string
	mode os.FileMode
}

// host lays out a fake root. Every file is written with its mode applied
// after creation, so the umask cannot quietly tighten a fixture.
func host(t *testing.T, files map[string]file) string {
	t.Helper()
	root := t.TempDir()
	for name, f := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, f.mode); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// A stock single-node k3s server: 0600 kubeconfig and tokens, no config, and
// the unit the install script writes.
func stock() map[string]file {
	return map[string]file{
		"etc/rancher/k3s/k3s.yaml":              {"apiVersion: v1\n", 0o600},
		"var/lib/rancher/k3s/server/token":      {"K10abc::server:def\n", 0o600},
		"var/lib/rancher/k3s/server/node-token": {"K10abc::server:def\n", 0o600},
		"etc/rancher/k3s/config.yaml":           {"secrets-encryption: true\n", 0o600},
	}
}

func unit(argv string) *checktest.Runner {
	return checktest.New().Script(
		"LoadState=loaded\nExecStart={ path=/usr/local/bin/k3s ; argv[]=/usr/local/bin/k3s "+argv+" ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n",
		"systemctl", "show", "k3s.service", "--property=LoadState,ExecStart", "--no-pager")
}

func with(base map[string]file, over map[string]file) map[string]file {
	for k, v := range over {
		base[k] = v
	}
	return base
}

func scan(t *testing.T, root string, env platform.Env) []model.Finding {
	t.Helper()
	fs, err := (&Checker{Root: root}).Check(context.Background(), env)
	if err != nil {
		t.Fatalf("nothing went unexamined: %v", err)
	}
	return fs
}

func has(fs []model.Finding, id string) *model.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestAStockServerIsClean(t *testing.T) {
	if fs := scan(t, host(t, stock()), unit("server").Env()); len(fs) != 0 {
		t.Errorf("flagged a stock, encrypted server: %v", fs)
	}
}

func TestOnlyAKubernetesHostIsAvailable(t *testing.T) {
	if ok, why := (&Checker{Root: t.TempDir()}).Available(context.Background(), platform.Env{}); ok || why == "" {
		t.Errorf("no k3s and no k0s is not a Kubernetes host: %v %q", ok, why)
	}
	if ok, _ := (&Checker{Root: host(t, stock())}).Available(context.Background(), platform.Env{}); !ok {
		t.Error("a k3s host is")
	}
	if ok, _ := (&Checker{Root: host(t, map[string]file{"etc/k0s/k0s.yaml": {"", 0o600}})}).Available(context.Background(), platform.Env{}); !ok {
		t.Error("a k0s host is")
	}
}

// --- kubeconfig ---

func TestWorldReadableKubeconfig(t *testing.T) {
	root := host(t, with(stock(), map[string]file{
		"etc/rancher/k3s/k3s.yaml":           {"apiVersion: v1\n", 0o644},
		"etc/systemd/system/k3s.service.env": {"K3S_KUBECONFIG_MODE='644'\n", 0o600},
	}))
	f := has(scan(t, root, unit("server").Env()), "kube.kubeconfig-readable")
	if f == nil {
		t.Fatal("a 0644 admin kubeconfig must be reported")
	}
	if f.Evidence["mode"] != "0644" || f.Evidence["set-in"] != "/etc/systemd/system/k3s.service.env" {
		t.Errorf("evidence = %v", f.Evidence)
	}
	if !strings.Contains(f.HowToFix, "k3s.service.env") {
		t.Errorf("the fix must point at where the mode is set, got %q", f.HowToFix)
	}
}

// The command line wins over the environment file and every config file.
func TestCommandLineModeWins(t *testing.T) {
	root := host(t, with(stock(), map[string]file{
		"etc/rancher/k3s/k3s.yaml":    {"apiVersion: v1\n", 0o644},
		"etc/rancher/k3s/config.yaml": {"secrets-encryption: true\nwrite-kubeconfig-mode: \"0600\"\n", 0o600},
	}))
	f := has(scan(t, root, unit("server --write-kubeconfig-mode 644").Env()), "kube.kubeconfig-readable")
	if f == nil || f.Evidence["set-in"] != "the k3s.service command line" {
		t.Fatalf("want the command line named, got %v", f)
	}
}

// A group bit is write-kubeconfig-group doing its job, the docker-group trade.
func TestGroupReadableKubeconfigIsAChoice(t *testing.T) {
	root := host(t, with(stock(), map[string]file{"etc/rancher/k3s/k3s.yaml": {"apiVersion: v1\n", 0o640}}))
	if f := has(scan(t, root, unit("server").Env()), "kube.kubeconfig-readable"); f != nil {
		t.Errorf("flagged a group-readable kubeconfig: %v", f.Evidence)
	}
}

// --- tokens ---

func TestWorldReadableToken(t *testing.T) {
	root := host(t, with(stock(), map[string]file{"var/lib/rancher/k3s/server/node-token": {"K10abc::server:def\n", 0o644}}))
	f := has(scan(t, root, unit("server").Env()), "kube.token-readable")
	if f == nil || !strings.HasSuffix(f.Evidence["path"], "node-token") {
		t.Fatalf("want node-token reported, got %v", f)
	}
}

// An agent holds no server token, and its API server is not its own.
func TestAnAgentIsNotJudgedAsAServer(t *testing.T) {
	root := host(t, map[string]file{"etc/rancher/k3s/config.yaml": {"kube-apiserver-arg: [anonymous-auth=true]\n", 0o600}})
	fs := scan(t, root, unit("agent --server https://10.0.0.1:6443").Env())
	if len(fs) != 0 {
		t.Errorf("judged an agent as a server: %v", fs)
	}
}

// --- anonymous auth ---

func TestAnonymousAuthLayers(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]file
		argv  string
		want  bool
	}{
		"config.yaml": {map[string]file{"etc/rancher/k3s/config.yaml": {"secrets-encryption: true\nkube-apiserver-arg:\n  - anonymous-auth=true\n", 0o600}}, "server", true},
		"kubelet arg": {map[string]file{"etc/rancher/k3s/config.yaml": {"secrets-encryption: true\nkubelet-arg: \"anonymous-auth=true\"\n", 0o600}}, "server", true},
		"drop-in replaces": {map[string]file{
			"etc/rancher/k3s/config.yaml":               {"secrets-encryption: true\nkube-apiserver-arg: [anonymous-auth=true]\n", 0o600},
			"etc/rancher/k3s/config.yaml.d/50-fix.yaml": {"kube-apiserver-arg: [audit-log-maxage=30]\n", 0o600},
		}, "server", false},
		"drop-in appends": {map[string]file{
			// With `+`, the base file's value survives the drop-in; without
			// it, the drop-in would have replaced it.
			"etc/rancher/k3s/config.yaml":               {"secrets-encryption: true\nkube-apiserver-arg: [anonymous-auth=true]\n", 0o600},
			"etc/rancher/k3s/config.yaml.d/50-dbg.yaml": {"kube-apiserver-arg+: [audit-log-maxage=30]\n", 0o600},
		}, "server", true},
		"later drop-in wins": {map[string]file{
			"etc/rancher/k3s/config.yaml.d/10-a.yaml": {"secrets-encryption: true\nkube-apiserver-arg: [anonymous-auth=true]\n", 0o600},
			"etc/rancher/k3s/config.yaml.d/20-b.yaml": {"kube-apiserver-arg: [anonymous-auth=false]\n", 0o600},
		}, "server", false},
		"flag replaces the files' list": {map[string]file{"etc/rancher/k3s/config.yaml": {"secrets-encryption: true\nkube-apiserver-arg: [anonymous-auth=true]\n", 0o600}}, "server --kube-apiserver-arg=audit-log-maxage=30", false},
		"flag sets it":                  {nil, "server --secrets-encryption --kube-apiserver-arg anonymous-auth=true", true},
		"explicit false":                {map[string]file{"etc/rancher/k3s/config.yaml": {"secrets-encryption: true\nkube-apiserver-arg: [anonymous-auth=false]\n", 0o600}}, "server", false},
	} {
		t.Run(name, func(t *testing.T) {
			root := host(t, with(stock(), tc.files))
			f := has(scan(t, root, unit(tc.argv).Env()), "kube.anonymous-auth")
			if (f != nil) != tc.want {
				t.Fatalf("anonymous-auth finding = %v, want %v", f != nil, tc.want)
			}
			if f != nil && f.Severity != model.SeverityMedium {
				t.Errorf("severity = %v; RBAC still stands between anonymous and the cluster", f.Severity)
			}
		})
	}
}

// --- secrets encryption ---

func TestSecretsEncryption(t *testing.T) {
	noConfig := with(stock(), map[string]file{"etc/rancher/k3s/config.yaml": {"# empty\n", 0o600}})
	if has(scan(t, host(t, noConfig), unit("server").Env()), "kube.secrets-unencrypted") == nil {
		t.Error("the k3s default is unencrypted and must be reported")
	}
	if f := has(scan(t, host(t, noConfig), unit("server --secrets-encryption").Env()), "kube.secrets-unencrypted"); f != nil {
		t.Error("a bare --secrets-encryption turns it on")
	}
	if f := has(scan(t, host(t, noConfig), unit("server --secrets-encryption=false").Env()), "kube.secrets-unencrypted"); f == nil {
		t.Error("--secrets-encryption=false is off")
	}
}

// --- how k3s is started ---

func TestTheCommandLineComesFromOpenRCWithoutSystemd(t *testing.T) {
	// Verbatim what `K3S_KUBECONFIG_MODE=644 sh install.sh server
	// --kube-apiserver-arg=anonymous-auth=true --node-label "a=b c"` writes
	// on Alpine: one quoted argument per line, backslash-continued, and a
	// redirect at the end. The first version of this read one line and saw
	// a bare `server`.
	script := "#!/sbin/openrc-run\n\ndepend() {\n    after network-online\n}\n\n" +
		"name=k3s\ncommand=\"/usr/local/bin/k3s\"\ncommand_args=\"server \\\n" +
		"\t'--kube-apiserver-arg=anonymous-auth=true' \\\n" +
		"\t'--node-label' \\\n" +
		"\t'a=b c' \\\n" +
		"    >>/var/log/k3s.log 2>&1\"\n\noutput_log=/var/log/k3s.log\n"
	root := host(t, with(stock(), map[string]file{
		"etc/init.d/k3s":           {script, 0o755},
		"etc/rancher/k3s/k3s.env":  {"K3S_KUBECONFIG_MODE='644'\n", 0o600},
		"etc/rancher/k3s/k3s.yaml": {"apiVersion: v1\n", 0o644},
	}))
	fs := scan(t, root, checktest.New().Without("systemctl").Env())
	f := has(fs, "kube.anonymous-auth")
	if f == nil || !strings.Contains(f.Evidence["set-in"], "/etc/init.d/k3s") {
		t.Fatalf("want the multi-line openrc command line read, got %v", fs)
	}
	if k := has(fs, "kube.kubeconfig-readable"); k == nil || k.Evidence["set-in"] != "/etc/rancher/k3s/k3s.env" {
		t.Errorf("the openrc environment file sets the mode; got %v", k)
	}
}

func TestShellWordsKeepsAQuotedSpace(t *testing.T) {
	got := shellWords("server '--node-label' 'a=b c'")
	if strings.Join(got, "|") != "server|--node-label|a=b c" {
		t.Errorf("shellWords = %q", got)
	}
}

// systemctl show exits 0 for a unit that does not exist. That is not a
// command line with no flags on it.
func TestAnUnreadCommandLineIsAGap(t *testing.T) {
	// No encryption in any file: only a command line nobody read could
	// still be turning it on.
	root := host(t, with(stock(), map[string]file{"etc/rancher/k3s/config.yaml": {"# empty\n", 0o600}}))
	for name, r := range map[string]*checktest.Runner{
		"unit not found": checktest.New().Script("LoadState=not-found\nExecStart=\n", "systemctl", "show", "k3s.service", "--property=LoadState,ExecStart", "--no-pager"),
		"no systemd":     checktest.New().Without("systemctl"),
	} {
		t.Run(name, func(t *testing.T) {
			fs, err := (&Checker{Root: root}).Check(context.Background(), r.Env())
			var pe *check.PartialError
			if !errors.As(err, &pe) {
				t.Fatalf("expected a coverage gap, got %v", err)
			}
			if has(fs, "kube.secrets-unencrypted") != nil {
				t.Error("judged secrets encryption without reading the command line it can be set on")
			}
		})
	}
}

// --- k0s ---

func TestK0s(t *testing.T) {
	root := host(t, map[string]file{
		"var/lib/k0s/pki/admin.conf": {"apiVersion: v1\n", 0o644},
		"etc/k0s/k0s.yaml":           {"apiVersion: k0s.k0sproject.io/v1beta1\nspec:\n  api:\n    extraArgs:\n      anonymous-auth: \"true\"\n", 0o600},
	})
	fs := scan(t, root, checktest.New().Env())
	if has(fs, "kube.kubeconfig-readable") == nil || has(fs, "kube.anonymous-auth") == nil {
		t.Errorf("want both k0s findings, got %v", fs)
	}

	clean := host(t, map[string]file{"var/lib/k0s/pki/admin.conf": {"apiVersion: v1\n", 0o640}})
	if fs := scan(t, clean, checktest.New().Env()); len(fs) != 0 {
		t.Errorf("k0s at its own defaults, with no config file, flagged: %v", fs)
	}
}
