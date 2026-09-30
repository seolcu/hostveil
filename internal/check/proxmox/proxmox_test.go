package proxmox

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

// A hardened node: management network only, root with a TOTP factor, and the
// no-subscription repository in place of the enterprise one.
var hardened = map[string]string{
	"etc/default/pveproxy":                          "ALLOW_FROM=\"10.0.0.0/8\"\nDENY_FROM=\"all\"\nPOLICY=\"allow\"\n",
	"etc/pve/priv/tfa.cfg":                          `{"users":{"root@pam":{"totp":[{"id":"t1","description":"phone","created":1,"entry":"otpauth://x"}]}}}`,
	"etc/apt/sources.list.d/pve-enterprise.sources": "Types: deb\nURIs: https://enterprise.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-enterprise\nEnabled: no\n",
	"etc/apt/sources.list.d/proxmox.sources":        "Types: deb\nURIs: http://download.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-no-subscription\n",
}

// node lays out a fake PVE root: the hardened files, with overrides. An
// override of "" deletes the file.
func node(t *testing.T, overrides map[string]string) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{}
	for k, v := range hardened {
		files[k] = v
	}
	for k, v := range overrides {
		files[k] = v
	}
	if err := os.MkdirAll(filepath.Join(root, "etc/pve"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if body == "" {
			continue
		}
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func subscription(status string) platform.Env {
	return checktest.New().Script("key: pve2c-0000000000\nstatus: "+status+"\n", "pvesubscription", "get").Env()
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

func TestAHardenedNodeIsClean(t *testing.T) {
	if fs := scan(t, node(t, nil), subscription("notfound")); len(fs) != 0 {
		t.Errorf("flagged a hardened node: %v", fs)
	}
}

func TestOnlyAPVEHostIsAvailable(t *testing.T) {
	if ok, why := (&Checker{Root: t.TempDir()}).Available(context.Background(), platform.Env{}); ok || why == "" {
		t.Errorf("a host with no /etc/pve is not a Proxmox VE host: ok=%v why=%q", ok, why)
	}
	if ok, why := (&Checker{Root: node(t, nil)}).Available(context.Background(), platform.Env{}); !ok {
		t.Errorf("a host with /etc/pve is: %s", why)
	}
}

// --- web interface ---

func TestWebUIDefaultsAreOpen(t *testing.T) {
	for name, body := range map[string]string{
		"file absent":                "",
		"stock comments only":        "# ALLOW_FROM=\"10.0.0.1-10.0.0.5,192.168.0.0/22\"\n# DENY_FROM=\"all\"\n# POLICY=\"allow\"\n",
		"allow list, nothing denied": "ALLOW_FROM=\"10.0.0.0/8\"\n",
		"allow all":                  "ALLOW_FROM=\"all\"\nPOLICY=\"deny\"\n",
		"deny 0/0 but allow all":     "ALLOW_FROM=\"0/0\"\nDENY_FROM=\"all\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := has(scan(t, node(t, map[string]string{"etc/default/pveproxy": body}), subscription("active")), "proxmox.webui-open")
			if f == nil {
				t.Fatal("expected proxmox.webui-open")
			}
			if f.Severity != model.SeverityMedium || f.Remediation != model.RemediationManual {
				t.Errorf("severity %v, remediation %v", f.Severity, f.Remediation)
			}
		})
	}
}

func TestWebUIRestrictedIsClean(t *testing.T) {
	for name, body := range map[string]string{
		"listen ip":             "LISTEN_IP=\"192.168.1.10\"\n",
		"allow + policy deny":   "ALLOW_FROM=\"192.168.1.0/24\"\nPOLICY=\"deny\"\n",
		"allow + deny all":      "ALLOW_FROM='192.168.1.0/24'\nDENY_FROM='all'\n",
		"allow + deny ::/0,0/0": "ALLOW_FROM=\"192.168.1.0/24\"\nDENY_FROM=\"0/0,::/0\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if f := has(scan(t, node(t, map[string]string{"etc/default/pveproxy": body}), subscription("active")), "proxmox.webui-open"); f != nil {
				t.Errorf("flagged %v", f.Evidence)
			}
		})
	}
}

// --- root's second factor ---

func TestRootWithoutASecondFactor(t *testing.T) {
	for name, body := range map[string]string{
		"file absent":           "",
		"no users":              `{}`,
		"another user only":     `{"users":{"alice@pve":{"totp":[{"id":"t","entry":"x"}]}}}`,
		"recovery codes only":   `{"users":{"root@pam":{"recovery":{"secret":"s","entries":["a"],"created":1}}}}`,
		"factor disabled":       `{"users":{"root@pam":{"webauthn":[{"id":"w","enable":false,"entry":{}}]}}}`,
		"webauthn config, none": `{"webauthn":{"rp":"pve","origin":"https://pve:8006","id":"pve"},"users":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := has(scan(t, node(t, map[string]string{"etc/pve/priv/tfa.cfg": body}), subscription("active")), "proxmox.root-no-tfa")
			if f == nil {
				t.Fatal("expected proxmox.root-no-tfa")
			}
		})
	}
}

func TestRootWithASecondFactorIsClean(t *testing.T) {
	for _, body := range []string{
		`{"users":{"root@pam":{"webauthn":[{"id":"w","description":"key","created":1,"entry":{}}]}}}`,
		`{"users":{"root@pam":{"yubico":[{"id":"y","enable":true,"entry":"cccc"}],"totp":[{"id":"t","enable":false,"entry":"x"}]}}}`,
	} {
		if f := has(scan(t, node(t, map[string]string{"etc/pve/priv/tfa.cfg": body}), subscription("active")), "proxmox.root-no-tfa"); f != nil {
			t.Errorf("%s: flagged", body)
		}
	}
}

// /etc/pve/priv is root's. A non-root scan cannot read it, and that is a
// blind spot, never "root has no second factor".
func TestUnreadableTFAConfigIsAGap(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file")
	}
	root := node(t, nil)
	if err := os.Chmod(filepath.Join(root, "etc/pve/priv/tfa.cfg"), 0); err != nil {
		t.Fatal(err)
	}
	fs, err := (&Checker{Root: root}).Check(context.Background(), subscription("active"))
	var pe *check.PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("expected a coverage gap, got %v", err)
	}
	if has(fs, "proxmox.root-no-tfa") != nil {
		t.Error("reported a finding about a file it could not read")
	}
}

// --- enterprise repository ---

func TestEnterpriseRepoWithoutSubscription(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"deb822 enabled":       {"etc/apt/sources.list.d/pve-enterprise.sources": "Types: deb\nURIs: https://enterprise.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-enterprise\nSigned-By: /usr/share/keyrings/proxmox-archive-keyring.gpg\n"},
		"deb822 second stanza": {"etc/apt/sources.list.d/pve-enterprise.sources": "Types: deb\nURIs: http://deb.debian.org/debian\nSuites: trixie\nComponents: main\n\nTypes: deb\nURIs:\n https://enterprise.proxmox.com/debian/ceph-squid\nSuites: trixie\nComponents: enterprise\n"},
		"one-line (PVE 8)":     {"etc/apt/sources.list.d/pve-enterprise.list": "deb https://enterprise.proxmox.com/debian/pve bookworm pve-enterprise\n"},
	} {
		t.Run(name, func(t *testing.T) {
			f := has(scan(t, node(t, files), subscription("notfound")), "proxmox.enterprise-repo-unsubscribed")
			if f == nil {
				t.Fatal("expected proxmox.enterprise-repo-unsubscribed")
			}
			if f.Evidence["status"] != "notfound" || !strings.Contains(f.Evidence["sources"], "/etc/apt/sources.list.d/") {
				t.Errorf("evidence = %v", f.Evidence)
			}
		})
	}
}

func TestEnterpriseRepoCleanCases(t *testing.T) {
	enabled := map[string]string{"etc/apt/sources.list.d/pve-enterprise.list": "deb https://enterprise.proxmox.com/debian/pve bookworm pve-enterprise\n"}
	for name, tc := range map[string]struct {
		files  map[string]string
		status string
	}{
		"subscribed":       {enabled, "Active"},
		"commented out":    {map[string]string{"etc/apt/sources.list.d/pve-enterprise.list": "# deb https://enterprise.proxmox.com/debian/pve bookworm pve-enterprise\n"}, "notfound"},
		"deb822 disabled":  {map[string]string{"etc/apt/sources.list.d/pve-enterprise.sources": "Types: deb\nURIs: https://enterprise.proxmox.com/debian/pve\nEnabled: false\n"}, "notfound"},
		"deb822 commented": {map[string]string{"etc/apt/sources.list.d/pve-enterprise.sources": "# URIs: https://enterprise.proxmox.com/debian/pve\n"}, "notfound"},
	} {
		t.Run(name, func(t *testing.T) {
			if f := has(scan(t, node(t, tc.files), subscription(tc.status)), "proxmox.enterprise-repo-unsubscribed"); f != nil {
				t.Errorf("flagged %v", f.Evidence)
			}
		})
	}
}

// With the enterprise repository enabled, the subscription is the whole
// question, and not being able to ask it is a gap.
func TestSubscriptionUnknownIsAGap(t *testing.T) {
	root := node(t, map[string]string{"etc/apt/sources.list.d/pve-enterprise.list": "deb https://enterprise.proxmox.com/debian/pve bookworm pve-enterprise\n"})
	for name, env := range map[string]platform.Env{
		"not installed": checktest.New().Without("pvesubscription").Env(),
		"fails":         checktest.New().Fail(errors.New("exit 2"), "pvesubscription", "get").Env(),
		"no status":     checktest.New().Script("key: x\n", "pvesubscription", "get").Env(),
	} {
		t.Run(name, func(t *testing.T) {
			fs, err := (&Checker{Root: root}).Check(context.Background(), env)
			var pe *check.PartialError
			if !errors.As(err, &pe) {
				t.Fatalf("expected a coverage gap, got %v", err)
			}
			if has(fs, "proxmox.enterprise-repo-unsubscribed") != nil {
				t.Error("reported a finding about a subscription it could not read")
			}
		})
	}
}

// Without an enterprise repository the subscription is not asked about at
// all, so a host without pvesubscription is not degraded for it.
func TestNoEnterpriseRepoNeedsNoSubscriptionCheck(t *testing.T) {
	scan(t, node(t, nil), checktest.New().Without("pvesubscription").Env())
}
