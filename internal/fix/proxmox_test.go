package fix

import (
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func TestEnterpriseSourcesBecomeNoSubscription(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"pve list": {
			"deb https://enterprise.proxmox.com/debian/pve bookworm pve-enterprise\n",
			"deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription\n"},
		"ceph list": {
			"deb https://enterprise.proxmox.com/debian/ceph-quincy bookworm enterprise\n",
			"deb http://download.proxmox.com/debian/ceph-quincy bookworm no-subscription\n"},
		"pve deb822": {
			"Types: deb\nURIs: https://enterprise.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-enterprise\nSigned-By: /usr/share/keyrings/proxmox-archive-keyring.gpg\n",
			"Types: deb\nURIs: http://download.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-no-subscription\nSigned-By: /usr/share/keyrings/proxmox-archive-keyring.gpg\n"},
	} {
		fx, err := buildProxmoxNoSubscription(model.NewFinding("proxmox.enterprise-repo-unsubscribed", "t",
			model.SeverityMedium, model.SourceProxmox, model.RemediationReview,
			model.WithEvidence("sources", "/etc/apt/sources.list.d/pve-enterprise.list")))
		if err != nil {
			t.Fatal(err)
		}
		out, err := fx.Actions[0].Transform([]byte(tc.in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(out) != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", name, out, tc.want)
		}
	}
}

func TestTwoEnterpriseSourcesAreDeclined(t *testing.T) {
	_, err := buildProxmoxNoSubscription(model.NewFinding("proxmox.enterprise-repo-unsubscribed", "t",
		model.SeverityMedium, model.SourceProxmox, model.RemediationReview,
		model.WithEvidence("sources", "/etc/apt/sources.list.d/a.list, /etc/apt/sources.list.d/b.list")))
	if err == nil {
		t.Fatal("two files are two edits")
	}
}
