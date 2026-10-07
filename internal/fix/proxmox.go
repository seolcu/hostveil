package fix

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

func registerProxmox(r *Registry) {
	r.Register("proxmox.enterprise-repo-unsubscribed", buildProxmoxNoSubscription)
}

// enterpriseURI matches a Proxmox enterprise repository URI and captures the
// path after the host (debian/pve, debian/ceph-squid, ...).
var enterpriseURI = regexp.MustCompile(`https://enterprise\.proxmox\.com/(debian/[A-Za-z0-9._-]+)`)

// enterpriseComponent is the component name on the same line or stanza:
// pve-enterprise for PVE, enterprise for Ceph.
var enterpriseComponent = regexp.MustCompile(`(?m)(^|[ \t])(pve-enterprise|enterprise)([ \t]*$|[ \t])`)

// buildProxmoxNoSubscription rewrites the one enterprise source file in place
// to the no-subscription repository: the same path on download.proxmox.com,
// with the enterprise component replaced. It is one file, signed by the same
// Proxmox release key, so it is one edit with a checkpoint — which is what
// the two-step "disable one, add the other" it used to be declined for was
// not.
func buildProxmoxNoSubscription(f model.Finding) (Fix, error) {
	p := f.Evidence["sources"]
	if p == "" || strings.Contains(p, ", ") {
		return Fix{}, fmt.Errorf("finding %s does not name exactly one source file", f.ID)
	}
	return Fix{Label: "Switch to the no-subscription repository", Kind: model.RemediationReview, IndividualOnly: true,
		Actions: []Action{{
			Label: "Rewrite " + p + " to the pve-no-subscription repository",
			Benefit: "apt can reach Proxmox's packages again, so the kernel, QEMU and the management stack start " +
				"receiving the security updates that have been silently refused.",
			Warning: "The no-subscription repository is the one Proxmox describes as less tested than enterprise and " +
				"not recommended for production. The next `apt full-upgrade` may bring a lot of Proxmox packages at " +
				"once, after months of none — run it while you can reboot. If you have a subscription, add the key " +
				"instead (`pvesubscription set <key>`) and roll this back. The edit has a checkpoint.",
			Kind: ActionEdit, Path: p,
			Transform: func(in []byte) ([]byte, error) {
				if !enterpriseURI.Match(in) {
					return nil, fmt.Errorf("%s no longer names the enterprise repository; re-scan before fixing", p)
				}
				out := enterpriseURI.ReplaceAll(in, []byte("http://download.proxmox.com/$1"))
				out = enterpriseComponent.ReplaceAllFunc(out, func(m []byte) []byte {
					s := string(m)
					if strings.Contains(s, "pve-enterprise") {
						return []byte(strings.Replace(s, "pve-enterprise", "pve-no-subscription", 1))
					}
					return []byte(strings.Replace(s, "enterprise", "no-subscription", 1))
				})
				return out, nil
			},
		}}}, nil
}
