package kube

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
)

// The fix writes a drop-in this checker reads back, under the same
// precedence k3s applies — so the loop closes here, with the fake root.
func TestTheK3sFixesClearTheirFindings(t *testing.T) {
	for _, id := range []string{"kube.anonymous-auth", "kube.secrets-unencrypted"} {
		t.Run(id, func(t *testing.T) {
			root := host(t, with(stock(), map[string]file{
				"etc/rancher/k3s/config.yaml": {"kube-apiserver-arg: [anonymous-auth=true]\n", 0o600},
			}))
			f := has(scan(t, root, unit("server").Env()), id)
			if f == nil {
				t.Fatal("not flagged")
			}
			if f.Remediation != model.RemediationReview {
				t.Fatalf("remediation = %v, want Review", f.Remediation)
			}
			fx, ok, err := fix.Default().Build(*f)
			if err != nil || !ok {
				t.Fatalf("build: %v %v", ok, err)
			}
			a := fx.Actions[0]
			out, err := a.Transform(nil)
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(root, a.Path)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, out, 0o600); err != nil {
				t.Fatal(err)
			}
			if has(scan(t, root, unit("server").Env()), id) != nil {
				t.Errorf("%s survived its own drop-in:\n%s", id, out)
			}
		})
	}
}

// A flag on the command line outranks every file, so a drop-in would change
// nothing: Manual, with the reason.
func TestACommandLineFlagIsNotFixedByAFile(t *testing.T) {
	root := host(t, stock())
	f := has(scan(t, root, unit("server --kube-apiserver-arg anonymous-auth=true").Env()), "kube.anonymous-auth")
	if f == nil {
		t.Fatal("not flagged")
	}
	if f.Remediation != model.RemediationManual || f.WhyNoFix == "" {
		t.Errorf("remediation = %v, why %q", f.Remediation, f.WhyNoFix)
	}
}
