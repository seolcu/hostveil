package fix

import (
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func TestUFWDockerAppendsTheBlockOnceAndReloads(t *testing.T) {
	fx, err := buildUFWDocker(model.NewFinding("firewall.docker-bypass", "t", model.SeverityHigh, model.SourceFirewall,
		model.RemediationReview, model.WithEvidence("published", "8080/tcp")))
	if err != nil {
		t.Fatal(err)
	}
	a := fx.Actions[0]
	if !fx.IndividualOnly || !slices.Equal(a.AfterWrite[0], []string{"ufw", "reload"}) {
		t.Fatalf("individual=%v afterwrite=%v", fx.IndividualOnly, a.AfterWrite)
	}
	orig := "*filter\n:ufw-after-input - [0:0]\nCOMMIT"
	out, err := a.Transform([]byte(orig))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), orig+"\n") || !strings.Contains(string(out), "-A DOCKER-USER -j ufw-user-forward") {
		t.Errorf("after.rules became:\n%s", out)
	}
	if _, err := a.Transform(out); err == nil {
		t.Error("a second block must be refused, not appended")
	}
}

func TestEnvFilesResolveAgainstTheProjectDirectory(t *testing.T) {
	f := model.NewFinding("compose.dr004", "t", model.SeverityLow, model.SourceCompose, model.RemediationReview,
		model.WithService("app"), model.WithMetadata("file", "/srv/stack/compose.yml"),
		model.WithEvidence("env_files", ".env"+model.PathListSeparator+"/etc/stack/secret.env"))
	fx, err := buildTightenEnvFiles(f)
	if err != nil {
		t.Fatal(err)
	}
	a := fx.Actions[0]
	if !slices.Equal(a.Paths, []string{"/srv/stack/.env", "/etc/stack/secret.env"}) {
		t.Errorf("paths = %v", a.Paths)
	}
	if a.SafeRoot != "" {
		t.Errorf("a file outside the project must drop SafeRoot rather than be refused: %q", a.SafeRoot)
	}
	if got := a.Mode(0o644); got.Perm() != 0o600 {
		t.Errorf("0644 -> %v", got)
	}
}

func TestKubeconfigModeFollowsTheDistribution(t *testing.T) {
	for path, want := range map[string]fs.FileMode{
		"/etc/rancher/k3s/k3s.yaml": 0o600,
		k0sAdminConf:                0o640,
	} {
		fx, err := buildTightenKubeconfig(model.NewFinding("kube.kubeconfig-readable", "t", model.SeverityMedium,
			model.SourceKube, model.RemediationReview, model.WithEvidence("path", path)))
		if err != nil {
			t.Fatal(err)
		}
		if got := fx.Actions[0].Mode(0o644).Perm(); got != want {
			t.Errorf("%s: 0644 -> %#o, want %#o", path, got, want)
		}
	}
}

// ufw reload leaves Docker's DOCKER-USER chain as it is, so restoring
// after.rules alone left the block in force; the rollback empties the chain.
func TestUFWDockerRollbackEmptiesDockerUser(t *testing.T) {
	fx, err := buildUFWDocker(model.NewFinding("firewall.docker-bypass", "t", model.SeverityHigh, model.SourceFirewall,
		model.RemediationReview, model.WithEvidence("published", "8080/tcp")))
	if err != nil {
		t.Fatal(err)
	}
	got := fx.Actions[0].AfterRestore
	if len(got) != 2 || !slices.Equal(got[1], []string{"iptables", "-F", "DOCKER-USER"}) {
		t.Errorf("rollback runs %v", got)
	}
}
