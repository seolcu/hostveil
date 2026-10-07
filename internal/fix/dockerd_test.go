package fix

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func dockerdFinding(id string, meta map[string]string, ev map[string]string) model.Finding {
	opts := []model.FindingOption{}
	for k, v := range meta {
		opts = append(opts, model.WithMetadata(k, v))
	}
	for k, v := range ev {
		opts = append(opts, model.WithEvidence(k, v))
	}
	return model.NewFinding(id, "t", model.SeverityHigh, model.SourceDockerd, model.RemediationReview, opts...)
}

func TestEveryDockerdFixIsIndividualAndRestartsWhatItEdits(t *testing.T) {
	f := dockerdFinding("dockerd.no-new-privileges", map[string]string{"daemon_json": "/etc/docker/daemon.json"}, nil)
	fx, err := buildDockerdNoNewPrivileges(f)
	if err != nil {
		t.Fatal(err)
	}
	if !fx.IndividualOnly || fx.Kind != model.RemediationReview {
		t.Fatalf("kind %v individual %v", fx.Kind, fx.IndividualOnly)
	}
	now, later := fx.Actions[0], fx.Actions[1]
	if !slices.Equal(now.AfterWrite[0], []string{"systemctl", "restart", "docker"}) || now.TakesEffectOn != "" {
		t.Errorf("the first alternative must restart Docker and be in force: %v %q", now.AfterWrite, now.TakesEffectOn)
	}
	if len(later.AfterWrite) != 0 || later.TakesEffectOn == "" {
		t.Errorf("the second alternative must leave the restart to the operator and say so")
	}
	out, err := now.Transform([]byte("{\n  \"log-driver\": \"journald\"\n}\n"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil || got["no-new-privileges"] != true || got["log-driver"] != "journald" {
		t.Errorf("daemon.json became %s", out)
	}
}

func TestRemovingAFileEndpointKeepsTheOtherHosts(t *testing.T) {
	f := dockerdFinding("dockerd.api-unauthenticated", map[string]string{
		"daemon_json":    "/etc/docker/daemon.json",
		"file_endpoints": "tcp://0.0.0.0:2375",
		"file_hosts":     "unix:///var/run/docker.sock" + model.EvidenceSeparator + "tcp://0.0.0.0:2375",
	}, nil)
	fx, err := buildDockerdRemoveTCP(f)
	if err != nil {
		t.Fatal(err)
	}
	out, err := fx.Actions[0].Transform([]byte(`{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"hosts": ["unix:///var/run/docker.sock"]}` {
		t.Errorf("daemon.json became %s", out)
	}
}

// Removing the only host would leave Docker with no socket at all, which is
// not the default it sounds like.
func TestRemovingTheOnlyHostLeavesTheUnixSocket(t *testing.T) {
	f := dockerdFinding("dockerd.api-unauthenticated", map[string]string{
		"daemon_json": "/etc/docker/daemon.json", "file_endpoints": "tcp://0.0.0.0:2375", "file_hosts": "tcp://0.0.0.0:2375",
	}, nil)
	fx, _ := buildDockerdRemoveTCP(f)
	out, err := fx.Actions[0].Transform([]byte(`{"hosts": ["tcp://0.0.0.0:2375"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "unix:///var/run/docker.sock") {
		t.Errorf("daemon.json became %s", out)
	}
}

func TestAUnitEndpointIsRemovedByOverridingExecStart(t *testing.T) {
	f := dockerdFinding("dockerd.api-unauthenticated", map[string]string{
		"unit": "docker.service", "unit_endpoints": "tcp://0.0.0.0:2375",
		"execstart": "/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375 --containerd=/run/containerd/containerd.sock",
	}, nil)
	fx, err := buildDockerdRemoveTCP(f)
	if err != nil {
		t.Fatal(err)
	}
	a := fx.Actions[0]
	if a.Path != "/etc/systemd/system/docker.service.d/99-hostveil-api.conf" {
		t.Errorf("drop-in path %s", a.Path)
	}
	out, err := a.Transform(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "[Service]\nExecStart=\nExecStart=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock\n"
	if string(out) != want {
		t.Errorf("drop-in:\n%s\nwant:\n%s", out, want)
	}
	if !slices.Equal(a.AfterWrite[0], []string{"systemctl", "daemon-reload"}) {
		t.Errorf("a unit override needs daemon-reload first: %v", a.AfterWrite)
	}
}

func TestEndpointsFromBothSourcesAreDeclined(t *testing.T) {
	f := dockerdFinding("dockerd.api-unauthenticated", map[string]string{
		"daemon_json": "/etc/docker/daemon.json", "file_endpoints": "tcp://0.0.0.0:2375",
		"unit": "docker.service", "unit_endpoints": "tcp://0.0.0.0:2376", "execstart": "/usr/bin/dockerd -H tcp://0.0.0.0:2376",
	}, nil)
	if _, err := buildDockerdRemoveTCP(f); err == nil {
		t.Fatal("one action cannot edit both sources")
	}
}

func TestAQuotedExecStartIsNotReRendered(t *testing.T) {
	f := dockerdFinding("dockerd.api-unauthenticated", map[string]string{
		"unit": "docker.service", "unit_endpoints": "tcp://0.0.0.0:2375",
		"execstart": `/usr/bin/dockerd -H tcp://0.0.0.0:2375 --label "a b"`,
	}, nil)
	if _, err := buildDockerdRemoveTCP(f); err == nil {
		t.Fatal("a command line with quoting must be declined, not re-rendered by splitting on spaces")
	}
}

func TestTheSocketFixIsTrueNowAndAfterTheNextStart(t *testing.T) {
	fx, err := buildDockerdSocketMode(dockerdFinding("dockerd.socket-world-writable", nil, map[string]string{"path": "/var/run/docker.sock"}))
	if err != nil {
		t.Fatal(err)
	}
	a := fx.Actions[0]
	out, _ := a.Transform(nil)
	if string(out) != "[Socket]\nSocketMode=0660\n" {
		t.Errorf("drop-in %q", out)
	}
	if !slices.ContainsFunc(a.AfterWrite, func(c []string) bool { return slices.Equal(c, []string{"chmod", "0660", "/var/run/docker.sock"}) }) {
		t.Errorf("the live socket must be fixed too: %v", a.AfterWrite)
	}
	for _, c := range a.AfterWrite {
		if slices.Contains(c, "restart") {
			t.Errorf("restarting docker.socket stops the daemon with it: %v", c)
		}
	}
}

func TestGroupMemberRemovalNamesOneAccount(t *testing.T) {
	fx, err := buildDockerdRemoveGroupMember(dockerdFinding("dockerd.group-members", nil,
		map[string]string{"group": "docker", "members": "ci" + model.EvidenceSeparator + "alice"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := fx.Actions[0].Commands[0]; !slices.Equal(got, []string{"gpasswd", "-d", "ci", "docker"}) {
		t.Errorf("runs %v", got)
	}
}

// Turning live-restore on is a reload; turning it back off is not, because a
// reload leaves alone the keys the file no longer has. The rollback must
// restart Docker, and the warning must say so.
func TestLiveRestoreRollsBackWithARestart(t *testing.T) {
	fx, err := buildDockerdLiveRestore(dockerdFinding("dockerd.live-restore", map[string]string{"daemon_json": "/etc/docker/daemon.json"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	a := fx.Actions[0]
	if !slices.Equal(a.AfterWrite[0], []string{"systemctl", "reload", "docker"}) {
		t.Errorf("apply runs %v", a.AfterWrite)
	}
	if len(a.AfterRestore) != 1 || !slices.Equal(a.AfterRestore[0], []string{"systemctl", "restart", "docker"}) {
		t.Errorf("rollback runs %v, want a restart", a.AfterRestore)
	}
	if !strings.Contains(a.Warning, "Rolling it back restarts Docker") {
		t.Errorf("the warning does not say the rollback restarts Docker: %s", a.Warning)
	}
}
