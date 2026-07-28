package dockerd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

type fakeRunner struct {
	present map[string]bool
	outputs map[string]string // key: "name arg1 arg2..."
}

func (f fakeRunner) LookPath(name string) (string, error) {
	if f.present[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if out, ok := f.outputs[key]; ok {
		return []byte(out), nil
	}
	return nil, errors.New("no output for: " + key)
}

const infoCmd = "docker info --format {{json .}}"

// hardenedInfo is a daemon with every default this domain checks turned on,
// so a test that means to isolate one rule does not accidentally assert the
// other two as well.
const hardenedInfo = `{"SecurityOptions":["name=seccomp,profile=builtin","name=no-new-privileges","name=userns"],"LiveRestoreEnabled":true}`

// bareInfo is a stock daemon: none of the three defaults set.
const bareInfo = `{"SecurityOptions":["name=seccomp,profile=builtin"],"LiveRestoreEnabled":false}`

// execStart renders `systemctl show` output the way systemd really does,
// so the parser is exercised against the real shape rather than a
// convenient one.
func execStart(args string) string {
	return "ExecStart={ path=/usr/bin/dockerd ; argv[]=/usr/bin/dockerd " + args +
		" ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n"
}

// env builds a scan environment whose daemon answers with the given info
// document and whose unit carries the given dockerd flags.
func env(info, unitArgs string) platform.Env {
	out := map[string]string{
		infoCmd: info,
		"docker version --format {{.Server.Version}}": "27.0.0\n",
	}
	if unitArgs != "" {
		out["systemctl show docker.service --property=ExecStart --no-pager"] = execStart(unitArgs)
	}
	return platform.Env{
		ServiceManager: platform.SMSystemd,
		Runner:         fakeRunner{present: map[string]bool{"docker": true}, outputs: out},
	}
}

// host writes a fixture host: a daemon.json (skipped when empty), a group
// file, a passwd file, and a real unix socket at the requested mode.
//
// The socket lives in os.MkdirTemp rather than t.TempDir because a unix
// socket path is bounded by sun_path (~104 bytes) and darwin's per-test
// temp directories are long enough to overflow it.
type fixture struct {
	c *Checker
}

func host(t *testing.T, daemonJSON, group, passwd string, mode os.FileMode) fixture {
	t.Helper()
	dir, err := os.MkdirTemp("", "hvdockerd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	c := &Checker{
		DaemonConfig: filepath.Join(dir, "daemon.json"),
		SocketPath:   filepath.Join(dir, "docker.sock"),
		GroupPath:    filepath.Join(dir, "group"),
		PasswdPath:   filepath.Join(dir, "passwd"),
		Unit:         "docker.service",
	}
	if daemonJSON != "" {
		write(t, c.DaemonConfig, daemonJSON)
	}
	if mode != 0 {
		l, err := net.Listen("unix", c.SocketPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		if err := os.Chmod(c.SocketPath, mode); err != nil {
			t.Fatal(err)
		}
	}

	// The fixture socket is owned by whichever group created it, which is
	// the test user's and differs between a developer's machine and CI's
	// root container. Chowning it would need privileges the tests must not
	// require, so the passwd and group fixtures name the socket's real gid
	// instead: %GID% is substituted here, and a test asserting membership
	// writes %GID% wherever it means "the group that owns the socket".
	gid := "999"
	if mode != 0 {
		s, _, _, _ := c.readSocket()
		gid = strconv.FormatUint(uint64(s.gid), 10)
	}
	write(t, c.GroupPath, strings.ReplaceAll(group, "%GID%", gid))
	write(t, c.PasswdPath, strings.ReplaceAll(passwd, "%GID%", gid))
	return fixture{c: c}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// cleanGroup is a docker group nobody but root holds, so group-membership
// findings stay out of tests about something else. %GID% is the gid that
// actually owns the fixture socket; see host.
const cleanGroup = "root:x:0:\ndocker:x:%GID%:\n"
const cleanPasswd = "root:x:0:0:root:/root:/bin/bash\n"

func (f fixture) check(t *testing.T, e platform.Env) []model.Finding {
	t.Helper()
	fs, err := f.c.Check(context.Background(), e)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return fs
}

// find returns the finding with the given ID, or nil.
func find(fs []model.Finding, id string) *model.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func mustFind(t *testing.T, fs []model.Finding, id string) model.Finding {
	t.Helper()
	f := find(fs, id)
	if f == nil {
		t.Fatalf("expected %s; got %v", id, ids(fs))
	}
	return *f
}

func mustNotFind(t *testing.T, fs []model.Finding, id string) {
	t.Helper()
	if f := find(fs, id); f != nil {
		t.Fatalf("did not expect %s; got %v", id, ids(fs))
	}
}

func ids(fs []model.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

// --- the API socket -------------------------------------------------------

func TestUnauthenticatedTCPFromDaemonJSON(t *testing.T) {
	h := host(t, `{"hosts":["unix:///var/run/docker.sock","tcp://0.0.0.0:2375"]}`,
		cleanGroup, cleanPasswd, 0o660)
	fs := h.check(t, env(hardenedInfo, "-H fd://"))

	f := mustFind(t, fs, "dockerd.api-unauthenticated")
	if f.Severity != model.SeverityCritical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	if got := f.Evidence["endpoints"]; got != "tcp://0.0.0.0:2375" {
		t.Errorf("endpoints evidence = %q", got)
	}
	if !strings.Contains(f.Evidence["configured in"], "daemon.json") {
		t.Errorf("configured-in evidence = %q, should name daemon.json", f.Evidence["configured in"])
	}
}

// The packaged unit is where every mainstream distribution puts the daemon's
// listening socket, so a checker that read only daemon.json would report a
// host with an exposed API as having no sockets configured at all.
func TestUnauthenticatedTCPFromExecStart(t *testing.T) {
	h := host(t, "", cleanGroup, cleanPasswd, 0o660)
	fs := h.check(t, env(hardenedInfo, "-H fd:// -H tcp://0.0.0.0:2375"))

	f := mustFind(t, fs, "dockerd.api-unauthenticated")
	if !strings.Contains(f.Evidence["configured in"], "unit") {
		t.Errorf("configured-in evidence = %q, should name the unit", f.Evidence["configured in"])
	}
}

func TestUnauthenticatedTCPFromAttachedHostFlag(t *testing.T) {
	h := host(t, "", cleanGroup, cleanPasswd, 0o660)
	fs := h.check(t, env(hardenedInfo, "--host=tcp://0.0.0.0:2375"))
	mustFind(t, fs, "dockerd.api-unauthenticated")
}

// The regression that matters most in this domain: an operator who set up
// mutual TLS did the work correctly and must see nothing at all.
func TestTLSVerifiedTCPIsClean(t *testing.T) {
	h := host(t, `{"hosts":["tcp://0.0.0.0:2376"],"tlsverify":true,"tlscacert":"/etc/docker/ca.pem","tlscert":"/etc/docker/cert.pem"}`,
		cleanGroup, cleanPasswd, 0o660)
	fs := h.check(t, env(hardenedInfo, "-H fd://"))

	mustNotFind(t, fs, "dockerd.api-unauthenticated")
	mustNotFind(t, fs, "dockerd.api-tls-unverified")
}

func TestTLSVerifiedFromExecStartIsClean(t *testing.T) {
	h := host(t, "", cleanGroup, cleanPasswd, 0o660)
	fs := h.check(t, env(hardenedInfo, "-H tcp://0.0.0.0:2376 --tlsverify"))
	mustNotFind(t, fs, "dockerd.api-unauthenticated")
	mustNotFind(t, fs, "dockerd.api-tls-unverified")
}

// TLS without client verification is encryption without authorization: a
// rung below Critical, but never clean and never the unauthenticated finding.
func TestTLSWithoutVerifyIsHighNotCritical(t *testing.T) {
	h := host(t, `{"hosts":["tcp://0.0.0.0:2376"],"tls":true,"tlscert":"/etc/docker/cert.pem"}`,
		cleanGroup, cleanPasswd, 0o660)
	fs := h.check(t, env(hardenedInfo, "-H fd://"))

	f := mustFind(t, fs, "dockerd.api-tls-unverified")
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want High", f.Severity)
	}
	mustNotFind(t, fs, "dockerd.api-unauthenticated")
}

// A certificate with no explicit "tls": true still means TLS is in force —
// dockerd enables it implicitly — so reading only the boolean would grade a
// TLS-serving daemon as plaintext.
func TestCertificateWithoutTLSFlagStillCountsAsTLS(t *testing.T) {
	h := host(t, `{"hosts":["tcp://0.0.0.0:2376"],"tlscert":"/etc/docker/cert.pem"}`,
		cleanGroup, cleanPasswd, 0o660)
	fs := h.check(t, env(hardenedInfo, "-H fd://"))
	mustFind(t, fs, "dockerd.api-tls-unverified")
	mustNotFind(t, fs, "dockerd.api-unauthenticated")
}

// An explicit --tlsverify=false is an opt-out, not a setting.
func TestExplicitTLSVerifyFalseIsNotVerified(t *testing.T) {
	h := host(t, "", cleanGroup, cleanPasswd, 0o660)
	fs := h.check(t, env(hardenedInfo, "-H tcp://0.0.0.0:2375 --tlsverify=false"))
	mustFind(t, fs, "dockerd.api-unauthenticated")
}

// Binding the API to loopback is the documented way to put a proxy in front
// of the daemon and reaches nothing the unix socket did not.
func TestLoopbackTCPIsNotAFinding(t *testing.T) {
	h := host(t, `{"hosts":["tcp://127.0.0.1:2375"]}`, cleanGroup, cleanPasswd, 0o660)
	fs := h.check(t, env(hardenedInfo, "-H fd://"))
	mustNotFind(t, fs, "dockerd.api-unauthenticated")
	mustNotFind(t, fs, "dockerd.api-tls-unverified")
}

func TestUnixAndFdSocketsAreNotEndpoints(t *testing.T) {
	h := host(t, `{"hosts":["unix:///var/run/docker.sock","fd://"]}`, cleanGroup, cleanPasswd, 0o660)
	fs := h.check(t, env(hardenedInfo, "-H fd://"))
	mustNotFind(t, fs, "dockerd.api-unauthenticated")
}

// ss sharpens the evidence but must never decide whether the finding exists.
func TestListenerCorroboratesEvidence(t *testing.T) {
	h := host(t, `{"hosts":["tcp://0.0.0.0:2375"]}`, cleanGroup, cleanPasswd, 0o660)
	e := env(hardenedInfo, "-H fd://")
	r := e.Runner.(fakeRunner)
	r.present["ss"] = true
	r.outputs["ss -tlnp"] = "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n" +
		`LISTEN 0      4096   0.0.0.0:2375        0.0.0.0:*         users:(("dockerd",pid=1,fd=3))` + "\n"
	e.Runner = r

	f := mustFind(t, h.check(t, e), "dockerd.api-unauthenticated")
	if got := f.Evidence["listening"]; got != "0.0.0.0:2375" {
		t.Errorf("listening evidence = %q, want the observed socket", got)
	}
}

func TestMissingSsIsNotPartial(t *testing.T) {
	h := host(t, `{"hosts":["tcp://0.0.0.0:2375"]}`, cleanGroup, cleanPasswd, 0o660)
	// env() never registers ss, so Listeners fails.
	fs, err := h.c.Check(context.Background(), env(hardenedInfo, "-H fd://"))
	if err != nil {
		t.Fatalf("a missing ss must not degrade the domain: %v", err)
	}
	f := mustFind(t, fs, "dockerd.api-unauthenticated")
	if _, ok := f.Evidence["listening"]; ok {
		t.Error("no listener evidence should be attached when ss is unavailable")
	}
}

// --- the socket -----------------------------------------------------------

func TestWorldWritableSocket(t *testing.T) {
	h := host(t, "", cleanGroup, cleanPasswd, 0o666)
	f := mustFind(t, h.check(t, env(hardenedInfo, "-H fd://")), "dockerd.socket-world-writable")
	if f.Severity != model.SeverityCritical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	if f.Evidence["mode"] != "0666" {
		t.Errorf("mode evidence = %q, want 0666", f.Evidence["mode"])
	}
}

func TestDefaultSocketModeIsClean(t *testing.T) {
	h := host(t, "", cleanGroup, cleanPasswd, 0o660)
	mustNotFind(t, h.check(t, env(hardenedInfo, "-H fd://")), "dockerd.socket-world-writable")
}

// Connecting to a unix socket requires write permission, so a world-readable
// socket grants nobody anything and flagging it would be noise.
func TestWorldReadableSocketIsNotAFinding(t *testing.T) {
	h := host(t, "", cleanGroup, cleanPasswd, 0o664)
	mustNotFind(t, h.check(t, env(hardenedInfo, "-H fd://")), "dockerd.socket-world-writable")
}

// A reachable daemon with no local socket is being reached over DOCKER_HOST.
// There is nothing to judge, which is not the same as failing to judge it.
func TestAbsentSocketIsNotPartial(t *testing.T) {
	h := host(t, "", cleanGroup, cleanPasswd, 0) // no socket created
	fs, err := h.c.Check(context.Background(), env(hardenedInfo, "-H fd://"))
	if err != nil {
		t.Fatalf("an absent socket must not degrade the domain: %v", err)
	}
	mustNotFind(t, fs, "dockerd.socket-world-writable")
	mustNotFind(t, fs, "dockerd.group-members")
}

// --- the group ------------------------------------------------------------

func TestGroupMembersAreMediumForHumans(t *testing.T) {
	h := host(t, "", "root:x:0:\ndocker:x:%GID%:alice\n",
		cleanPasswd+"alice:x:1000:2000::/home/alice:/bin/bash\n", 0o660)
	f := mustFind(t, h.check(t, env(hardenedInfo, "-H fd://")), "dockerd.group-members")
	if f.Severity != model.SeverityMedium {
		t.Errorf("severity = %v, want Medium for a human administrator", f.Severity)
	}
	if f.Evidence["members"] != "alice" {
		t.Errorf("members evidence = %q", f.Evidence["members"])
	}
}

// Nobody deliberately grants a CI runner the ability to become root, and a
// credential that never logs in is one nobody is watching.
func TestGroupMembersEscalateForServiceAccounts(t *testing.T) {
	h := host(t, "", "root:x:0:\ndocker:x:%GID%:alice,ci_runner\n",
		cleanPasswd+"alice:x:1000:2000::/home/alice:/bin/bash\nci_runner:x:997:997::/nonexistent:/usr/sbin/nologin\n", 0o660)
	f := mustFind(t, h.check(t, env(hardenedInfo, "-H fd://")), "dockerd.group-members")
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want High when a service account holds the group", f.Severity)
	}
	if !strings.Contains(f.Description, "ci_runner") {
		t.Errorf("description should name the service account: %q", f.Description)
	}
}

// A nologin shell above the system uid range is still a service identity.
func TestHighUIDNologinAccountIsAServiceAccount(t *testing.T) {
	h := host(t, "", "root:x:0:\ndocker:x:%GID%:runner\n",
		cleanPasswd+"runner:x:3000:3000::/srv/runner:/bin/false\n", 0o660)
	f := mustFind(t, h.check(t, env(hardenedInfo, "-H fd://")), "dockerd.group-members")
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want High", f.Severity)
	}
}

// An account added with `useradd -g docker` appears nowhere in the group's
// member list, only as a primary gid in passwd.
func TestPrimaryGIDCountsAsMembership(t *testing.T) {
	h := host(t, "", "root:x:0:\ndocker:x:%GID%:\n",
		cleanPasswd+"bob:x:1001:%GID%::/home/bob:/bin/bash\n", 0o660)
	f := mustFind(t, h.check(t, env(hardenedInfo, "-H fd://")), "dockerd.group-members")
	if f.Evidence["members"] != "bob" {
		t.Errorf("members evidence = %q, want the primary-group member", f.Evidence["members"])
	}
}

// The socket's group is whatever owns it, which daemon.json's "group" key can
// set to anything. Looking up "docker" by name would report a clean host in
// exactly the case worth catching.
func TestSocketGroupIsResolvedByGidNotByName(t *testing.T) {
	h := host(t, "", cleanGroup+"wheel:x:4242:carol\n",
		cleanPasswd+"carol:x:1000:2000::/home/carol:/bin/bash\n", 0o660)
	// Point the checker at a socket owned by gid 998 by rewriting what it
	// resolves: the fixture socket is owned by the test user's gid, so assert
	// the resolution path directly instead.
	if got := h.c.groupName(4242); got != "wheel" {
		t.Fatalf("groupName(4242) = %q, want wheel", got)
	}
	members, ok, _ := h.c.readMembers(4242)
	if !ok || len(members) != 1 || members[0].name != "carol" {
		t.Fatalf("readMembers(4242) = %v (ok=%v), want carol", members, ok)
	}
}

// root already holds this authority by every other route, so naming it here
// would be noise in a finding that is about everyone else.
func TestRootIsNotReportedAsAGroupMember(t *testing.T) {
	h := host(t, "", "root:x:0:\ndocker:x:%GID%:root\n", cleanPasswd, 0o660)
	mustNotFind(t, h.check(t, env(hardenedInfo, "-H fd://")), "dockerd.group-members")
}

// --- the daemon defaults --------------------------------------------------

func TestDaemonDefaultsFromDockerInfo(t *testing.T) {
	h := host(t, "", cleanGroup, cleanPasswd, 0o660)
	fs := h.check(t, env(bareInfo, "-H fd://"))
	for _, id := range []string{"dockerd.no-new-privileges", "dockerd.userns-remap", "dockerd.live-restore"} {
		mustFind(t, fs, id)
	}
}

func TestHardenedDaemonIsClean(t *testing.T) {
	h := host(t, "", cleanGroup, cleanPasswd, 0o660)
	fs := h.check(t, env(hardenedInfo, "-H fd://"))
	if len(fs) != 0 {
		t.Errorf("a correctly configured daemon should produce nothing; got %v", ids(fs))
	}
}

// live-restore is unsupported in swarm mode, so flagging it on a swarm node
// would be a guaranteed false positive.
func TestSwarmSuppressesLiveRestore(t *testing.T) {
	const swarm = `{"SecurityOptions":["name=no-new-privileges","name=userns"],"LiveRestoreEnabled":false,"Swarm":{"LocalNodeState":"active"}}`
	h := host(t, "", cleanGroup, cleanPasswd, 0o660)
	mustNotFind(t, h.check(t, env(swarm, "-H fd://")), "dockerd.live-restore")
}

// Rootless already gives every container a remapped uid, and its socket
// confers only that user's own containers rather than host root.
func TestRootlessSuppressesUsernsAndGroup(t *testing.T) {
	const rootless = `{"SecurityOptions":["name=rootless","name=no-new-privileges"],"LiveRestoreEnabled":true}`
	h := host(t, "", "root:x:0:\ndocker:x:%GID%:alice\n",
		cleanPasswd+"alice:x:1000:2000::/home/alice:/bin/bash\n", 0o660)
	fs := h.check(t, env(rootless, "-H fd://"))
	mustNotFind(t, fs, "dockerd.userns-remap")
	mustNotFind(t, fs, "dockerd.group-members")
}

func TestRootlessDowngradesTheAPIFinding(t *testing.T) {
	const rootless = `{"SecurityOptions":["name=rootless","name=no-new-privileges","name=userns"],"LiveRestoreEnabled":true}`
	h := host(t, `{"hosts":["tcp://0.0.0.0:2375"]}`, cleanGroup, cleanPasswd, 0o660)
	f := mustFind(t, h.check(t, env(rootless, "-H fd://")), "dockerd.api-unauthenticated")
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want High on a rootless daemon", f.Severity)
	}
}

// --- coverage -------------------------------------------------------------

// Losing `docker info` costs the three default-hardening rules and leaves the
// four socket and group rules genuinely answered — including two of the three
// Criticals. Reporting that as an outright error would discard them.
func TestDockerInfoFailureIsPartialNotFatal(t *testing.T) {
	h := host(t, `{"hosts":["tcp://0.0.0.0:2375"]}`, cleanGroup, cleanPasswd, 0o666)
	e := env(hardenedInfo, "-H fd://")
	r := e.Runner.(fakeRunner)
	delete(r.outputs, infoCmd)
	e.Runner = r

	fs, err := h.c.Check(context.Background(), e)
	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("err = %v, want a PartialError", err)
	}
	if partial.Covered != 4 || partial.Total != 7 {
		t.Errorf("coverage = %d/%d, want 4/7", partial.Covered, partial.Total)
	}
	// The findings that did run must survive the degradation.
	mustFind(t, fs, "dockerd.api-unauthenticated")
	mustFind(t, fs, "dockerd.socket-world-writable")
}

// An absent daemon.json is a complete answer — it means no options are set
// there, which is the default state of most hosts — not a failed read.
func TestAbsentDaemonJSONIsNotPartial(t *testing.T) {
	h := host(t, "", cleanGroup, cleanPasswd, 0o660)
	if _, err := h.c.Check(context.Background(), env(hardenedInfo, "-H fd://")); err != nil {
		t.Fatalf("an absent daemon.json must not degrade the domain: %v", err)
	}
}

// An unreadable daemon.json still leaves the unit, which carries both the
// socket flags and the TLS flags, so the two rules are answered.
func TestUnreadableDaemonJSONWithAUnitIsNotPartial(t *testing.T) {
	h := host(t, "", cleanGroup, cleanPasswd, 0o660)
	// A directory in the file's place fails with EISDIR regardless of uid.
	// CI runs some jobs as root, where a chmod 000 fixture would read fine
	// and the test would pass without exercising anything.
	if err := os.Mkdir(h.c.DaemonConfig, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := h.c.Check(context.Background(), env(hardenedInfo, "-H fd://")); err != nil {
		t.Fatalf("the unit covers what daemon.json would have: %v", err)
	}
}

func TestUnreadableDaemonJSONAndNoUnitIsPartial(t *testing.T) {
	h := host(t, "", cleanGroup, cleanPasswd, 0o660)
	if err := os.Mkdir(h.c.DaemonConfig, 0o755); err != nil {
		t.Fatal(err)
	}
	e := env(hardenedInfo, "") // no systemctl output registered
	_, err := h.c.Check(context.Background(), e)
	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("err = %v, want a PartialError", err)
	}
	if partial.Covered != 5 || partial.Total != 7 {
		t.Errorf("coverage = %d/%d, want 5/7", partial.Covered, partial.Total)
	}
}

func TestUnreadableGroupIsPartial(t *testing.T) {
	h := host(t, "", cleanGroup, cleanPasswd, 0o660)
	if err := os.Remove(h.c.GroupPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(h.c.GroupPath, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := h.c.Check(context.Background(), env(hardenedInfo, "-H fd://"))
	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("err = %v, want a PartialError", err)
	}
	if partial.Covered != 6 || partial.Total != 7 {
		t.Errorf("coverage = %d/%d, want 6/7", partial.Covered, partial.Total)
	}
}

// --- contract -------------------------------------------------------------

// A `docker` binary on PATH says nothing about whether this user may talk to
// the socket, and a domain that accepted that would score a perfect axis on
// exactly the host whose daemon nobody could examine.
func TestAvailableRequiresAReachableDaemon(t *testing.T) {
	r := fakeRunner{present: map[string]bool{"docker": true}} // no version output
	ok, reason := New().Available(context.Background(), platform.Env{Runner: r})
	if ok {
		t.Fatal("Available should be false when the daemon does not answer")
	}
	if !strings.Contains(reason, "docker group") && !strings.Contains(reason, "sudo") {
		t.Errorf("reason = %q, should tell the operator what to do", reason)
	}
}

func TestAvailableWhenDockerIsAbsent(t *testing.T) {
	ok, reason := New().Available(context.Background(), platform.Env{Runner: fakeRunner{}})
	if ok {
		t.Fatal("Available should be false with no Docker at all")
	}
	if reason == "" {
		t.Error("a skipped domain must say why")
	}
}

// Every finding must survive the engine's post-scan validation, carry this
// domain's source, and be namespaced by it — the Valid() upper bound in
// model.Source is a range check, and getting it wrong drops the whole domain
// silently.
func TestEveryFindingValidates(t *testing.T) {
	h := host(t, `{"hosts":["tcp://0.0.0.0:2375"]}`,
		"root:x:0:\ndocker:x:%GID%:alice\n",
		cleanPasswd+"alice:x:1000:2000::/home/alice:/bin/bash\n", 0o666)
	fs := h.check(t, env(bareInfo, "-H fd://"))
	if len(fs) == 0 {
		t.Fatal("expected findings from a thoroughly misconfigured daemon")
	}
	for _, f := range fs {
		if err := f.Validate(); err != nil {
			t.Errorf("%s: %v", f.ID, err)
		}
		if f.Source != model.SourceDockerd {
			t.Errorf("%s: source = %v, want SourceDockerd", f.ID, f.Source)
		}
		if !strings.HasPrefix(f.ID, "dockerd.") {
			t.Errorf("%s is not namespaced by its domain", f.ID)
		}
		if f.Remediation != model.RemediationManual {
			t.Errorf("%s: remediation = %v; every dockerd finding is Manual by decision", f.ID, f.Remediation)
		}
		if f.Description == "" || f.HowToFix == "" {
			t.Errorf("%s: a Manual finding is only as good as its prose", f.ID)
		}
	}
}

// Evidence assembled from a map iterates in a random order unless it is
// sorted, and unstable evidence makes every repeat scan report a delta
// nobody caused.
func TestEvidenceIsStableAcrossScans(t *testing.T) {
	h := host(t, `{"hosts":["tcp://0.0.0.0:2375","tcp://10.0.0.5:2376"]}`,
		"root:x:0:\ndocker:x:%GID%:zoe,alice,mallory\n",
		cleanPasswd+"alice:x:1000:2000::/home/alice:/bin/bash\nzoe:x:1002:2000::/home/zoe:/bin/bash\nmallory:x:1003:2000::/home/mallory:/bin/bash\n",
		0o660)
	first := fmt.Sprint(h.check(t, env(bareInfo, "-H fd://")))
	for i := range 5 {
		if got := fmt.Sprint(h.check(t, env(bareInfo, "-H fd://"))); got != first {
			t.Fatalf("scan %d differs from the first:\n%s\n%s", i+2, first, got)
		}
	}
}
