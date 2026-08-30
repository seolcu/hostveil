package fix

import (
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix/fixtest"
	"github.com/seolcu/hostveil/internal/model"
)

// representative builds a finding with the metadata/evidence each fix
// builder needs, so the registry can be exercised without a live scan.
//
// It lives in fixtest rather than here because cmd/sitegen needs the same
// thing: pinning the docs' Fix column against what a user is offered means
// building the fix, and building it means having a finding to build from.
func representative(id string) model.Finding { return fixtest.Finding(id) }

// TestEveryRegisteredFixIsValid builds each registered fix from a
// representative finding and asserts it passes Validate — Auto has exactly
// one action, Review has independent alternatives, every edit has a
// Transform, every exec has commands.
// It enumerates the registry itself rather than a hand-kept list, so a new
// registration cannot slip in unvalidated.
func TestEveryRegisteredFixIsValid(t *testing.T) {
	r := Default()
	for _, id := range r.Patterns() {
		// A glob has no single representative finding to build from, so it
		// would silently skip this test's coverage. Nothing registers one
		// today, and the CVE decision depends on that staying true: a
		// "cve.*" pattern would sweep up every per-CVE finding the registry
		// deliberately declines. Make introducing one a visible act.
		if strings.ContainsAny(id, "*?") {
			t.Errorf("glob pattern %q has no representative finding; register an exact ID, or extend this test deliberately", id)
			continue
		}
		f := representative(id)
		fx, ok, err := r.Build(f)
		if err != nil {
			t.Errorf("%s: build error: %v", id, err)
			continue
		}
		if !ok {
			t.Errorf("%s: no fix registered", id)
			continue
		}
		if err := Validate(fx); err != nil {
			t.Errorf("%s: %v", id, err)
		}
		if !fx.Kind.IsFixable() {
			t.Errorf("%s: kind %v is not fixable", id, fx.Kind)
		}
	}
}

func TestRootLoginIsReviewWithAlternatives(t *testing.T) {
	fx, ok, err := Default().Build(representative("ssh.rootlogin"))
	if err != nil || !ok {
		t.Fatalf("build: ok=%v err=%v", ok, err)
	}
	if fx.Kind != model.RemediationReview {
		t.Errorf("rootlogin kind = %v, want Review", fx.Kind)
	}
	if len(fx.Actions) < 2 {
		t.Errorf("review fix should have >= 2 alternatives, has %d", len(fx.Actions))
	}
}

func TestUnregisteredFindingHasNoFix(t *testing.T) {
	_, ok, _ := Default().Build(representative("compose.ds001")) // privileged: Manual, no fix
	if ok {
		t.Error("ds001 should have no registered fix")
	}
}

// TestKnownUnregisteredFindings pins the findings that are fixable in
// principle but deliberately have no builder, each for a reason recorded
// in Default's doc comment. Registering one of these means deleting an
// assertion here, which is the point: the decision should be argued with,
// not quietly reversed.
func TestKnownUnregisteredFindings(t *testing.T) {
	declined := map[string]string{
		"firewall.docker-bypass":  "republishing to loopback means editing an unknown compose file and recreating the container; the ufw-docker alternative is firewall policy with no rollback",
		"updates.reboot-required": "rebooting is exec with no checkpoint and takes every service down; only the operator knows when that is acceptable",
		"ports.exposed-datastore": "the remediation is a bind-address edit in a daemon config whose path and syntax the finding does not carry",
		"ports.exposed-admin":     "same as ports.exposed-datastore",
		"compose.ds016":           "the only honest remediation deletes a mount that Portainer/Traefik/Watchtower legitimately need; :ro is a placebo",
		// The checker no longer emits per-CVE findings at all — they were
		// aggregated into cve.outdated-image / cve.unpatched-image. The pin
		// stays as a guard: a cve.* glob would make this shape fixable again
		// if anyone reintroduced it. The lowercased form is what vulnFinding
		// used to build; the mixed-case entry that lived here before matched
		// nothing and passed vacuously.
		"cve.cve-2021-1234":   "Trivy's fixed_version is an OS package version, not an image tag — see issue #473",
		"cve.unpatched-image": "collects exactly the vulnerabilities with no published fix; there is nothing to update to",
		"compose.ds009":       "the finding carries no evidence about which UID the image supports, and every candidate is a guess",
		"compose.ds017":       ":ro is the only computable remediation, and Review requires two alternatives",
		"compose.ds001":       "removal-shaped: hostveil cannot tell a needless privileged flag from a load-bearing one",
		"compose.ds005":       "removal-shaped: same, for cap_add",
		"compose.dr001":       "removing host networking without knowing which ports to publish leaves the service unreachable",
		"compose.ds020":       "removal-shaped: a monitoring agent legitimately needs the host PID namespace, and hostveil cannot tell that from a cargo-culted one",
		"compose.ds021":       "removal-shaped: deliberate host-IPC sharing breaks silently when the line is deleted",
		"compose.ds022":       "read_only: true breaks any image that writes to its own filesystem, and the audit cannot infer the tmpfs mounts that would make it safe",
		"compose.ds023":       "removing a seccomp exception can break a workload that needs the syscall",
		"compose.ds024":       "hostveil cannot invent an application-specific AppArmor profile",
		"compose.ds026":       "changing user namespace mode can invalidate bind-mount ownership",
		"compose.dr005":       "a two-file change where Action carries one Path, and the real remediation is rotating the leaked secret",

		// The agent.* config-key findings that internal/json5 did NOT
		// unblock. The editor removed one shared obstacle — re-encoding a
		// JSON5 config deleted the operator's comments — and what is left
		// here is what that obstacle was hiding, which is different for each
		// of the three.
		"agent.gateway-exposed": "rebinding a gateway to loopback can cut the operator off from the agent they administer remotely",
		"agent.auth-disabled":   "nothing in hostveil knows which auth mode to write, and the safe posture is an absent key, which the editor deliberately cannot produce",
		"agent.sandbox-off":     "hostveil knows `off` is wrong and does not know what turns the sandbox on; writing a guessed enum is the invented mapping the CVE fixes are declined for",

		// sysctl.* was on this list and is not any more. The reason it gave
		// — that the drop-in does not exist and an edit action cannot create
		// a file — stopped being true when Action grew CreateIfMissing, and
		// the reason outlived it here by one release. If a fix is registered
		// for something this map names, the loop below fails; nothing catches
		// a stale *comment*, so it is written down as history rather than
		// deleted, and register.go carries the argument.

		// Every dockerd.* finding, one shared reason: the checker reads the
		// running daemon's state while a fix would edit a file the daemon
		// does not re-read until a restart that stops every container — so
		// the fix would mark the finding Fixed and change nothing the next
		// scan can see.
		"dockerd.api-unauthenticated":   "removing the TCP endpoint severs the channel a remote operator may be administering the host through",
		"dockerd.api-tls-unverified":    "same as dockerd.api-unauthenticated",
		"dockerd.socket-world-writable": "the socket's mode is recreated from the systemd unit at every restart, so a chmod does not persist",
		"dockerd.group-members":         "a service account in the group is as likely a deliberate integration (Portainer, Watchtower, CI) as a forgotten grant, and the evidence cannot tell them apart",
		"dockerd.no-new-privileges":     "a daemon default that takes effect only for containers started after a restart",
		"dockerd.userns-remap":          "same, and it rewrites the ownership of every bind mount on the host",
		"dockerd.live-restore":          "reload is exec with no checkpoint, and write-then-apply is sequential steps rather than Review's independent alternatives",

		"fileperms.owner":                   "chown has no checkpoint — a rollback records contents and mode and has nowhere to put the previous owner; and the right group differs by distribution",
		"compose.ds012":                     "the right healthcheck depends on what the service exposes; a guessed one marks a working container unhealthy and stalls everything waiting on it",
		"compose.dr004":                     "the remediation is about the env_file's permissions and whether it is in git and backups — nothing in the compose file to edit",
		"ports.exposed":                     "the aggregate says N services are exposed; the per-service findings carry the fixable detail, and a firewall is firewall.inactive's fix rather than this one's",
		"accounts.uid0":                     "userdel is exec, irreversible, and takes the home directory with it; hostveil cannot tell a backdoor from a deliberate second root",
		"accounts.duplicate-uid":            "UID migration spans every file the account owns and is not one reversible action",
		"accounts.weak-password-hash":       "a password reset requires a human-chosen credential",
		"accounts.sudo-nopasswd":            "the grant comes from sudo -l, not from reading /etc/sudoers, so nothing says which file, line, or group rule to edit",
		"systemd.private-devices":           "device access may be load-bearing",
		"systemd.protect-kernel-tunables":   "network managers may require kernel tunables",
		"systemd.protect-control-groups":    "container managers may require cgroup access",
		"systemd.restrict-namespaces":       "container runtimes require namespaces",
		"systemd.memory-deny-write-execute": "JIT runtimes require writable executable memory",
	}
	r := Default()
	for id, why := range declined {
		if r.Has(id) {
			t.Errorf("%s has a registered fix, but is documented as deliberately unfixed: %s", id, why)
		}
	}
}

// TestCVERollupIsFixableButPerCVEIsNot asserts both halves of the CVE
// decision at once, which is the point of having it in one test: a "cve.*"
// glob would satisfy the first assertion and break the second. Per-CVE
// findings stay unfixable because a package version is not an image tag;
// the per-image rollup is fixable because re-pulling a mutable tag needs no
// version mapping at all.
func TestCVERollupIsFixableButPerCVEIsNot(t *testing.T) {
	r := Default()
	if !r.Has("cve.outdated-image") {
		t.Error("the per-image rollup should have a registered fix")
	}
	for _, id := range []string{"cve.cve-2021-1234", "cve.cve-2024-9999"} {
		if r.Has(id) {
			t.Errorf("%s matched a fix; a per-CVE finding must never resolve to one", id)
		}
	}
}

// TestReviewIntentSurvivesAnAutoShapedFix guards the rule that a fix
// registered as Auto describes the fix's shape (one mechanical action) and
// does not overrule a checker that asked for Review. ssh.passwordauth is
// the case that matters: the edit is reversible on disk, but a user
// without a working key loses the session and cannot get back in to roll
// it back, so it must never be swept up by "fix all safe".
func TestReviewIntentSurvivesAnAutoShapedFix(t *testing.T) {
	for _, id := range []string{"ssh.passwordauth", "updates.disabled"} {
		fx, ok, err := Default().Build(representative(id))
		if err != nil || !ok {
			t.Fatalf("%s: build: ok=%v err=%v", id, ok, err)
		}
		// The registry may shape these as Auto; Engine.classify is what holds
		// them at Review. This asserts the registry stays buildable so that
		// resolution has something to work with.
		if !fx.Kind.IsFixable() {
			t.Errorf("%s: kind %v is not fixable", id, fx.Kind)
		}
	}
}

// The two alternatives must be independent choices, not two halves of one
// procedure: action 1 is the zero-downtime option for anyone who cannot
// take an unplanned restart, at the cost of not remediating yet.
func TestRepullFixHasTwoIndependentAlternatives(t *testing.T) {
	fx, ok, err := Default().Build(representative("cve.outdated-image"))
	if err != nil || !ok {
		t.Fatalf("build: ok=%v err=%v", ok, err)
	}
	if fx.Kind != model.RemediationReview {
		t.Errorf("kind = %v, want Review — exec fixes are never Auto", fx.Kind)
	}
	if len(fx.Actions) != 2 {
		t.Fatalf("expected 2 alternatives, got %d", len(fx.Actions))
	}
	if len(fx.Actions[0].Commands) != 2 {
		t.Errorf("pull-and-recreate should be one action of 2 commands, got %d", len(fx.Actions[0].Commands))
	}
	if len(fx.Actions[1].Commands) != 1 {
		t.Errorf("pull-only should be a single command, got %d", len(fx.Actions[1].Commands))
	}
	for i, a := range fx.Actions {
		if a.Kind != ActionExec {
			t.Errorf("action %d is not an exec", i)
		}
		// Exec fixes have no checkpoint; the preview is the only place a
		// user learns that before committing to it.
		if !strings.Contains(a.Warning, "no rollback checkpoint") {
			t.Errorf("action %d warning does not mention the absence of rollback: %q", i, a.Warning)
		}
	}
}

// applyExec runs argv with no shell and no working directory, so a bare
// "docker compose" would resolve against whatever cwd the daemon happened
// to have. Pin the -f.
func TestRepullFixTargetsTheComposeFile(t *testing.T) {
	f := representative("cve.outdated-image")
	fx, _, err := Default().Build(f)
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range fx.Actions {
		for j, cmd := range a.Commands {
			idx := slices.Index(cmd, "-f")
			if idx < 0 || idx+1 >= len(cmd) {
				t.Errorf("action %d command %d has no -f: %v", i, j, cmd)
				continue
			}
			if cmd[idx+1] != f.Metadata["file"] {
				t.Errorf("action %d command %d targets %q, want %q", i, j, cmd[idx+1], f.Metadata["file"])
			}
			// The unqualified name, as written in the compose file — never
			// the project-qualified f.Service.
			if cmd[len(cmd)-1] != f.Metadata["service"] {
				t.Errorf("action %d command %d does not end with the bare service: %v", i, j, cmd)
			}
		}
	}
}

// CVE image findings qualify Service with the compose project so two
// projects' same-named services stay distinct in Key(). The docker command
// must still use the bare name from the compose file.
func TestRepullUsesTheUnqualifiedServiceName(t *testing.T) {
	f := model.NewFinding("cve.outdated-image", "t", model.SeverityHigh,
		model.SourceCVE, model.RemediationReview,
		model.WithService("cloud/db"),
		model.WithMetadata("file", "/opt/cloud/docker-compose.yml"),
		model.WithMetadata("service", "db"),
		model.WithEvidence("reference", "tag"),
		model.WithEvidence("paths", "/etc/shadow"),
		model.WithEvidence("expected", "0640"),
	)
	fx, ok, err := Default().Build(f)
	if err != nil || !ok {
		t.Fatalf("build: ok=%v err=%v", ok, err)
	}
	for i, a := range fx.Actions {
		for j, cmd := range a.Commands {
			if last := cmd[len(cmd)-1]; last != "db" {
				t.Errorf("action %d command %d targets %q, want the bare db", i, j, last)
			}
		}
	}
}

// A pull on a digest is a no-op by construction. The builder refuses, and a
// build error is how classify learns there is no fix.
func TestRepullRefusesDigestPinnedImages(t *testing.T) {
	f := model.NewFinding("cve.outdated-image", "t", model.SeverityHigh,
		model.SourceCVE, model.RemediationManual,
		model.WithService("app"),
		model.WithMetadata("file", "/tmp/docker-compose.yml"),
		model.WithMetadata("service", "app"),
		model.WithEvidence("reference", "digest"),
	)
	if _, _, err := Default().Build(f); err == nil {
		t.Error("expected a build error for a digest-pinned image")
	}
}

func TestMemLimitFixOffersSeveralValues(t *testing.T) {
	fx, ok, err := Default().Build(representative("compose.ds010"))
	if err != nil || !ok {
		t.Fatalf("build: ok=%v err=%v", ok, err)
	}
	if fx.Kind != model.RemediationReview {
		t.Errorf("kind = %v, want Review", fx.Kind)
	}
	if len(fx.Actions) < 2 {
		t.Fatalf("expected >= 2 alternatives, got %d", len(fx.Actions))
	}
	in := []byte("services:\n  app:\n    image: myapp\n")
	seen := map[string]bool{}
	for i, a := range fx.Actions {
		out, err := a.Transform(in)
		if err != nil {
			t.Fatalf("action %d: %v", i, err)
		}
		if !strings.Contains(string(out), "mem_limit") {
			t.Errorf("action %d did not set mem_limit: %s", i, out)
		}
		// Each alternative must be a distinct choice, not the same edit
		// relabelled — the loop variable capture bug this guards is easy to
		// reintroduce.
		if seen[string(out)] {
			t.Errorf("action %d produced an output identical to an earlier alternative", i)
		}
		seen[string(out)] = true

		if again, _ := a.Transform(in); string(again) != string(out) {
			t.Errorf("action %d transform is not deterministic", i)
		}
	}
}

func TestExecFixTransformsPure(t *testing.T) {
	// An edit fix's Transform must not touch disk when called; verify it is
	// a pure byte transform.
	fx, _, err := Default().Build(representative("compose.ds006"))
	if err != nil {
		t.Fatal(err)
	}
	in := []byte("services:\n  app:\n    image: myapp\n")
	out, err := fx.Actions[0].Transform(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) == string(in) {
		t.Error("transform made no change")
	}
	// Calling again on the same input is deterministic.
	out2, _ := fx.Actions[0].Transform(in)
	if string(out) != string(out2) {
		t.Error("transform is not deterministic")
	}
}

// The property that makes this fix safe to apply unattended: it only ever
// removes permission bits. Assigning the rule's MaxMode outright would GRANT
// access — /etc/shadow at 0604 violates a 0640 rule, and setting it to 0640
// hands the shadow group a read bit the file never had.
func TestTightenOnlyRemovesBits(t *testing.T) {
	cases := []struct {
		current, mask, want fs.FileMode
		why                 string
	}{
		{0o666, 0o644, 0o644, "world-writable stripped to the rule"},
		{0o644, 0o640, 0o640, "other-read stripped"},
		{0o604, 0o640, 0o600, "must NOT become 0640 — that would grant group read"},
		{0o600, 0o640, 0o600, "already stricter than the rule is left alone"},
		{0o400, 0o644, 0o400, "stricter in every bit, untouched"},
	}
	for _, c := range cases {
		if got := tighten(c.current, c.mask); got != c.want {
			t.Errorf("tighten(%#o, %#o) = %#o, want %#o — %s", c.current, c.mask, got, c.want, c.why)
		}
		// Whatever the inputs, no bit may appear that was not already set.
		if got := tighten(c.current, c.mask); got&^c.current != 0 {
			t.Errorf("tighten(%#o, %#o) = %#o added bits %#o", c.current, c.mask, got, got&^c.current)
		}
	}
}

// Perm() is only the low nine bits, so rebuilding a mode from it alone would
// silently clear setuid/setgid/sticky. The checker judged the file on its
// permission bits; those are the only bits this fix may touch.
func TestTightenPreservesSpecialBits(t *testing.T) {
	got := tighten(fs.ModeSetuid|fs.ModeSticky|0o666, 0o644)
	if got&fs.ModeSetuid == 0 || got&fs.ModeSticky == 0 {
		t.Errorf("tighten dropped special bits: %v", got)
	}
	if got.Perm() != 0o644 {
		t.Errorf("perm = %#o, want 0644", got.Perm())
	}
}

// ModeDir must survive too. planModes compares tighten's result against the
// full fs.FileMode, so dropping the type bit makes an already-compliant
// directory compare unequal to itself: preview prints a phantom 0700 → 0700
// row and apply checkpoints and chmods a directory that needed nothing.
func TestTightenPreservesModeDir(t *testing.T) {
	if got := tighten(fs.ModeDir|0o777, 0o700); got != fs.ModeDir|0o700 {
		t.Errorf("tighten(d0777, 0700) = %v, want d0700", got)
	}
	// The identity that planModes depends on: a compliant directory is a
	// fixed point, so it produces no change at all.
	compliant := fs.ModeDir | 0o700
	if got := tighten(compliant, 0o700); got != compliant {
		t.Errorf("tighten(%v, 0700) = %v, want it unchanged", compliant, got)
	}
}

func TestFilePermsFixIsAutoAndModeShaped(t *testing.T) {
	f := model.NewFinding("fileperms.hostkey", "t", model.SeverityHigh,
		model.SourceFilePerms, model.RemediationAuto,
		model.WithEvidence("paths", strings.Join(
			[]string{"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ed25519_key"},
			model.PathListSeparator)),
		model.WithEvidence("expected", "0640"),
	)
	fx, ok, err := Default().Build(f)
	if err != nil || !ok {
		t.Fatalf("build: ok=%v err=%v", ok, err)
	}
	if fx.Kind != model.RemediationAuto {
		t.Errorf("kind = %v, want Auto", fx.Kind)
	}
	if err := Validate(fx); err != nil {
		t.Fatal(err)
	}
	a := fx.Actions[0]
	if a.Kind != ActionMode {
		t.Fatalf("action kind = %v, want ActionMode", a.Kind)
	}
	// A glob rule covers several files, and an Auto fix gets exactly one
	// action — so the one action has to carry them all.
	if len(a.Paths) != 2 {
		t.Errorf("paths = %v, want both host keys", a.Paths)
	}
	if got := a.Mode(0o644); got != 0o640 {
		t.Errorf("Mode(0644) = %#o, want 0640", got)
	}
}

func TestFilePermsFixRefusesIncompleteEvidence(t *testing.T) {
	for _, ev := range []map[string]string{
		{"expected": "0640"},     // no paths
		{"paths": "/etc/shadow"}, // no expected mode
		{"paths": "/etc/shadow", "expected": "not-a-mode"},
	} {
		f := model.NewFinding("fileperms.shadow", "t", model.SeverityHigh,
			model.SourceFilePerms, model.RemediationAuto)
		for k, v := range ev {
			model.WithEvidence(k, v)(&f)
		}
		if _, _, err := Default().Build(f); err == nil {
			t.Errorf("expected a build error for evidence %v", ev)
		}
	}
}

// A path may contain ", ". The human-readable "files" evidence and the
// machine-readable "paths" evidence used to share that separator, so a
// directory like "logs, old" split into two paths that do not exist. It
// failed safe — planModes aborts the whole fix when a path is missing — but
// it failed, on a fix that should have worked, for a reason invisible in the
// output.
func TestFilePermsFixHandlesPathsContainingTheHumanSeparator(t *testing.T) {
	want := []string{"/home/me/logs, old/config.json", "/etc/plain"}
	f := model.NewFinding("fileperms.shadow", "t", model.SeverityHigh,
		model.SourceFilePerms, model.RemediationAuto,
		model.WithEvidence("paths", strings.Join(want, model.PathListSeparator)),
		model.WithEvidence("expected", "0600"),
	)

	fx, ok, err := Default().Build(f)
	if err != nil || !ok {
		t.Fatalf("build: ok=%v err=%v", ok, err)
	}
	got := fx.Actions[0].Paths
	if len(got) != len(want) {
		t.Fatalf("paths = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("path %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// buildRepullImage's Benefit must not promise more than a re-pulled floating
// tag can actually deliver: re-resolving the tag *may* pick up a fix for the
// CVE that triggered the finding, but hostveil has no way to confirm it did,
// since the same tag can move for unrelated reasons too. This mirrors
// internal/check/cve's own HowToFix, which carries the identical caveat —
// and it is the property the whole feature exists to state honestly, per the
// user's original example: fast patches are attractive on a self-hosted box
// and risky on a stable one, and a Benefit that oversold "this fixes it"
// would hide the second half of that trade-off.
func TestOutdatedImageBenefitDoesNotOverpromise(t *testing.T) {
	fx, ok, err := Default().Build(representative("cve.outdated-image"))
	if err != nil || !ok {
		t.Fatalf("build: ok=%v err=%v", ok, err)
	}
	if len(fx.Actions) != 2 {
		t.Fatalf("cve.outdated-image has %d actions, want 2", len(fx.Actions))
	}

	pullNow := fx.Actions[0].Benefit
	if !strings.Contains(pullNow, "may") {
		t.Errorf("action 0's Benefit does not use non-guarantee language: %q", pullNow)
	}
	if strings.Contains(pullNow, "will fix") || strings.Contains(pullNow, "fixes the") {
		t.Errorf("action 0's Benefit oversells the fix as guaranteed: %q", pullNow)
	}

	downloadOnly := fx.Actions[1].Benefit
	if !strings.Contains(downloadOnly, "before deciding") && !strings.Contains(downloadOnly, "inspect") {
		t.Errorf("action 1's Benefit does not explain it lets the operator inspect before committing: %q", downloadOnly)
	}
}
