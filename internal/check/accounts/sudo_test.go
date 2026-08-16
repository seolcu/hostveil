package accounts

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/checktest"
	"github.com/seolcu/hostveil/internal/model"
)

// alicePasswd is the shape every test here starts from: root, a service
// account that cannot log in, and one ordinary user.
const aliceShadow = "root:$6$abc:19000:0:99999:7:::\nalice:$6$def:19000:0:99999:7:::\n"

func sudoChecker(t *testing.T) *Checker {
	t.Helper()
	return &Checker{
		PasswdPath: writeFile(t, "passwd", cleanPasswd),
		ShadowPath: writeFile(t, "shadow", aliceShadow),
	}
}

// The finding this domain gained, in the form the overwhelming majority of
// hosts carry it: a cloud or VM image that shipped NOPASSWD so the first login
// would work, still there years later.
func TestPasswordlessSudoIsFound(t *testing.T) {
	c := sudoChecker(t)
	fs, err := c.Check(context.Background(), withSudo(map[string]string{
		"root":  rootMayRunAnything,
		"alice": "User alice may run the following commands on host:\n    (ALL : ALL) NOPASSWD: ALL\n",
	}))
	if err != nil {
		t.Fatalf("nothing went unexamined here: %v", err)
	}
	if !has(fs, "accounts.sudo-nopasswd") {
		t.Fatalf("expected accounts.sudo-nopasswd, got %v", fs)
	}
	for _, f := range fs {
		if f.ID != "accounts.sudo-nopasswd" {
			continue
		}
		if f.Severity != model.SeverityMedium {
			t.Errorf("severity = %v, want medium: holding the account is the price of "+
				"entry, which is exactly what medium means", f.Severity)
		}
		if f.Evidence["accounts"] != "alice" {
			t.Errorf("evidence should name who, got %v", f.Evidence)
		}
	}
}

// The command spec is what separates a real finding from noise. A NOPASSWD
// rule on one named command is ordinary administration — a backup script, a
// monitoring hook — and it is a path to root only if that command happens to
// be exploitable, which nothing reading a config can decide. Flagging those
// would bury the unambiguous case under rules that are working as intended.
func TestNarrowNopasswdRuleIsNotAFinding(t *testing.T) {
	c := sudoChecker(t)
	fs, err := c.Check(context.Background(), withSudo(map[string]string{
		"root":  rootMayRunAnything,
		"alice": "User alice may run the following commands on host:\n    (root) NOPASSWD: /usr/bin/systemctl restart backup.service\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if has(fs, "accounts.sudo-nopasswd") {
		t.Errorf("a NOPASSWD rule on one command is not passwordless root, got %v", fs)
	}
}

// Within one privilege line NOPASSWD applies from where it appears until a
// later PASSWD turns the prompt back on. Reading the line as "contains
// NOPASSWD and contains ALL" — the obvious implementation — reports
// unrestricted passwordless root about a rule that asks for a password before
// doing anything unrestricted.
func TestPasswdTagLaterInTheLineTurnsThePromptBackOn(t *testing.T) {
	c := sudoChecker(t)
	fs, err := c.Check(context.Background(), withSudo(map[string]string{
		"root":  rootMayRunAnything,
		"alice": "User alice may run the following commands on host:\n    (ALL) NOPASSWD: /bin/ls, PASSWD: ALL\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if has(fs, "accounts.sudo-nopasswd") {
		t.Errorf("PASSWD: ALL restores the prompt for ALL; this host asks for a password, got %v", fs)
	}
}

// And the mirror: tags stack, so the command has to be read past all of them.
func TestStackedTagsStillReachTheCommand(t *testing.T) {
	c := sudoChecker(t)
	fs, err := c.Check(context.Background(), withSudo(map[string]string{
		"root":  rootMayRunAnything,
		"alice": "User alice may run the following commands on host:\n    (ALL : ALL) NOPASSWD: SETENV: ALL\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !has(fs, "accounts.sudo-nopasswd") {
		t.Errorf("NOPASSWD: SETENV: ALL is unrestricted passwordless root, got %v", fs)
	}
}

// Defaults !authenticate turns the password off for every rule on the host,
// and the privilege lines below it carry no tag saying so. A checker reading
// only the tags calls this host clean while it is the most passwordless
// arrangement sudoers can express — a false negative about something plainly
// visible, which is the failure this domain exists to avoid.
func TestGlobalNoAuthenticateIsFound(t *testing.T) {
	c := sudoChecker(t)
	fs, err := c.Check(context.Background(), withSudo(map[string]string{
		"root": rootMayRunAnything,
		"alice": "Matching Defaults entries for alice on host:\n    env_reset, !authenticate\n\n" +
			"User alice may run the following commands on host:\n    (ALL : ALL) ALL\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !has(fs, "accounts.sudo-nopasswd") {
		t.Errorf("Defaults !authenticate is passwordless sudo with no tag to read, got %v", fs)
	}
}

// root running anything without a password grants root nothing it did not
// already have. Reporting it would put a finding on every host that has sudo
// installed, which is every host — and an account that is root under another
// name is accounts.uid0's finding.
func TestRootIsNotReportedAsItsOwnRisk(t *testing.T) {
	c := sudoChecker(t)
	fs, err := c.Check(context.Background(), withSudo(map[string]string{
		"root":  "User root may run the following commands on host:\n    (ALL : ALL) NOPASSWD: ALL\n",
		"alice": "User alice may run the following commands on host:\n    (ALL) ALL\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if has(fs, "accounts.sudo-nopasswd") {
		t.Errorf("root's own NOPASSWD rule is not a finding, got %v", fs)
	}
}

// The one that matters most, and the reason for the control run.
//
// `sudo -l -U alice` exits non-zero both for an account with no sudo rights —
// the ordinary case — and for "a non-root user cannot use -U". Without the
// control run the second reads as the first, and a non-root scan reports that
// nobody on the host can become root without a password, having never been
// allowed to ask. That is "I couldn't look" scoring as "nothing there", which
// is the same lie that once produced a perfect CVE score on an unscanned host.
func TestNonRootScanReportsAGapRatherThanAClean(t *testing.T) {
	c := sudoChecker(t)
	denied := checktest.New().
		Fail(errors.New("sudo: a password is required"), sudoListArgv("root")...).
		Fail(errors.New("sudo: a password is required"), sudoListArgv("alice")...).
		Env()

	fs, err := c.Check(context.Background(), denied)

	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("a scan that was refused the question must degrade the domain, got %v", err)
	}
	if !strings.Contains(partial.Reason, "without a password") {
		t.Errorf("the reason must name what went unchecked, got %q", partial.Reason)
	}
	if has(fs, "accounts.sudo-nopasswd") {
		t.Errorf("nothing was learned, so nothing may be claimed, got %v", fs)
	}
}

// An account with no sudo rights at all is the ordinary case and must not
// degrade anything: the control run succeeded, so the failure below it is an
// answer rather than a refusal.
func TestAccountWithNoSudoRightsIsCleanNotDegraded(t *testing.T) {
	c := sudoChecker(t)
	env := checktest.New().
		Script(rootMayRunAnything, sudoListArgv("root")...).
		Fail(errors.New("User alice is not allowed to run sudo on host."), sudoListArgv("alice")...).
		Env()

	fs, err := c.Check(context.Background(), env)
	if err != nil {
		t.Fatalf("the question was asked and answered; nothing is missing: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("no sudo rights is not a finding, got %v", fs)
	}
}

// A host with no sudo binary has an answer, not a gap: no sudo rule can be
// granting anyone anything. Calling it a gap would mark every sudo-less host
// Degraded — the direction dockerd's config merge got wrong, where an absent
// file was treated as a blind spot rather than as a complete answer about
// that file.
func TestNoSudoInstalledIsAnAnswerNotAGap(t *testing.T) {
	c := sudoChecker(t)
	fs, err := c.Check(context.Background(), noSudo())
	if err != nil {
		t.Fatalf("no sudo installed means no sudo rule; that is covered, got %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("got %v", fs)
	}
}

// Two blind spots at once, which is the ordinary non-root scan: /etc/shadow
// unreadable and sudo refusing to answer. Keeping one and discarding the other
// is what check.Coverage exists to prevent, and both container checkers did it
// before it existed.
func TestBothGapsAreReportedTogether(t *testing.T) {
	c := &Checker{
		PasswdPath: writeFile(t, "passwd", cleanPasswd),
		ShadowPath: writeFile(t, "shadow-missing", "") + ".nope",
	}
	denied := checktest.New().
		Fail(errors.New("sudo: a password is required"), sudoListArgv("root")...).
		Env()

	_, err := c.Check(context.Background(), denied)
	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("want a PartialError, got %v", err)
	}
	for _, want := range []string{"empty password", "without a password"} {
		if !strings.Contains(partial.Reason, want) {
			t.Errorf("the reason keeps one gap and drops the other; %q is missing from %q", want, partial.Reason)
		}
	}
	if partial.Covered != 1 || partial.Total != 3 {
		t.Errorf("coverage = %d/%d, want 1/3 — the counters have to say how much went "+
			"unexamined, not just that something did", partial.Covered, partial.Total)
	}
}

// A non-login account cannot use sudo interactively and is not what this
// finding is about; asking about every /etc/passwd entry on a host with two
// hundred service accounts is also two hundred subprocesses.
func TestNonLoginAccountsAreNotAsked(t *testing.T) {
	c := sudoChecker(t)
	// daemon is in cleanPasswd with /usr/sbin/nologin. Only root and alice are
	// scripted, so an ask about daemon would fall through to the fake's
	// unscripted-command error and simply return no finding — which is why the
	// assertion is on the finding for daemon, not on the error.
	fs, err := c.Check(context.Background(), withSudo(map[string]string{
		"root":   rootMayRunAnything,
		"alice":  "User alice may run the following commands on host:\n    (ALL) ALL\n",
		"daemon": "User daemon may run the following commands on host:\n    (ALL : ALL) NOPASSWD: ALL\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if has(fs, "accounts.sudo-nopasswd") {
		t.Errorf("a nologin account's sudo rule is not a login risk, got %v", fs)
	}
}
