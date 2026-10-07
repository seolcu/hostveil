package fix

import (
	"fmt"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// registerHostRisky wires the host findings that were declined because their
// remediation is an exec action with consequences a checker cannot weigh —
// rebooting the host, disabling an account that might be load-bearing. Each
// is Review because it is exec, and IndividualOnly because the consequence
// is the operator's to accept, not a batch's.
func registerHostRisky(r *Registry) {
	r.Register("updates.reboot-required", buildScheduleReboot)
	r.Register("accounts.uid0", buildDisableRogueRoot)
	r.Register("accounts.weak-password-hash", buildExpireWeakPassword)
}

// rebootDelay is how long `shutdown -r` waits. Long enough for hostveil to
// finish recording the fix and for the operator to read the result on the
// session the reboot is about to drop; short enough that "later" does not
// turn into "never". `shutdown -c` cancels it in that window.
const rebootDelay = "+1"

func buildScheduleReboot(model.Finding) (Fix, error) {
	return Fix{
		Label:          "Reboot the host to load the installed updates",
		Kind:           model.RemediationReview,
		IndividualOnly: true,
		Actions: []Action{{
			Label: "Reboot in one minute (`shutdown -r " + rebootDelay + "`)",
			Benefit: "The host starts running the patched kernel and libraries it already has on disk, " +
				"which is the only way the vulnerabilities those updates fixed actually stop applying to it.",
			Warning: "Every service on this host goes down until the machine is back, and this session " +
				"is disconnected. Services without a restart policy, and anything started by hand, stay " +
				"down after the boot. If the new kernel fails to boot, getting the machine back needs " +
				"console access. Run `shutdown -c` within the minute to cancel. There is no checkpoint: " +
				"a reboot cannot be rolled back.",
			Kind:          ActionExec,
			Commands:      [][]string{{"shutdown", "-r", rebootDelay, "hostveil: rebooting to load installed security updates"}},
			TakesEffectOn: "the reboot, one minute after this is applied",
		}},
	}, nil
}

// firstAccount is the first of a comma-separated "accounts" evidence list.
// These fixes act on one account at a time, like accounts.emptypassword's:
// the blast radius of one button is one account, and the rest are reported
// again on the next scan.
func firstAccount(f model.Finding) (string, error) {
	account, _, _ := strings.Cut(f.Evidence["accounts"], ", ")
	if account == "" {
		return "", fmt.Errorf("finding %s names no accounts", f.ID)
	}
	return account, nil
}

func buildDisableRogueRoot(f model.Finding) (Fix, error) {
	account, err := firstAccount(f)
	if err != nil {
		return Fix{}, err
	}
	noCheckpoint := "There is no checkpoint: exec fixes are not file-backed, so Hostveil cannot undo this."
	return Fix{
		Label:          "Disable the UID-0 account " + account,
		Kind:           model.RemediationReview,
		IndividualOnly: true,
		Actions: []Action{
			{
				Label: "Lock and expire " + account + " (`usermod --lock --expiredate 1`)",
				Benefit: "The account can no longer log in by any route — password, SSH key or su — so a " +
					"backdoor planted under it stops working, while the entry, its files and its history " +
					"stay in place for you to investigate.",
				Warning: "If something on this host deliberately logs in as " + account + " — a recovery " +
					"procedure, a monitoring agent, a second admin name for root — it stops working. " +
					noCheckpoint + " To reverse it: `usermod --unlock --expiredate '' " + account + "`.",
				Kind:     ActionExec,
				Commands: [][]string{{"usermod", "--lock", "--expiredate", "1", account}},
			},
			{
				Label: "Delete " + account + " (`userdel`), keeping its home directory",
				Benefit: "Removes the second root entirely, so nothing about it can be re-enabled later " +
					"by someone who knows it is there.",
				Warning: "This cannot be undone: the account entry, its group and its mail spool are gone, " +
					"and every file it owned is left owned by UID 0 with nothing recording that it was " + account +
					"'s. Prefer locking first if you have not yet worked out how the account got there. " + noCheckpoint,
				Kind:     ActionExec,
				Commands: [][]string{{"userdel", account}},
			},
		},
	}, nil
}

func buildExpireWeakPassword(f model.Finding) (Fix, error) {
	account, err := firstAccount(f)
	if err != nil {
		return Fix{}, err
	}
	return Fix{
		Label:          "Force " + account + " to choose a new password",
		Kind:           model.RemediationReview,
		IndividualOnly: true,
		Actions: []Action{{
			Label: "Expire " + account + "'s password (`passwd --expire`)",
			Benefit: "At the next login " + account + " has to set a new password, which is stored with " +
				"the system's current hashing method instead of the DES or MD5 hash that is cheap to crack today.",
			Warning: "The next login as " + account + " stops at a password change. An account that only " +
				"logs in non-interactively (a script using a password over SSH, an FTP account) fails instead " +
				"of prompting. The weak hash stays in /etc/shadow until the change happens, and the new one " +
				"is only strong if the system's ENCRYPT_METHOD is SHA512 or yescrypt. There is no checkpoint: " +
				"exec fixes are not file-backed, so Hostveil cannot undo this.",
			Kind:          ActionExec,
			Commands:      [][]string{{"passwd", "--expire", account}},
			TakesEffectOn: account + "'s next password change",
		}},
	}, nil
}
