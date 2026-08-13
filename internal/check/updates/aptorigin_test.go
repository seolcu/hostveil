package updates

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/check/checktest"
	"github.com/seolcu/hostveil/internal/model"
)

// The host cloud images and several hardening guides produce: the conventional
// file turns unattended upgrades on, and a later fragment turns them off.
//
// apt reads every file in apt.conf.d in lexical order and the last assignment
// wins, so this host does NOT run unattended upgrades. hostveil read
// 20auto-upgrades alone, saw "1", and reported the domain clean — while the
// fix for the finding it was not reporting would have written "1" into the
// same losing file.
//
// This is the failure mode the fix round-trip cannot catch, and the reason it
// says so in its own doc comment: checker and fix shared one wrong oracle, so
// closing the loop over the checker confirms the wrong answer twice.
func TestAptReadsTheOptionAptWouldRead(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "20auto-upgrades"), `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`)
	write(t, filepath.Join(dir, "99-disable-auto-upgrades"), `APT::Periodic::Unattended-Upgrade "0";
`)

	c := &Checker{
		AptConfigPath:  filepath.Join(dir, "20auto-upgrades"),
		AptConfDirPath: dir,
	}
	// apt answers what apt actually resolves.
	env := checktest.New().Also("apt-config", "unattended-upgrade", "apt").
		Script(`APT::Periodic::Unattended-Upgrade "0";`+"\n",
			"apt-config", "dump", "APT::Periodic::Unattended-Upgrade").Env()

	// A coverage gap on the *other* half of the domain (pending updates) is
	// not a failure of the half under test.
	fs, _ := c.auditApt(context.Background(), env)
	var got model.Finding
	for _, f := range fs {
		if f.ID == "updates.disabled" {
			got = f
		}
	}
	if got.ID == "" {
		t.Fatal("unattended upgrades are switched off by the last fragment apt reads, and the domain reported nothing")
	}
	if want := filepath.Join(dir, "99-disable-auto-upgrades"); got.Evidence["set-by"] != want {
		t.Errorf("set-by = %q, want %q — the fix has to edit the file whose assignment apt reads last, not the one that loses",
			got.Evidence["set-by"], want)
	}
	if got.Evidence["config"] != got.Evidence["set-by"] {
		t.Errorf("the fix is pointed at %q while %q is what decides", got.Evidence["config"], got.Evidence["set-by"])
	}
}

// And the ordinary host, where nothing outranks the conventional file, is
// unchanged: no set-by, and the fix edits 20auto-upgrades as it always has.
func TestTheOrdinaryAptHostStillPointsAtTheConventionalFile(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "20auto-upgrades")
	write(t, conf, `APT::Periodic::Unattended-Upgrade "0";`+"\n")

	c := &Checker{AptConfigPath: conf, AptConfDirPath: dir}
	env := checktest.New().Also("apt-config", "unattended-upgrade", "apt").
		Script(`APT::Periodic::Unattended-Upgrade "0";`+"\n",
			"apt-config", "dump", "APT::Periodic::Unattended-Upgrade").Env()

	// A coverage gap on the *other* half of the domain (pending updates) is
	// not a failure of the half under test.
	fs, _ := c.auditApt(context.Background(), env)
	for _, f := range fs {
		if f.ID != "updates.disabled" {
			continue
		}
		if f.Evidence["config"] != conf {
			t.Errorf("config = %q, want the conventional file %q", f.Evidence["config"], conf)
		}
		return
	}
	t.Fatal("no updates.disabled finding on a host with unattended upgrades switched off")
}

// A host with no apt-config is not a host with the option unset. Falling back
// to the single file is what hostveil did before and is still the best
// available answer; claiming to know the effective value is not.
func TestWithoutAptConfigTheSingleFileIsTheFallback(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "20auto-upgrades")
	write(t, conf, `APT::Periodic::Unattended-Upgrade "1";`+"\n")

	c := &Checker{AptConfigPath: conf, AptConfDirPath: dir}
	env := checktest.New().Also("unattended-upgrade", "apt").Env() // no apt-config

	// A coverage gap on the *other* half of the domain (pending updates) is
	// not a failure of the half under test.
	fs, _ := c.auditApt(context.Background(), env)
	for _, f := range fs {
		if f.ID == "updates.disabled" {
			t.Error("the fallback read the file as disabled when it says \"1\"")
		}
	}
}

// apt ignores fragments whose extension is not .conf — dpkg's .dpkg-dist
// leftovers, editor backups — so naming one as the winner would send the fix
// to edit a file apt never opens.
func TestAFragmentAptIgnoresIsNotTheWinner(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "20auto-upgrades"), `APT::Periodic::Unattended-Upgrade "0";`+"\n")
	write(t, filepath.Join(dir, "99-disable.dpkg-dist"), `APT::Periodic::Unattended-Upgrade "0";`+"\n")
	write(t, filepath.Join(dir, "99-backup~"), `APT::Periodic::Unattended-Upgrade "0";`+"\n")

	if got, want := aptOrigin(dir), filepath.Join(dir, "20auto-upgrades"); got != want {
		t.Errorf("aptOrigin = %q, want %q — apt does not read the other two", got, want)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
