package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/platform"
	"github.com/seolcu/hostveil/internal/selfupdate"
)

// The update path needs two clients, and sharing one is a bug that hides
// until the first real download.
//
// resolveClient must NOT follow redirects: Latest learns the version by
// reading the Location header of /releases/latest, and a client that followed
// it would return the release page's HTML with no version in it.
//
// downloadClient must follow them: a release asset URL answers 302 and sends
// the caller on to objects.githubusercontent.com. One shared no-redirect
// client made every download fail with "returned 302 Found" — on the one path
// a `--check` smoke test never reaches.
func resolveClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func downloadClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Minute}
}

func cmdUpdate(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	var (
		check bool
		yes   bool
	)
	fs.BoolVar(&check, "check", false, "report whether a newer version exists and exit without installing")
	fs.BoolVar(&yes, "yes", false, "do not ask before installing")
	// Parsed before elevating, and elevated only where root is actually
	// needed. This is the one command whose need for root depends on its
	// flags: --check makes a single HTTP request and writes nothing, so
	// asking for a password to run it is the same defect as asking for one
	// before a usage error.
	if code := parseFlags(fs, args); code >= 0 {
		return code
	}
	if !check {
		maybeElevate("update") // on success the process is replaced and does not return
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil: cannot locate this binary:", err)
		return 1
	}
	runner := platform.DefaultRunner{}
	origin := selfupdate.DetectOrigin(ctx, runner, exe)

	rel, err := selfupdate.Latest(ctx, resolveClient())
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}
	if selfupdate.SameVersion(version, rel.Version) {
		fmt.Printf("hostveil %s is the latest version.\n", version)
		return 0
	}
	fmt.Printf("hostveil %s is installed; %s is available.\n", version, rel.Version)
	if check {
		// A distinct status so a cron job or a CI step can branch on it
		// without parsing the sentence above.
		return 10
	}
	if origin == selfupdate.OriginUnknown {
		fmt.Fprintln(os.Stderr, "\nhostveil: "+origin.Advice())
		return 1
	}
	fmt.Printf("This binary came from %s, so hostveil will update it that way.\n", origin)
	if !yes && !promptYesNo("Update now?") {
		return 1
	}
	if err := runUpdate(ctx, runner, origin, exe, rel); err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}
	// Confirmed, not assumed. `apt-get install` on a package whose version
	// dpkg already records exits 0 having done nothing, and a `go install`
	// that resolves to a cached build does the same. Printing a tick over
	// that is the one thing this project refuses to do anywhere else.
	switch now, err := selfupdate.InstalledVersion(ctx, runner, exe); {
	case err != nil:
		fmt.Printf("hostveil %s was installed, but asking the binary its version failed: %v\n", rel.Version, err)
		return 1
	case !selfupdate.SameVersion(now, rel.Version):
		fmt.Fprintf(os.Stderr, "hostveil: the install reported success and %s still reports %s.\n", exe, now)
		fmt.Fprintln(os.Stderr, "Nothing was changed. This happens when the package manager already "+
			"records the new version, or when the binary on disk was replaced by hand.")
		return 1
	}
	fmt.Printf("✓ hostveil %s installed.\n", rel.Version)
	return 0
}

// runUpdate does the origin's own kind of update. Each path verifies before it
// touches anything, and only the standalone one writes to /usr/bin directly.
func runUpdate(ctx context.Context, r platform.CommandRunner, o selfupdate.Origin, exe string, rel selfupdate.Release) error {
	if o == selfupdate.OriginGoInstall {
		fmt.Println("  · rebuilding from source with the Go toolchain")
		return selfupdate.Rebuild(ctx, r)
	}

	asset := rel.Asset
	if o == selfupdate.OriginDeb || o == selfupdate.OriginRPM {
		var err error
		if asset, err = selfupdate.PackageAsset(o, rel.Version); err != nil {
			return err
		}
		if rel, err = rel.WithAsset(asset); err != nil {
			return err
		}
	}

	fmt.Printf("  · downloading %s\n", asset)
	data, err := selfupdate.Download(ctx, downloadClient(), rel)
	if err != nil {
		return err
	}
	fmt.Println("  ✓ checksum matches the release")

	path, cleanup, err := selfupdate.WriteTemp(asset, data)
	if err != nil {
		return err
	}
	defer cleanup()

	switch checked, err := selfupdate.Provenance(ctx, r, path); {
	case err != nil:
		return err
	case checked:
		fmt.Println("  ✓ build provenance verified")
	default:
		fmt.Println("  · provenance not checked (install the GitHub CLI to enable it)")
	}

	switch o {
	case selfupdate.OriginDeb, selfupdate.OriginRPM:
		return selfupdate.InstallPackage(ctx, r, o, path)
	default:
		bin, err := selfupdate.BinaryFromArchive(data)
		if err != nil {
			return err
		}
		return selfupdate.Replace(exe, bin)
	}
}

func cmdUninstall(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "do not ask before removing")
	if code := parseAndElevate(fs, args); code >= 0 {
		return code
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil: cannot locate this binary:", err)
		return 1
	}
	runner := platform.DefaultRunner{}
	origin := selfupdate.DetectOrigin(ctx, runner, exe)
	if origin == selfupdate.OriginUnknown {
		fmt.Fprintln(os.Stderr, "hostveil: "+origin.Advice())
		return 1
	}

	fmt.Printf("This will remove hostveil %s, installed by %s.\n", version, origin)
	// Said before the prompt, not after. The checkpoints are the backups of
	// every file hostveil edited here, and whether they matter is exactly what
	// the operator is being asked to decide.
	if note := selfupdate.StateNote(history.DefaultDir()); note != "" {
		fmt.Println("\n" + note)
	}
	if !*yes && !promptYesNo("\nRemove hostveil?") {
		return 1
	}

	switch origin {
	case selfupdate.OriginDeb, selfupdate.OriginRPM:
		err = selfupdate.RemovePackage(ctx, runner, origin)
	default:
		err = selfupdate.Remove(exe)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}
	fmt.Println("✓ hostveil removed.")
	return 0
}

// noUpdateCheckEnv turns the background check off entirely.
const noUpdateCheckEnv = "HOSTVEIL_NO_UPDATE_CHECK"

// startUpdateCheck refreshes the cached "is there a newer release" answer, at
// most once a day, without the scan waiting for it.
//
// Opt-out, because a security tool that reaches the network on its own has to
// be stoppable: HOSTVEIL_NO_UPDATE_CHECK=1 and hostveil never contacts GitHub
// unless you type `hostveil update`.
func startUpdateCheck(ctx context.Context) {
	if os.Getenv(noUpdateCheckEnv) != "" {
		return
	}
	selfupdate.CheckInBackground(ctx, resolveClient(), stateDir(), time.Now())
}

// updateNotice is the one line to append to human output, or "" when there is
// nothing to say.
func updateNotice() string {
	if os.Getenv(noUpdateCheckEnv) != "" {
		return ""
	}
	return selfupdate.LoadCache(stateDir()).Notice(version)
}
