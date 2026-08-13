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

// updateClient is the HTTP client the update path uses.
//
// Redirects are not followed on purpose: Latest reads the Location header of
// /releases/latest to learn the version, and a client that followed it would
// hand back the release page's HTML instead. Everything else here is a direct
// asset URL.
func updateClient() *http.Client {
	return &http.Client{
		Timeout:       2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func cmdUpdate(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	var (
		check bool
		yes   bool
	)
	fs.BoolVar(&check, "check", false, "report whether a newer version exists and exit without installing")
	fs.BoolVar(&yes, "yes", false, "do not ask before installing")
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

	rel, err := selfupdate.Latest(ctx, updateClient())
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
		rel = rel.WithAsset(asset)
	}

	fmt.Printf("  · downloading %s\n", asset)
	data, err := selfupdate.Download(ctx, updateClient(), rel)
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
