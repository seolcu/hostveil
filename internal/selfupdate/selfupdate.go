// Package selfupdate replaces or removes the hostveil binary in place.
//
// It exists because managing a tool should not mean pasting a URL. The
// installer is still the way in; this is the way to stay current afterwards,
// and it does the same three things the installer does in the same order:
// resolve the latest release, verify what it downloaded, and only then touch
// /usr/bin.
//
// # What this is, honestly
//
// A path by which a program running as root fetches code from the network and
// runs it. hostveil audits hosts for exactly that shape, so the rules it
// applies to itself are the strict reading of the ones it applies to others:
//
//   - The checksum is mandatory. Not "warn and continue": a download that
//     cannot be matched against the release's own checksums file is discarded.
//   - The build provenance attestation is mandatory wherever it can be
//     checked. `gh` is not a dependency this can require, so its absence is a
//     note; its *failure* is a refusal. That is the installer's rule and the
//     reasoning is the same: matching a checksum proves the bytes arrived
//     intact, and nothing more.
//   - A binary a package manager owns is never overwritten. It is handed to
//     the package manager instead, with the release's own .deb or .rpm, so
//     dpkg and rpm keep describing the filesystem correctly. Refusing and
//     printing a command would have been easier and would have left the
//     operator doing by hand the thing this exists to stop them doing.
//   - Nothing is written until everything is verified, and the write is a
//     rename over the target rather than a write through it. A running
//     executable cannot be opened for writing at all, and a partially written
//     one is a host with no working hostveil and no obvious reason why.
package selfupdate

import (
	"context"
	"errors"
	"strings"
)

// Repo is the only repository this will install from. A constant rather than a
// parameter: an updater that can be pointed somewhere else is an updater whose
// safety argument depends on nobody pointing it somewhere else.
const Repo = "seolcu/hostveil"

// Origin is how the running binary got onto this host, which decides whether
// replacing it is this program's business.
type Origin int

const (
	// OriginUnknown means the install method could not be established. It is
	// the one case that ends in advice rather than action: guessing wrong
	// here corrupts a package database or deletes a file somebody else owns.
	OriginUnknown Origin = iota
	// OriginStandalone is a binary this tool may replace directly, which is
	// what the install script produces.
	OriginStandalone
	// OriginDeb is a binary dpkg owns. Updated and removed through apt.
	OriginDeb
	// OriginRPM is a binary rpm owns. Updated and removed through dnf.
	OriginRPM
	// OriginGoInstall is a binary built from source into GOBIN. There is no
	// release archive that corresponds to it, so it is rebuilt from source
	// rather than replaced with one.
	OriginGoInstall
)

// ErrUnknownOrigin is returned when hostveil cannot establish how its own
// binary was installed, which is the one case it will not act on. UIs match on
// it rather than on the message.
var ErrUnknownOrigin = errors.New("hostveil cannot tell how this binary was installed")

// String names the origin for a message.
func (o Origin) String() string {
	switch o {
	case OriginStandalone:
		return "the install script"
	case OriginDeb:
		return "a .deb package"
	case OriginRPM:
		return "an .rpm package"
	case OriginGoInstall:
		return "go install"
	default:
		return "an unknown method"
	}
}

// Advice is what to tell an operator when hostveil will not act, which is only
// ever the unknown case. Every other origin has something hostveil can do.
func (o Origin) Advice() string {
	return "hostveil could not tell how this binary was installed, so it will not replace or delete it. " +
		"Use the tool that put it there. If you installed it with the script, it should be at " +
		"/usr/bin/hostveil; a copy somewhere else is yours to manage."
}

// Release is a version and the archive that carries it.
type Release struct {
	Version string // without the leading v
	Asset   string // the archive's file name
	URL     string // where the archive is
	Sums    string // where the release's checksums file is
}

// Plan is what an update would do, resolved before anything is downloaded so a
// caller can print it and stop.
type Plan struct {
	Origin  Origin
	Path    string // the binary that would be replaced
	Current string
	Latest  string
}

// UpToDate reports whether there is nothing to do.
func (p Plan) UpToDate() bool { return SameVersion(p.Current, p.Latest) }

// SameVersion compares two versions without caring which of them carries the
// leading v.
//
// The two sides genuinely disagree. goreleaser stamps the binary with
// `-X main.version=v{{.Version}}`, so a released hostveil says "v3.17.0",
// while the release tag read back out of the /releases/latest redirect is
// trimmed to "3.17.0" because that is what builds an asset URL. Comparing them
// raw is never equal, and the symptom is not a crash: `hostveil update` on a
// perfectly current host announces an update and reinstalls the version it is
// already running, every time.
func SameVersion(a, b string) bool {
	a, b = strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v")
	return a != "" && a == b
}

// ctxErr folds a cancelled context into an error a caller can print without
// dressing an interruption up as a failure.
func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// WithAsset points a release at a different published file, which is how the
// package paths reuse the checksum machinery: the .deb and the .rpm are listed
// in the same checksums file as the tarball.
func (r Release) WithAsset(name string) Release {
	base := r.URL[:len(r.URL)-len(r.Asset)]
	r.Asset, r.URL = name, base+name
	return r
}
