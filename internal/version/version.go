// Package version carries the binary's identity (version, commit, build
// date) embedded at build time via scripts/build.sh. The values live
// in package-level variables so they can be overridden by the linker.
package version

// Name is the program name; used as the directory under XDG paths.
const Name = "hostveil"

// These three are set at build time by scripts/build.sh via -ldflags.
var (
	Version = "v3.0.0-dev"
	Commit  = "unknown"
	Built   = "unknown"
)
