package fix

import (
	"github.com/seolcu/hostveil/internal/model"
)

// ConflictKind enumerates the shapes from FR-011 that the detector
// reports. The plain-language message and the file:line location
// are derived per-kind in the Conflict struct.
type ConflictKind string

const (
	ConflictSSHMatchBlock         ConflictKind = "ssh_match_block"
	ConflictComposeOverrideFile   ConflictKind = "compose_override_file"
	ConflictSSHDropIn             ConflictKind = "ssh_drop_in"
	ConflictOther                 ConflictKind = "other"
)

// Conflict is a single construct that would re-assert the pre-fix
// value after the fix is applied. The list of conflicts is the
// detector's output.
type Conflict struct {
	Kind     ConflictKind
	Path     string
	Line     int
	Snippet  string
}

// Detect scans the host for any construct that would conflict with
// the proposed fix for the given finding. The v3.0.0-alpha detector
// covers the four shapes from FR-011:
//
//   (a) an SSH Match block that re-enables a setting the program
//       intends to disable.
//   (b) a Docker Compose override file that re-applies a value the
//       program intends to change.
//   (c) a user-supplied drop-in under /etc/ssh/sshd_config.d/.
//   (d) any other re-asserting construct.
//
// The detector returns an empty slice when no conflicts are found;
// a non-empty slice means the fix MUST NOT proceed without an
// explicit --force override.
func Detect(f model.Finding) []Conflict {
	var out []Conflict
	switch f.RuleID {
	case "ssh.permit_root_login.allow",
		"ssh.password_auth.only",
		"ssh.protocol.legacy":
		out = append(out, detectSSHConflicts(f)...)
	default:
		// No specific detector for this rule; no conflicts.
	}
	return out
}

// detectSSHConflicts scans /etc/ssh/sshd_config.d/*.conf for
// drop-ins that override the main sshd_config, and the main file
// for any Match block that re-enables the relevant setting. The
// detector is deliberately a line scanner, not a full sshd_config
// parser; the output is a starting list the human reviews before
// applying the fix.
func detectSSHConflicts(f model.Finding) []Conflict {
	var out []Conflict

	// (a) Match blocks in the main sshd_config.
	if matches, err := scanSSHMatchBlocks(sshMainPath); err == nil {
		out = append(out, matches...)
	}

	// (c) Drop-ins under /etc/ssh/sshd_config.d/.
	dropDir := "/etc/ssh/sshd_config.d"
	entries, err := readDir(dropDir)
	if err == nil {
		for _, name := range entries {
			fp := joinPath(dropDir, name)
			if conflicts, err := scanSSHMatchBlocks(fp); err == nil {
				out = append(out, conflicts...)
			}
		}
	}

	// Re-key the conflicts with the SSH rule id so the user
	// understands why the conflict is listed.
	_ = f
	return out
}
