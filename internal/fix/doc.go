// Package fix implements the apply / preview / rollback / record
// flow for Hostveil v3.0.0.
//
// The package is split into the pieces the spec and the tasks call
// out: preview rendering, backup (with SHA-256 verification),
// apply (the minimum-elevation execution), rollback (byte-identical
// restore plus a follow-up FixRecord), record (persistence), and
// conflict detection (per FR-011).
//
// In v3.0.0-alpha, the actual fix procedures for each rule are
// placeholders (the real procedures are post-v3.0). The apply
// flow, however, is fully wired: preview, confirmation, backup,
// record, and the rollback path that restores byte-for-byte.
package fix
