package fix

import (
	"fmt"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// Preview is the human-readable description of what a fix will
// change, before the user confirms. In v3.0.0-alpha the preview is
// generated from the finding's rule_id and the affected entity
// references; the v3.x release will replace this with a per-rule
// catalog with full diffs.
type Preview struct {
	Title       string
	Description string
	Lines       []PreviewLine
}

// PreviewLine is a single line of the preview, rendered as
// `current → proposed`. For textual config files it carries a
// `path:line` location; for non-textual entities (containers,
// certs) the line is still rendered but the path points at the
// owning resource.
type PreviewLine struct {
	Path      string
	Line      int
	Current   string
	Proposed  string
	IsRemoval bool
}

// RenderPreview produces the preview for a finding. The current
// implementation is intentionally minimal: it returns a single
// "no-op fix" line for rules we don't have a real procedure for,
// and a richer preview for the small set of rules that have a
// known shape (e.g. ssh.permit_root_login.allow).
func RenderPreview(f model.Finding) Preview {
	p := Preview{
		Title:       fmt.Sprintf("Apply %s", f.RuleID),
		Description: fmt.Sprintf("This will change the configuration that produced the finding \"%s\".", f.Title),
	}
	switch f.RuleID {
	case "ssh.permit_root_login.allow":
		p.Lines = append(p.Lines, PreviewLine{
			Path:      "/etc/ssh/sshd_config",
			Line:      findSSHLine(f),
			Current:   "PermitRootLogin yes",
			Proposed:  "PermitRootLogin no",
			IsRemoval: false,
		})
	case "ssh.password_auth.only":
		p.Lines = append(p.Lines, PreviewLine{
			Path:     "/etc/ssh/sshd_config",
			Line:     findSSHLine(f),
			Current:  "PasswordAuthentication yes",
			Proposed: "PasswordAuthentication no",
		})
	case "ssh.protocol.legacy":
		p.Lines = append(p.Lines, PreviewLine{
			Path:     "/etc/ssh/sshd_config",
			Line:     findSSHLine(f),
			Current:  "Protocol " + displayProtocol(f),
			Proposed: "Protocol 2",
		})
	default:
		// Unknown rule: emit a single "will be applied" line so the
		// preview is still useful.
		loc := "(unknown)"
		if len(f.EntityRefs) > 0 {
			loc = f.EntityRefs[0].Display
		}
		p.Lines = append(p.Lines, PreviewLine{
			Path:     loc,
			Current:  "(no preview available for this rule in v3.0.0)",
			Proposed: "(will be applied per the fix catalog)",
		})
	}
	return p
}

// String returns the preview in the plain-language form that
// `hostveil fix` prints before confirmation.
func (p Preview) String() string {
	var b strings.Builder
	b.WriteString(p.Title)
	b.WriteString("\n")
	b.WriteString(p.Description)
	b.WriteString("\n")
	for _, l := range p.Lines {
		b.WriteString("  ")
		b.WriteString(l.Path)
		if l.Line > 0 {
			b.WriteString(fmt.Sprintf(":%d", l.Line))
		}
		b.WriteString("\n")
		b.WriteString("    - ")
		b.WriteString(l.Current)
		b.WriteString("\n")
		b.WriteString("    + ")
		b.WriteString(l.Proposed)
		b.WriteString("\n")
	}
	return b.String()
}

// findSSHLine is a small helper that pulls the line number from
// the SSH finding's entity ref.
func findSSHLine(f model.Finding) int {
	for _, r := range f.EntityRefs {
		if r.Kind == model.EntityRefKindSetting {
			// Display is "key = value"; we don't have the line
			// in the display, so return 0 to mean "unknown line".
			return 0
		}
	}
	return 0
}

// displayProtocol is a best-effort reconstruction of the Protocol
// value from the SSH finding's entity ref.
func displayProtocol(f model.Finding) string {
	for _, r := range f.EntityRefs {
		if r.Kind == model.EntityRefKindSetting && strings.HasPrefix(r.Display, "Protocol ") {
			return strings.TrimPrefix(r.Display, "Protocol ")
		}
	}
	return "(see sshd_config)"
}
