package fix

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// registerSystemd registers the one systemd finding whose remediation hostveil
// can write down.
//
// The domain has four rules and three of them stay declined, because each
// breaks something the unit does not show: PrivateTmp breaks two services that
// hand each other files through /tmp, ProtectHome breaks anything whose data
// lives in a home directory, ProtectSystem breaks a service that writes under
// /usr. NoNewPrivileges carries no such blind spot — it closes the setuid path,
// and nothing about the unit hides whether that matters.
//
// The reason this one was declined has expired. It read "a drop-in plus a
// restart is one procedure in two steps rather than two alternatives", and
// Action.TakesEffectOn is exactly the shape that objection describes: write the
// artifact now, name what has to happen for it to be in force. Every compose
// fix runs on it. The sentence was written before it existed.
//
// The other half of that reason still holds — a service that deliberately
// escalates stops coming back — so this is Review, declared by the checker.
// The action here is one edit, which is Auto's shape; resolvedKind takes the
// more cautious of the two.
func registerSystemd(r *Registry) {
	r.Register("systemd.no-new-privileges", buildSystemdNoNewPrivileges)
}

// serviceDirective matches an existing assignment of the directive's key
// anywhere in the file, in systemd's own spelling: the key, optional spaces,
// '=', the rest of the line.
func serviceDirective(key string) *regexp.Regexp {
	return regexp.MustCompile(`(?mi)^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*=.*$`)
}

func buildSystemdNoNewPrivileges(f model.Finding) (Fix, error) {
	return systemdDropIn(f, "NoNewPrivileges", "yes",
		"Closes the setuid path out of this service. A service that deliberately "+
			"escalates — anything calling a setuid helper — stops working, and it "+
			"stops at the next restart rather than now.")
}

// systemdDropIn builds the edit that turns one [Service] directive on.
//
// The path is the finding's, not one computed here: internal/check/systemd
// works it out from the unit id and carries it, and a second computation here
// would be a second answer to a question that has one. It is also the path
// that checker's own how-to tells the operator to create, which is what makes
// the fix and the instructions the same instruction.
func systemdDropIn(f model.Finding, key, value, warning string) (Fix, error) {
	// Empty means the checker found a drop-in systemd loads after anything
	// hostveil could write. Drop-ins are applied in filename order whichever
	// directory they live in (systemd.unit(5)), so the file this fix would
	// create is one the next daemon-reload overrides — it would appear, report
	// success, take a checkpoint, and change nothing. That is persistSysctl's
	// rule, and refusing here is what makes it true of this domain too: the
	// finding falls back to Manual and its how-to-fix names the file that
	// outranks it.
	path := f.Metadata["dropin"]
	if path == "" {
		return Fix{}, fmt.Errorf("no drop-in filename for %s would sort after the ones systemd "+
			"has already loaded for %s, so any file written here would be overridden", f.ID, f.Service)
	}
	unit := f.Service
	if unit == "" {
		return Fix{}, fmt.Errorf("finding %s names no unit", f.ID)
	}
	line := key + "=" + value

	return Fix{
		FindingID: f.ID,
		Label:     "Write " + path,
		Kind:      model.RemediationAuto, // one action; the checker asks for Review
		Actions: []Action{{
			Label:   "Set " + line + " for " + unit,
			Warning: warning,
			Kind:    ActionEdit,
			Path:    path,
			// The drop-in does not exist — if it did, the directive would be
			// set and the finding would not have fired. Undoing the fix means
			// deleting the file, which is what the checker's own instructions
			// already tell the operator.
			CreateIfMissing: true,
			// systemd reads unit files once. Until it is told to read them
			// again, `systemctl show` keeps reporting the old value, so the
			// re-check will still report this finding — correctly, and that
			// is what VerifyStillPresent is for.
			TakesEffectOn: "`systemctl daemon-reload && systemctl restart " + unit + "`",
			Transform:     setServiceDirective(key, line),
		}},
	}, nil
}

// setServiceDirective returns the transform that leaves the file with exactly
// one assignment of key, set to line.
//
// Four shapes reach it. An absent file arrives as nil and gets a whole
// drop-in. A file that already says the right thing is returned untouched —
// applying a fix twice is not an error the operator should have to avoid. A
// file that assigns the key differently has that line replaced rather than
// another appended: systemd takes the last assignment so appending would
// work, and a file carrying both is not wrong so much as evidence of a tool
// that does not know what it has done. A file with no [Service] section at
// all gets one, because a bare directive in a drop-in belongs to no section
// and systemd ignores it.
func setServiceDirective(key, line string) func([]byte) ([]byte, error) {
	re := serviceDirective(key)
	return func(in []byte) ([]byte, error) {
		if len(bytes.TrimSpace(in)) == 0 {
			return []byte("[Service]\n" + line + "\n"), nil
		}
		if m := re.Find(in); m != nil {
			if strings.EqualFold(strings.Join(strings.Fields(string(m)), ""), line) {
				return in, nil
			}
			return re.ReplaceAll(in, []byte(line)), nil
		}

		out := string(in)
		if !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		// Append under the last [Service] section, or add one. Appending at
		// the end of the file would land inside whatever section happens to
		// be last — [Unit] or [Install] — where systemd would ignore it. The
		// SSH domain learned the same lesson about Match blocks.
		idx := regexp.MustCompile(`(?mi)^\[Service\][ \t]*$`).FindAllStringIndex(out, -1)
		if len(idx) == 0 {
			return []byte(out + "\n[Service]\n" + line + "\n"), nil
		}
		start := idx[len(idx)-1][1]
		end := len(out)
		if next := regexp.MustCompile(`(?m)^\[`).FindStringIndex(out[start:]); next != nil {
			end = start + next[0]
			// Back over the blank line that separates the sections. Inserting
			// after it leaves the directive sitting against the next header,
			// which systemd reads correctly and a person does not: it looks
			// like it belongs to [Install].
			for end > start && strings.HasSuffix(out[:end], "\n\n") {
				end--
			}
		}
		return []byte(out[:end] + line + "\n" + out[end:]), nil
	}
}
