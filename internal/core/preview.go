package core

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/seolcu/hostveil/internal/diff"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// maxEditBytes bounds a no-follow read of an edit target. The files that
// need one are configs in a user's home, where a megabyte is generous and
// an unbounded read is how a FIFO or /dev/zero at the end of the path turns
// a fix into a process that never returns.
const maxEditBytes = 1 << 20

// PreviewFix returns, per available action, exactly what the fix would
// change — a unified diff for edits, the command list for execs — WITHOUT
// touching any file or running anything. This is the single preview path
// all UIs use.
func (e *Engine) PreviewFix(f model.Finding) (model.FixPreview, error) {
	fx, ok, err := e.buildFix(f)
	if err != nil {
		return model.FixPreview{}, err
	}
	if !ok {
		return model.FixPreview{}, fmt.Errorf("no fix available for %s", f.ID)
	}

	// Report the resolved kind, not the registry's raw one: classify may
	// hold a fix at Review that the registry shapes as Auto, and a preview
	// labelled "Auto-fix" next to a finding labelled "Review" would be a
	// contradiction the user has to resolve. It has to be the *same*
	// resolution the finding went through, exec floor included — this used to
	// call only the checker-versus-registry half, so an exec fix the finding
	// carried as Review previewed as "Auto-fix", producing that contradiction
	// on exactly the fixes where unattended application is the thing being
	// ruled out.
	preview := model.FixPreview{FindingID: f.ID, Label: fx.Label, Kind: resolvedKind(f.Remediation, fx)}
	for i, a := range fx.Actions {
		ap := model.ActionPreview{Index: i, Label: a.Label, Warning: a.Warning}
		switch a.Kind {
		case fix.ActionEdit:
			ap.Type = "edit"
			ap.Path = a.Path
			d, err := previewEdit(a, f.ID)
			if err != nil {
				return model.FixPreview{}, err
			}
			ap.Diff = d
		case fix.ActionExec:
			ap.Type = "exec"
			ap.Commands = a.Commands
		case fix.ActionMode:
			ap.Type = "mode"
			d, err := previewMode(a)
			if err != nil {
				return model.FixPreview{}, err
			}
			ap.Diff = d
		default:
			return model.FixPreview{}, fmt.Errorf("action %d of %s has unknown kind %v", i, f.ID, a.Kind)
		}
		preview.Actions = append(preview.Actions, ap)
	}
	return preview, nil
}

// previewEdit computes an edit action's diff purely: read the file, run the
// pure Transform on a copy, diff the two. The live file is never written.
func previewEdit(a fix.Action, id string) (string, error) {
	orig, _, err := readEditTarget(a)
	if err != nil {
		return "", err
	}
	next, err := safeTransform(a, id, orig)
	if err != nil {
		return "", err
	}
	return diff.Unified(a.Path, string(orig), string(next)), nil
}

// readEditTarget reads an edit action's file, reporting whether the action
// is about to create it.
//
// A CreateIfMissing action treats an absent file as empty input, so
// Transform composes the whole contents and the diff renders as a pure
// addition — which is exactly what the operator is being asked to approve.
// Any other read error is still an error, including for such an action: a
// permission denial or an EISDIR must not be mistaken for "not there yet"
// and answered by creating something.
func readEditTarget(a fix.Action) (data []byte, creating bool, err error) {
	if a.NoFollow {
		// A target inside somebody's home. See fix.Action.NoFollow: the
		// account owns every component of the path, and root must not be
		// walked into reading a file it was not pointed at.
		data, err = platform.ReadFileNoFollow(a.Path, maxEditBytes)
	} else {
		data, err = os.ReadFile(a.Path) // path from a discovered finding
	}
	switch {
	case err == nil:
		return data, false, nil
	case a.CreateIfMissing && errors.Is(err, fs.ErrNotExist):
		return nil, true, nil
	default:
		return nil, false, err
	}
}

// previewMode renders a mode action as a table. It only stats; the live
// files are never chmod'ed, mirroring previewEdit's purity.
//
// diff.Unified is no use here — it returns "" when the bytes match, and a
// mode change leaves them identical.
func previewMode(a fix.Action) (string, error) {
	changes, err := planModes(a)
	if err != nil {
		return "", err
	}
	return modeTable(changes), nil
}
