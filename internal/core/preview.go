package core

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/seolcu/hostveil/internal/diff"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
)

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

	// Report the classified kind, not the registry's raw one: classify may
	// hold a fix at Review that the registry shapes as Auto, and a preview
	// labelled "Auto-fix" next to a finding labelled "Review" would be a
	// contradiction the user has to resolve.
	preview := model.FixPreview{FindingID: f.ID, Label: fx.Label, Kind: classifiedKind(f.Remediation, fx.Kind)}
	for i, a := range fx.Actions {
		ap := model.ActionPreview{Index: i, Label: a.Label, Warning: a.Warning}
		switch a.Kind {
		case fix.ActionEdit:
			ap.Type = "edit"
			ap.Path = a.Path
			d, err := previewEdit(a)
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
func previewEdit(a fix.Action) (string, error) {
	orig, _, err := readEditTarget(a)
	if err != nil {
		return "", err
	}
	next, err := a.Transform(orig)
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
	data, err = os.ReadFile(a.Path) //nolint:gosec // path from a discovered finding
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
