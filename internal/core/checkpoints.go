package core

import (
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// ListCheckpoints returns saved restore points, newest first, as model
// values so every UI can render the applied-fix log without reaching into
// internal/history.
//
// A checkpoint whose metadata cannot be read comes back as a non-nil error
// *alongside* the ones that could, because the list is still worth showing
// and the operator still needs telling that part of their recovery history is
// gone. Use IsIncompleteHistory to tell that from an outright failure.
func (e *Engine) ListCheckpoints() ([]model.Checkpoint, error) {
	cps, err := e.store.List()
	if err != nil && !history.IsDamaged(err) {
		return nil, err
	}
	out := make([]model.Checkpoint, 0, len(cps))
	for _, cp := range cps {
		out = append(out, toModelCheckpoint(cp))
	}
	return out, err
}

// IsIncompleteHistory reports whether an error from ListCheckpoints means
// "some checkpoints are unreadable" rather than "the list failed".
//
// It exists for the same reason IsExternalEdit does: the layering tests
// forbid internal/ui/* from importing internal/history, so a UI has no access
// to the error type and would otherwise be left matching on message text.
func IsIncompleteHistory(err error) bool { return history.IsDamaged(err) }

func toModelCheckpoint(cp history.Checkpoint) model.Checkpoint {
	out := model.Checkpoint{
		ID:             cp.ID,
		FindingID:      cp.FindingID,
		Label:          cp.Label,
		CreatedAt:      cp.CreatedAt,
		Reversible:     cp.Reversible(),
		Diff:           cp.Diff,
		RestartService: cp.RestartService,
		Commands:       cp.Commands,
	}
	for _, bf := range cp.Files {
		out.Files = append(out.Files, bf.Path)
	}
	return out
}
