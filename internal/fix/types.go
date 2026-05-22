package fix

type FixActionType int

const (
	ActionComposeEdit FixActionType = iota
	ActionHostEdit
	ActionShellCommand
)

type FixAction struct {
	Type     FixActionType
	Service  string
	Summary  string
	Diff     string
	Path     string
	Content  string
	Command  string
	Rollback string
}

type FixProposal struct {
	Service     string
	Summary     string
	Remediation string // "auto" or "review"
}

type FixPlan struct {
	ComposeFile  string
	AutoApplied  []FixProposal
	ReviewNeeded []FixProposal
	HostEdits    []FixAction
	ShellCmds    []FixAction
	Actions      []FixAction
	DiffPreview  string
	BackupPath   string
}

func (p *FixPlan) Changed() bool {
	return len(p.AutoApplied) > 0 || len(p.ReviewNeeded) > 0 ||
		len(p.HostEdits) > 0 || len(p.ShellCmds) > 0
}
