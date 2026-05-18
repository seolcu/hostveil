package domain

type Finding struct {
	ID             string
	Axis           Axis
	Severity       Severity
	Scope          Scope
	Source         Source
	Subject        string
	Service        string
	Title          string
	Description    string
	WhyRisky       string
	HowToFix       string
	Evidence       map[string]string
	Remediation    RemediationKind
}

func (f *Finding) IsFixable() bool {
	return f.Remediation == RemediationAuto || f.Remediation == RemediationReview
}
