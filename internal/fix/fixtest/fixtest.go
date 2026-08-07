// Package fixtest builds findings the fix registry can be exercised with,
// so a caller can ask "what would a user actually be offered for this ID?"
// without a live scan.
//
// It is exported for the same reason internal/check/checktest is: the answer
// is needed outside the package that knows it. cmd/sitegen's docs tests pin
// the checks table's Fix column against the registry, and the column is what
// a user reads — which means resolving the fix, which means building it.
package fixtest

import "github.com/seolcu/hostveil/internal/model"

// Finding returns a finding for id carrying the union of the metadata and
// evidence every registered builder reads.
//
// One finding with every key rather than a per-domain table: a builder that
// starts reading a new key fails loudly here (its Build errors) instead of
// being quietly skipped, and no caller has to know which domain an ID
// belongs to. The source and severity are placeholders — no builder reads
// either — and the declared remediation is deliberately Review, the value
// that resolves against anything without hiding it.
func Finding(id string) model.Finding {
	return model.NewFinding(id, "t", model.SeverityHigh, model.SourceCompose, model.RemediationReview,
		model.WithService("app"),
		model.WithMetadata("file", "/tmp/docker-compose.yml"),
		model.WithMetadata("service", "app"),
		model.WithEvidence("port", "6379"),
		model.WithEvidence("config", "/etc/ssh/sshd_config"),
		model.WithEvidence("mechanism", "dnf-automatic"),
		model.WithEvidence("image", "redis:7"),
		model.WithEvidence("fixable_count", "3"),
		model.WithEvidence("worst_cve", "CVE-2021-1234"),
		model.WithEvidence("reference", "tag"),
		model.WithEvidence("paths", "/etc/shadow"),
		model.WithEvidence("expected", "0640"),
		model.WithEvidence("set", "kernel.kptr_restrict=1"),
		model.WithEvidence("ssh_port", "22"),
		model.WithEvidence("available", "ufw"),
	)
}
