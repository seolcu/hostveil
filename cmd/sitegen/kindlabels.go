package main

import "github.com/seolcu/hostveil/internal/model"

// kindLabels is each language's user-facing name for every remediation kind
// a finding can carry.
//
// The docs used to be read through a map to a bare fixable/not-fixable bool,
// which made "Auto-fix" and "Review" the same answer — so the column could
// promise unattended application of a fix the registry shapes as Review and
// nothing would say a word. The difference between those two is the whole
// subject of the fixing page: one of them is what `fix --all` runs on its own.
//
// The Korean row is deliberately the same four English words as the English
// one, not a translation of them. hostveil's CLI, TUI, and dashboard are
// English-only and always print "Auto-fix"/"Review"/"Manual"/"Unavailable"
// — there is no Korean build of the tool itself — so a Korean docs page that
// called them "자동 수정"/"검토"/"수동"/"사용 불가" was teaching a vocabulary
// the reader would never see again the moment they ran the binary it was
// documenting. These four are classification names, not prose, and every
// other classification name on the site (finding IDs, `HOSTVEIL_*` variable
// names, flag names) already stays in its original form in Korean copy for
// the same reason.
//
// RemediationUnset has no entry because no user can be shown one;
// TestFixingPageDocumentsEveryKindAUserCanSee asserts that rather than
// assuming it.
//
// Not a _test.go file: fixactions.go renders these same words into the
// generated fix-actions section, and docs_test.go pins the checks table's
// hand-typed Fix column against them. One map read by both is what keeps a
// label typed once from drifting into two answers for the same kind.
var kindLabels = map[string]map[model.RemediationKind]string{
	"en": {
		model.RemediationAuto:        "Auto-fix",
		model.RemediationReview:      "Review",
		model.RemediationManual:      "Manual",
		model.RemediationUnavailable: "Unavailable",
	},
	"ko": {
		model.RemediationAuto:        "Auto-fix",
		model.RemediationReview:      "Review",
		model.RemediationManual:      "Manual",
		model.RemediationUnavailable: "Unavailable",
	},
}

// kindInDocs inverts kindLabels: a Fix-column string to the kind it names,
// in whichever language wrote it.
var kindInDocs = func() map[string]model.RemediationKind {
	out := map[string]model.RemediationKind{}
	for _, byKind := range kindLabels {
		for kind, label := range byKind {
			out[label] = kind
		}
	}
	return out
}()
