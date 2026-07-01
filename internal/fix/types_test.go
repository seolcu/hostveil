package fix

import (
	"errors"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

func TestClass_NoActions(t *testing.T) {
	f := &Fix{FindingID: "test"}
	if got := f.Class(); got != domain.RemediationUnavailable {
		t.Errorf("Class() = %v, want Unavailable", got)
	}
}

// TestRegistry_Classify_UnregisteredIDLeavesRemediationUnchanged is a
// regression test for the RemediationKind zero-value footgun documented
// on domain.Finding: RemediationAuto is 0, so a Finding built without
// explicitly setting Remediation reads as "Auto-fixable" by default.
// Classify must never paper over that by leaving an unregistered
// finding's Remediation at whatever it already was — it only writes a
// new Remediation when it finds an exact or wildcard match in the
// registry. Every real scanner (composeaudit, trivy, lynis) sets
// Remediation explicitly before Classify runs specifically so this
// zero value is never actually reached in production; this test locks
// in that Classify's contract doesn't quietly rely on that discipline.
func TestRegistry_Classify_UnregisteredIDLeavesRemediationUnchanged(t *testing.T) {
	r := New()
	r.Register(&Fix{FindingID: "known.id", Actions: []Action{{Type: ActionEdit}}})

	findings := []domain.Finding{
		{ID: "known.id", Remediation: domain.RemediationUnavailable},
		{ID: "totally.unknown.id"}, // zero-value Remediation == RemediationAuto
	}
	r.Classify(findings)

	if findings[0].Remediation != domain.RemediationAuto {
		t.Errorf("known.id: Remediation = %v, want Auto (registered fix should classify it)", findings[0].Remediation)
	}
	// This assertion is the documentation, not a desirable behavior: an
	// unregistered finding's Remediation is whatever the caller set it
	// to (here, the zero value). Classify has no way to distinguish "the
	// caller explicitly wants Auto" from "the caller forgot to set
	// this" — that's why every finding constructor in this codebase
	// must set Remediation itself, per the domain.Finding doc comment.
	if findings[1].Remediation != domain.RemediationAuto {
		t.Errorf("totally.unknown.id: Remediation = %v, want unchanged zero-value Auto", findings[1].Remediation)
	}
}

func TestClass_Auto_Edit(t *testing.T) {
	f := &Fix{Actions: []Action{{Type: ActionEdit}}}
	if got := f.Class(); got != domain.RemediationAuto {
		t.Errorf("Class(edit) = %v, want Auto", got)
	}
}

func TestClass_Auto_Exec(t *testing.T) {
	f := &Fix{Actions: []Action{{Type: ActionExec}}}
	if got := f.Class(); got != domain.RemediationAuto {
		t.Errorf("Class(exec) = %v, want Auto", got)
	}
}

func TestClass_Review(t *testing.T) {
	f := &Fix{Actions: []Action{{Type: ActionEdit}, {Type: ActionExec}}}
	if got := f.Class(); got != domain.RemediationReview {
		t.Errorf("Class(2 actions) = %v, want Review", got)
	}
}

func TestRun_Success(t *testing.T) {
	applied := false
	f := &Fix{Actions: []Action{{
		Label: "test",
		Apply: func(ctx Context) error {
			applied = true
			return nil
		},
	}}}
	result := f.Run(Context{}, 0)
	if !result.Success {
		t.Error("Run() should succeed")
	}
	if result.Label != "test" {
		t.Errorf("Run() Label = %q, want test", result.Label)
	}
	if !applied {
		t.Error("Apply was not called")
	}
}

func TestRun_Error(t *testing.T) {
	f := &Fix{Actions: []Action{{
		Apply: func(ctx Context) error { return errors.New("fail") },
	}}}
	result := f.Run(Context{}, 0)
	if result.Success {
		t.Error("Run() should fail")
	}
	if result.Error != "fail" {
		t.Errorf("Run() Error = %q, want fail", result.Error)
	}
}

func TestRun_InvalidIndex(t *testing.T) {
	f := &Fix{Actions: []Action{{Label: "a"}}}
	result := f.Run(Context{}, 5)
	if result.Success {
		t.Error("Run(invalid index) should fail")
	}
	if result.Error == "" {
		t.Error("Run(invalid index) should have error message")
	}
}

func TestRegistry_Lookup(t *testing.T) {
	r := New()
	r.Register(&Fix{FindingID: "trivy.ds001"})
	if r.Lookup("trivy.ds001") == nil {
		t.Error("Lookup(trivy.ds001) should find fix")
	}
	if r.Lookup("TRIVY.DS001") == nil {
		t.Error("Lookup(TRIVY.DS001) should be case-insensitive")
	}
	if r.Lookup("nonexistent") != nil {
		t.Error("Lookup(nonexistent) should return nil")
	}
}

func TestRegistry_Classify_Auto(t *testing.T) {
	r := New()
	r.Register(&Fix{FindingID: "test.auto", Actions: []Action{{Type: ActionEdit}}})
	r.Register(&Fix{FindingID: "test.review", Actions: []Action{{Type: ActionEdit}, {Type: ActionEdit}}})

	findings := []domain.Finding{
		{ID: "test.auto", Remediation: domain.RemediationUnavailable},
		{ID: "test.review", Remediation: domain.RemediationUnavailable},
		{ID: "test.none", Remediation: domain.RemediationUnavailable},
	}
	r.Classify(findings)

	wants := []domain.RemediationKind{
		domain.RemediationAuto,
		domain.RemediationReview,
		domain.RemediationUnavailable,
	}
	for i, want := range wants {
		if findings[i].Remediation != want {
			t.Errorf("findings[%d].Remediation = %v, want %v", i, findings[i].Remediation, want)
		}
	}
}

func TestRegistry_Classify_Empty(t *testing.T) {
	r := New()
	r.Classify(nil)
	// should not panic
}

func TestContext_ComposePath(t *testing.T) {
	ctx := Context{Finding: &domain.Finding{Metadata: map[string]string{"compose_path": "/a/b.yml"}}}
	if got := ctx.ComposePath(); got != "/a/b.yml" {
		t.Errorf("ComposePath() = %q, want /a/b.yml", got)
	}
}

func TestContext_ComposePath_Empty(t *testing.T) {
	ctx := Context{}
	if got := ctx.ComposePath(); got != "" {
		t.Errorf("ComposePath() = %q, want empty", got)
	}
}

func TestFixResult_String_Success(t *testing.T) {
	r := FixResult{Success: true, Label: "fixed it"}
	s := r.String()
	if s != "✓ fixed it" {
		t.Errorf("String() = %q, want '✓ fixed it'", s)
	}
}

func TestFixResult_String_Error(t *testing.T) {
	r := FixResult{Error: "something broke"}
	s := r.String()
	if s != "✗ : something broke" {
		t.Errorf("String() = %q, want '✗ : something broke'", s)
	}
}

func TestRegisterAll(t *testing.T) {
	r := New()
	RegisterAll(r)
	// spot-check a few known entries (v2.5.0: IDs match Lynis 3.1.6 semantics)
	for _, id := range []string{
		"compose.ds001",
		"compose.dr001",
		"lynis.AUTH-9286", // min/max password age
		"lynis.ACCT-9626", // sysstat
		"trivy.cve-*",
	} {
		if r.Lookup(id) == nil {
			t.Errorf("RegisterAll did not register %s", id)
		}
	}
}

func TestRegisterAll_Classification(t *testing.T) {
	r := New()
	RegisterAll(r)
	// ds001 = 1 action, ActionEdit → Auto
	fix := r.Lookup("compose.ds001")
	if fix == nil {
		t.Fatal("compose.ds001 not registered")
	}
	if got := fix.Class(); got != domain.RemediationAuto {
		t.Errorf("compose.ds001 class = %v, want Auto", got)
	}

	// dr001 = 2 actions → Review
	review := r.Lookup("compose.dr001")
	if review == nil {
		t.Fatal("compose.dr001 not registered")
	}
	if got := review.Class(); got != domain.RemediationReview {
		t.Errorf("compose.dr001 class = %v, want Review", got)
	}
}

func TestRegisterAll_DockerSocketAndSensitiveMountClassification(t *testing.T) {
	r := New()
	RegisterAll(r)

	// ds016 (Docker socket mount) = 1 action → Auto, with a warning since
	// removing the mount can break services that depend on it.
	socket := r.Lookup("compose.ds016")
	if socket == nil {
		t.Fatal("compose.ds016 not registered")
	}
	if got := socket.Class(); got != domain.RemediationAuto {
		t.Errorf("compose.ds016 class = %v, want Auto", got)
	}
	if len(socket.Actions) == 0 || socket.Actions[0].Warning == "" {
		t.Error("compose.ds016 action should have a warning (removing Docker API access)")
	}

	// ds017 (sensitive host mount) = 2 actions → Review (ro vs remove are
	// independent alternatives, not stages).
	sensitive := r.Lookup("compose.ds017")
	if sensitive == nil {
		t.Fatal("compose.ds017 not registered")
	}
	if got := sensitive.Class(); got != domain.RemediationReview {
		t.Errorf("compose.ds017 class = %v, want Review", got)
	}
}

func TestRegisterAll_DatastoreAndAdminPanelClassification(t *testing.T) {
	r := New()
	RegisterAll(r)

	// ds018 (unauthenticated datastore exposed) = 1 action → Auto, with a
	// warning since removing the port mapping can break intentional
	// external access.
	datastore := r.Lookup("compose.ds018")
	if datastore == nil {
		t.Fatal("compose.ds018 not registered")
	}
	if got := datastore.Class(); got != domain.RemediationAuto {
		t.Errorf("compose.ds018 class = %v, want Auto", got)
	}
	if len(datastore.Actions) == 0 || datastore.Actions[0].Warning == "" {
		t.Error("compose.ds018 action should have a warning (removing external access)")
	}

	// ds019 (admin panel exposed) = 2 actions → Review (localhost-bind vs
	// remove are independent alternatives).
	panel := r.Lookup("compose.ds019")
	if panel == nil {
		t.Fatal("compose.ds019 not registered")
	}
	if got := panel.Class(); got != domain.RemediationReview {
		t.Errorf("compose.ds019 class = %v, want Review", got)
	}
}

func TestRegisterAll_SystemFixes(t *testing.T) {
	r := New()
	RegisterAll(r)
	// v2.5.0: IDs match Lynis 3.1.6 semantics
	for _, id := range []string{
		"lynis.AUTH-9328", // umask
		"lynis.ACCT-9626", // sysstat
		"lynis.ACCT-9622", // process accounting
		"lynis.NETW-3200", // dccp/sctp/rds/tipc
	} {
		if r.Lookup(id) == nil {
			t.Errorf("RegisterAll did not register %s", id)
		}
	}
}

func TestRegisterAll_SystemFixActionTypes(t *testing.T) {
	r := New()
	RegisterAll(r)

	// ACCT-9626 (sysstat) is now Review with 1 action (installPackage)
	fix := r.Lookup("lynis.ACCT-9626")
	if fix == nil || len(fix.Actions) == 0 {
		t.Fatal("ACCT-9626 not registered or has no actions")
	}
	if fix.Actions[0].Type != ActionExec {
		t.Errorf("ACCT-9626 action type = %v, want ActionExec", fix.Actions[0].Type)
	}

	// ACCT-9622 (process accounting) — installPackage
	fix = r.Lookup("lynis.ACCT-9622")
	if fix == nil || len(fix.Actions) == 0 {
		t.Fatal("ACCT-9622 not registered or has no actions")
	}
	if fix.Actions[0].Type != ActionExec {
		t.Errorf("ACCT-9622 action type = %v, want ActionExec", fix.Actions[0].Type)
	}

	// NETW-3200 (uncommon protocols) — modprobe
	fix = r.Lookup("lynis.NETW-3200")
	if fix == nil || len(fix.Actions) == 0 {
		t.Fatal("NETW-3200 not registered or has no actions")
	}
	if fix.Actions[0].Type != ActionExec {
		t.Errorf("NETW-3200 action type = %v, want ActionExec", fix.Actions[0].Type)
	}
}

func TestRegisterAll_WarningPreserved(t *testing.T) {
	r := New()
	RegisterAll(r)
	fix := r.Lookup("compose.ds003") // pid_mode: host
	if fix == nil {
		t.Fatal("compose.ds003 not registered")
	}
	if len(fix.Actions) == 0 || fix.Actions[0].Warning == "" {
		t.Error("compose.ds003 action should have a warning")
	}
}

func TestRegistry_WildcardMatch(t *testing.T) {
	r := New()
	r.Register(&Fix{FindingID: "trivy.cve-*", Actions: []Action{{Type: ActionEdit}}})
	r.Register(&Fix{FindingID: "lynis.AUTH-*", Actions: []Action{{Type: ActionExec}}})

	if f := r.Lookup("trivy.cve-2024-12345"); f == nil {
		t.Error("Lookup(trivy.cve-2024-12345) should match trivy.cve-*")
	}
	if f := r.Lookup("trivy.cve-2023-54321"); f == nil {
		t.Error("Lookup(trivy.cve-2023-54321) should match trivy.cve-*")
	}
	if f := r.Lookup("lynis.AUTH-9999"); f == nil {
		t.Error("Lookup(lynis.AUTH-9999) should match lynis.AUTH-*")
	}
	if f := r.Lookup("trivy.ds001"); f != nil {
		t.Error("Lookup(trivy.ds001) should NOT match any wildcard (ds001)")
	}
}

func TestRegistry_WildcardExactLookup(t *testing.T) {
	r := New()
	r.Register(&Fix{FindingID: "trivy.cve-*", Actions: []Action{{Type: ActionEdit}}})
	r.Register(&Fix{FindingID: "trivy.cve-*-base", Actions: []Action{{Type: ActionExec}}})
	r.Register(&Fix{FindingID: "trivy.ds001", Actions: []Action{{Type: ActionExec}}})

	if f := r.Lookup("trivy.cve-*"); f == nil {
		t.Error("exact lookup of wildcard pattern should find itself")
	}
	if f := r.Lookup("trivy.ds001"); f == nil {
		t.Error("exact lookup should still work alongside wildcards")
	}
	if f := r.Lookup("trivy.cve-*-base"); f == nil {
		t.Error("wildcard pattern with multiple special chars should be findable")
	}
}

func TestRegistry_WildcardClassify(t *testing.T) {
	r := New()
	r.Register(&Fix{FindingID: "trivy.cve-*", Actions: []Action{{Type: ActionEdit}}})

	findings := []domain.Finding{
		{ID: "trivy.cve-2024-12345", Remediation: domain.RemediationUnavailable},
		{ID: "trivy.cve-2023-99999", Remediation: domain.RemediationUnavailable},
		{ID: "trivy.ds001", Remediation: domain.RemediationUnavailable},
	}
	r.Classify(findings)

	if findings[0].Remediation != domain.RemediationAuto {
		t.Errorf("CVE-2024-12345 should be Auto, got %v", findings[0].Remediation)
	}
	if findings[1].Remediation != domain.RemediationAuto {
		t.Errorf("CVE-2023-99999 should be Auto, got %v", findings[1].Remediation)
	}
	if findings[2].Remediation != domain.RemediationUnavailable {
		t.Errorf("ds001 should remain Unavailable (unregistered), got %v", findings[2].Remediation)
	}
}
