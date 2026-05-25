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

func TestClass_Manual(t *testing.T) {
	f := &Fix{Actions: []Action{{Type: ActionPrompt}}}
	if got := f.Class(); got != domain.RemediationManual {
		t.Errorf("Class(prompt) = %v, want Manual", got)
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
	// spot-check a few known entries
	for _, id := range []string{
		"trivy.ds001",
		"trivy.dr001",
		"lynis.AUTH-9286",
		"lynis.FIRE-4512",
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
	fix := r.Lookup("trivy.ds001")
	if fix == nil {
		t.Fatal("trivy.ds001 not registered")
	}
	if got := fix.Class(); got != domain.RemediationAuto {
		t.Errorf("trivy.ds001 class = %v, want Auto", got)
	}

	// dr001 = 2 actions → Review
	review := r.Lookup("trivy.dr001")
	if review == nil {
		t.Fatal("trivy.dr001 not registered")
	}
	if got := review.Class(); got != domain.RemediationReview {
		t.Errorf("trivy.dr001 class = %v, want Review", got)
	}
}

func TestRegisterAll_WarningPreserved(t *testing.T) {
	r := New()
	RegisterAll(r)
	fix := r.Lookup("trivy.ds003") // pid_mode: host
	if fix == nil {
		t.Fatal("trivy.ds003 not registered")
	}
	if len(fix.Actions) == 0 || fix.Actions[0].Warning == "" {
		t.Error("trivy.ds003 action should have a warning")
	}
}
