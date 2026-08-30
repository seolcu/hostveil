package report

import (
	"strings"
	"testing"
)

func markdownOf(t *testing.T) string {
	t.Helper()
	data, _, err := Export(sampleReport(), "v-test", "markdown")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestMarkdownHeaderAndFooterCarryVersion(t *testing.T) {
	got := markdownOf(t)
	if !strings.Contains(got, "# hostveil security report") {
		t.Error("missing title heading")
	}
	if !strings.Contains(got, "v-test") {
		t.Error("build version does not appear in the header/footer")
	}
	if !strings.Contains(got, "No AI was used to produce this report") {
		t.Error("missing the no-AI disclosure in the footer")
	}
}

func TestMarkdownFindingsCarryPlainLanguageContent(t *testing.T) {
	got := markdownOf(t)

	if !strings.Contains(got, "SSH permits root login with a password") {
		t.Error("High finding title missing")
	}
	if !strings.Contains(got, "An attacker who guesses or steals the root password can log in directly.") {
		t.Error("Description text missing verbatim")
	}
	if !strings.Contains(got, "Set PermitRootLogin to no or prohibit-password in sshd_config.") {
		t.Error("HowToFix text missing verbatim")
	}
	if !strings.Contains(got, "| PermitRootLogin | yes |") {
		t.Error("evidence table row missing")
	}

	// The fixed finding must not appear at all.
	if strings.Contains(got, "X11 forwarding is enabled") {
		t.Error("a fixed finding must be excluded from the export")
	}

	// The Manual finding with no fix explains why, not how.
	if !strings.Contains(got, "Why hostveil won't do this for you.") {
		t.Error("Manual finding should render WhyNoFix, not a fix section")
	}
	if !strings.Contains(got, "Removing the mount would break the container's intended function") {
		t.Error("WhyNoFix text missing verbatim")
	}
}

func TestMarkdownFindingsCarryTheFixTradeOff(t *testing.T) {
	got := markdownOf(t)

	if !strings.Contains(got, "**Benefit.** Keeps key-based root access working") {
		t.Error("the High finding's FixBenefit is missing")
	}
	if !strings.Contains(got, "**Side effect.** Keep a working key for root") {
		t.Error("the High finding's FixSideEffect is missing")
	}

	// The Manual finding has no registered fix, so it must show neither
	// heading — inventing a trade-off for a fix that does not exist would
	// be worse than saying nothing.
	mediumSection := got[strings.Index(got, "Container has the Docker socket mounted"):]
	if strings.Contains(mediumSection, "**Benefit.**") || strings.Contains(mediumSection, "**Side effect.**") {
		t.Error("a finding with no registered fix must not render Benefit/Side effect")
	}
}

func TestMarkdownCallsOutASkippedDomain(t *testing.T) {
	got := markdownOf(t)
	if !strings.Contains(got, "trivy is not installed") {
		t.Error("a skipped domain's reason must be visible, not silently dropped")
	}
	if !strings.Contains(got, "Domains scanned") {
		t.Error("missing the domains-scanned section")
	}
}

func TestMarkdownSeverityLegendUsesSeverityDescription(t *testing.T) {
	got := markdownOf(t)
	if !strings.Contains(got, "Nothing has to be broken first.") {
		t.Error("severity legend should include SeverityHigh's description")
	}
}

func TestMarkdownGroupsFindingsSeverityFirst(t *testing.T) {
	got := markdownOf(t)
	highIdx := strings.Index(got, "### High")
	medIdx := strings.Index(got, "### Medium")
	if highIdx == -1 || medIdx == -1 {
		t.Fatalf("expected both a High and a Medium group heading, got:\n%s", got)
	}
	if highIdx > medIdx {
		t.Error("High findings should be grouped before Medium")
	}
}
