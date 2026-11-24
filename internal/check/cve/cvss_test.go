package cve

import (
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func vuln(sev string, vectors ...string) trivyVuln {
	v := trivyVuln{VulnerabilityID: "CVE-1", Severity: sev}
	if len(vectors) > 0 {
		v.CVSS = map[string]cvssScore{}
		for i, vec := range vectors {
			v.CVSS[string(rune('a'+i))] = cvssScore{V3Vector: vec}
		}
	}
	return v
}

// Hostveil's High is remote, unauthenticated and needs nobody's help; the
// CVSS base metrics state exactly that, so they decide.
func TestSeverityFollowsTheCVSSVector(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    trivyVuln
		want model.Severity
	}{
		{"remote, no credentials, no user", vuln("CRITICAL", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), model.SeverityHigh},
		{"a local account", vuln("HIGH", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), model.SeverityMedium},
		{"needs a login", vuln("HIGH", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), model.SeverityMedium},
		{"needs a click", vuln("HIGH", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"), model.SeverityMedium},
		{"one source says remote", vuln("HIGH", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), model.SeverityHigh},
		{"no vector", vuln("HIGH"), model.SeverityHigh},
		{"never raised", vuln("MEDIUM", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), model.SeverityMedium},
		{"v4 vector", trivyVuln{Severity: "HIGH", CVSS: map[string]cvssScore{"nvd": {V40Vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}}, model.SeverityMedium},
	} {
		if got := severityOf(tc.v); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The vectors survive the cache: a report read back gives the same severity.
func TestCompactReportKeepsTheVectors(t *testing.T) {
	raw := []byte(`{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"HIGH","Description":"long text",
		"CVSS":{"nvd":{"V3Vector":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","V3Score":7.8}}}]}]}`)
	out, err := compactReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := parseTrivy(out, target{image: "x:1", service: "x", file: "/x/docker-compose.yml", project: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Severity != model.SeverityMedium {
		t.Fatalf("a local-only vulnerability read back from the cache is Medium, got %v", fs)
	}
}
