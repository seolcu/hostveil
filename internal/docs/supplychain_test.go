package docs

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Supply-chain integrity is the one claim on this site a reader cannot check
// from the outside without acting on it.
//
// Every other published figure describes something — a score, a measured run —
// that is wrong if the number is wrong. "Every release carries a signed build
// provenance attestation" is different: a reader who believes it stops
// checking, and a reader who checks and finds nothing has been told to trust a
// binary running as root on the strength of a sentence.
//
// So the sentence answers to the pipeline. If a page says SBOM, .goreleaser
// must produce one; if it says provenance, release.yml must mint one; and the
// verify command a page prints has to name this repository, not an example.
func TestEveryPublishedSupplyChainClaimMatchesTheReleasePipeline(t *testing.T) {
	goreleaser := readRepoFile(t, ".goreleaser.yaml")
	release := readRepoFile(t, filepath.Join(".github", "workflows", "release.yml"))

	for _, page := range supplyChainPages() {
		body := readRepoFile(t, page)
		if strings.Contains(strings.ToLower(body), "sbom") && !strings.Contains(goreleaser, "sboms:") {
			t.Errorf("%s promises an SBOM and .goreleaser.yaml has no sboms: block", page)
		}
		if !mentionsProvenance(body) {
			continue
		}
		if !strings.Contains(release, "attest-build-provenance") {
			t.Errorf("%s promises build provenance and release.yml never mints an attestation", page)
		}
		if !strings.Contains(release, "attestations: write") {
			t.Errorf("%s promises build provenance and release.yml lacks the attestations: write "+
				"permission, so the step cannot sign anything", page)
		}
	}
}

// TestEveryVerifyCommandNamesThisRepository.
//
// `gh attestation verify … --repo X` is a command a reader copies and runs.
// Against the wrong X it fails, and the natural conclusion from a failed
// verification is that the download is bad — so a typo here reads as evidence
// of exactly the compromise the command exists to rule out.
func TestEveryVerifyCommandNamesThisRepository(t *testing.T) {
	mod := readRepoFile(t, "go.mod")
	m := regexp.MustCompile(`(?m)^module\s+github\.com/(\S+)\s*$`).FindStringSubmatch(mod)
	if m == nil {
		t.Fatal("could not read the module path out of go.mod")
	}
	repo := m[1]

	verify := regexp.MustCompile(`gh attestation verify\s+\S+\s+--repo\s+([^\s<]+)`)
	var checked int
	for _, page := range append(supplyChainPages(), "README.md", "README.ko.md") {
		for _, hit := range verify.FindAllStringSubmatch(readRepoFile(t, page), -1) {
			checked++
			if hit[1] != repo {
				t.Errorf("%s tells the reader to verify against --repo %s; this repository is %s. "+
					"A failed verification reads as a tampered download.", page, hit[1], repo)
			}
		}
	}
	if checked == 0 {
		t.Errorf("no `gh attestation verify` command is published anywhere. Every release ships "+
			"a signed attestation and %d pages describe the supply chain; if none of them says "+
			"how to check it, the attestation is doing nothing for a reader.", len(supplyChainPages()))
	}
}

// supplyChainPages are the pages that make a claim about how releases are
// built. The installation pages are where a reader is asked to trust one.
func supplyChainPages() []string {
	var out []string
	for _, lang := range []string{"en", "ko"} {
		for _, slug := range []string{"installation", "cli"} {
			out = append(out, filepath.Join("cmd", "sitegen", "content", lang, "docs", slug+".html"))
		}
		out = append(out, filepath.Join("cmd", "sitegen", "content", lang, "index.html"))
	}
	return out
}

func mentionsProvenance(body string) bool {
	low := strings.ToLower(body)
	return strings.Contains(low, "provenance") || strings.Contains(low, "프로버넌스")
}
