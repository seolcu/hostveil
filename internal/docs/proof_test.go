package docs

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/fix/fixtest"
	"github.com/seolcu/hostveil/internal/model"
)

// This file is measurements_test.go's idea applied to the other kind of
// published number.
//
// A figure off a measurement run is checked against the committed JSON. A
// figure about the *program* — how many findings it can report, how many of
// them it can fix, how many fuzz targets run nightly — had nowhere to be
// checked against, so it was published nowhere: the fix coverage appeared only
// inside a release note, and the testing regime appeared in no README and on no
// page. Those are among the strongest things here and a visitor could not find
// any of them.
//
// The rule is the same as for a measurement: a number may be published only
// where something computes it. Pages carry
//
//	<td data-counted="findings.fixable">38</td>
//
// and the READMEs carry a phrase built from the same quantities, because a
// data attribute does not reach Markdown.
var countedCell = regexp.MustCompile(`<[^<>]*data-counted="([^"]+)"[^<>]*>([^<]*)<`)

// counts derives every publishable quantity from the code that owns it.
//
// Nothing here is a literal. The whole point is that adding a checker, or
// registering a fix for a finding that did not have one, moves these numbers
// and fails the build until the pages move with them — which is the mechanism
// that has caught the domain table, the axis labels and the fuzz matrix
// falling behind, applied to the figures that had no mechanism at all.
func counts(t *testing.T) map[string]int {
	t.Helper()

	ids := emittedFindingIDs(t)
	registry := fix.Default()

	var fixable, auto, review int
	// These checkers deliberately demand Review even though the registered
	// fix has Auto's one-action shape. Counts are user-facing classifications,
	// so resolve the same caution floor Engine.classify applies instead of
	// publishing the registry shape as though it were the screen value.
	checkerReview := map[string]bool{
		"ssh.passwordauth": true, "ssh.gatewayports": true,
		"ssh.hostbasedauth": true, "ssh.kbdinteractive": true,
		"ssh.permituserenvironment": true, "ssh.permittunnel": true,
		"ssh.allowtcpforwarding": true, "ssh.maxsessions": true,
		"ssh.allowagentforwarding": true,
		"accounts.local-banner":    true, "accounts.remote-banner": true,
		"sysctl.module-dccp": true, "sysctl.module-sctp": true,
		"sysctl.module-rds": true, "sysctl.module-tipc": true,
		"sysctl.module-usbstorage": true,
		"fileperms.compiler":       true,
		"ports.redis-bind":         true, "ports.redis-disable-config": true,
		"agent.exec-unrestricted": true, "systemd.no-new-privileges": true,
		"systemd.protect-clock": true, "systemd.lock-personality": true,
		"systemd.restrict-suid-sgid": true, "systemd.protect-kernel-logs": true,
		"systemd.protect-kernel-modules": true,
	}
	for _, id := range ids {
		fx, ok, err := registry.Build(fixtest.Finding(id))
		if err != nil || !ok {
			continue
		}
		fixable++
		kind := fx.EffectiveKind()
		if checkerReview[id] && kind < model.RemediationReview {
			kind = model.RemediationReview
		}
		switch kind {
		case model.RemediationAuto:
			auto++
		case model.RemediationReview:
			review++
		}
	}

	return map[string]int{
		"findings.total":   len(ids),
		"findings.fixable": fixable,
		"findings.auto":    auto,
		"findings.review":  review,
		"findings.manual":  len(ids) - fixable,
		"domains.total":    len(model.AllSources()),
		"fuzz.targets":     len(fuzzTargets(t)),
	}
}

// A sanity floor, so a harvester that silently stops finding anything cannot
// make every claim below vacuously true. emittedFindingIDs walking the wrong
// directory would otherwise publish "0 findings" and pass.
func TestTheCountsAreNotAccidentallyZero(t *testing.T) {
	for name, n := range counts(t) {
		if n == 0 {
			t.Errorf("%s counted 0 — either the harvester broke or the claim is not worth "+
				"publishing; both fail here rather than reaching a page", name)
		}
	}
}

func TestEveryPublishedCountIsComputedFromTheCode(t *testing.T) {
	want := counts(t)
	var seen int

	for _, page := range countedPages() {
		for _, c := range countedCell.FindAllStringSubmatch(readRepoFile(t, page), -1) {
			key, shown := c[1], strings.TrimSpace(c[2])
			n, ok := want[key]
			if !ok {
				t.Errorf("%s: data-counted=%q is not a quantity counts() knows how to "+
					"compute, so nothing checks it", page, key)
				continue
			}
			seen++
			if shown != strconv.Itoa(n) {
				t.Errorf("%s says %q for %s, and the code says %d", page, shown, key, n)
			}
		}
	}
	if seen == 0 {
		t.Error("no page carries a data-counted cell, so this test proves nothing")
	}
}

func countedPages() []string {
	return []string{
		filepath.Join("cmd", "sitegen", "content", "en", "docs", "checks.html"),
		filepath.Join("cmd", "sitegen", "content", "ko", "docs", "checks.html"),
		filepath.Join("cmd", "sitegen", "content", "en", "docs", "faq.html"),
		filepath.Join("cmd", "sitegen", "content", "ko", "docs", "faq.html"),
	}
}

// countClaim is publishedProseClaims' shape for the counted quantities: one
// sentence a README makes, in its own words, with the figures filled in.
//
// Markdown has no attributes, and the READMEs are where most people read any
// of this. Requiring the phrase verbatim is stricter than checking the digits —
// it fails a README that quotes a right number inside a sentence that has
// stopped being true around it.
type countClaim struct {
	file   string
	what   string
	keys   []string
	phrase string
}

func publishedCountClaims() []countClaim {
	return []countClaim{
		{
			file:   "README.md",
			what:   "how much of what it finds it can also fix",
			keys:   []string{"findings.total", "findings.fixable", "findings.auto", "findings.review"},
			phrase: "**%s findings** across those domains, and **%s of them carry a fix** — %s Hostveil will apply unattended, %s only after you have read the diff",
		},
		{
			file:   "README.ko.md",
			what:   "how much of what it finds it can also fix",
			keys:   []string{"findings.total", "findings.fixable", "findings.auto", "findings.review"},
			phrase: "이 영역들에서 **발견 항목 %s개**를 보고할 수 있고, 그중 **%s개에 수정이 붙어 있습니다.** %s개는 무인으로 적용하고, %s개는 차이를 읽은 뒤에만 적용합니다",
		},
		{
			file:   "README.md",
			what:   "how many fuzz targets run nightly",
			keys:   []string{"fuzz.targets"},
			phrase: "%s fuzz targets",
		},
		{
			file:   "README.ko.md",
			what:   "how many fuzz targets run nightly",
			keys:   []string{"fuzz.targets"},
			phrase: "퍼즈 타깃 %s개",
		},
	}
}

func TestEveryReadmeCountClaimIsComputedFromTheCode(t *testing.T) {
	want := counts(t)

	for _, c := range publishedCountClaims() {
		args := make([]any, 0, len(c.keys))
		for _, k := range c.keys {
			n, ok := want[k]
			if !ok {
				t.Fatalf("%s: counts() has no %q", c.file, k)
			}
			args = append(args, strconv.Itoa(n))
		}
		phrase := c.phrase
		for _, a := range args {
			phrase = strings.Replace(phrase, "%s", a.(string), 1)
		}
		if !strings.Contains(normalizeSpace(readRepoFile(t, c.file)), normalizeSpace(phrase)) {
			t.Errorf("%s does not state %s the way the code counts it.\n  want the phrase: %s",
				c.file, c.what, phrase)
		}
	}
}

// normalizeSpace collapses runs of whitespace, so a claim may wrap wherever the
// file wants it to.
var spaceRun = regexp.MustCompile(`\s+`)

func normalizeSpace(s string) string { return spaceRun.ReplaceAllString(s, " ") }

// TestThereIsMoreTestCodeThanProductCode.
//
// Published as a property rather than as two line counts, because the counts
// move on every commit and a page that names them would be wrong by the
// afternoon. The inequality is the claim worth making and it is the one that
// can be kept true.
//
// It is a real statement about this repository and it was written down nowhere
// a reader could find it, which is the gap this whole file exists to close.
func TestThereIsMoreTestCodeThanProductCode(t *testing.T) {
	test, product := goLines(t)
	if test <= product {
		t.Errorf("the READMEs claim more test code than product code, and there are now "+
			"%d lines of tests against %d of product. Either write the tests or delete the "+
			"claim — a published property nobody maintains is worse than one nobody made.",
			test, product)
	}
}

// goLines counts lines of Go, split by whether the file is a test.
//
// Deliberately crude: it counts every line, comments and blanks included,
// because the claim is about how much of this repository is given over to
// checking itself, and a doc comment explaining why a test exists is part of
// that. A precise metric would be a different claim.
func goLines(t *testing.T) (test, product int) {
	t.Helper()
	root := repoRoot(t)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "site" || name == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		n := bytes.Count(b, []byte("\n"))
		if strings.HasSuffix(path, "_test.go") {
			test += n
			return nil
		}
		product += n
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if test == 0 || product == 0 {
		t.Fatal("counted no Go at all, so the inequality below would be meaningless")
	}
	return test, product
}
