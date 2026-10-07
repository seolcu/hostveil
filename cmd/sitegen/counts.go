package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/fix/fixtest"
	"github.com/seolcu/hostveil/internal/model"
)

// The checks page's Fix column and the counts beside it used to be typed by
// hand and checked by tests, so every fix registered meant editing ten places
// in step: two tables, eight counts, two bar widths, two README sentences.
// The tests caught every miss and fixed none of them. Everything here is
// computed from the registry instead, and `go run ./cmd/sitegen` writes it
// into the source pages and the READMEs as well as the site, so the files a
// reader and the tests both read say what the registry says.

// dependsOnFinding names the fixes whose kind the registry cannot settle from
// a representative finding, and what the table shows for them.
// agent.exec-unrestricted reads its safe values out of the finding: Review
// when tools.exec.security tripped, which offers two, and Auto when only
// tools.exec.ask did. The table describes the first, the case with a choice.
var dependsOnFinding = map[string]model.RemediationKind{
	"agent.exec-unrestricted": model.RemediationReview,
}

// shownKind is the remediation a user is shown for id, as far as the
// registry can say without a host. The registry reports the kind classify
// settles on (fix.checkerDeclaresReview floors the fixes whose checker always
// asks for Review), so this is EffectiveKind, or Manual where nothing is
// registered.
func shownKind(r *fix.Registry, id string) model.RemediationKind {
	if k, ok := dependsOnFinding[id]; ok {
		return k
	}
	fx, ok, err := r.Build(fixtest.Finding(id))
	if err != nil || !ok {
		return model.RemediationManual
	}
	return fx.EffectiveKind()
}

// tally is how the findings on the checks page resolve.
type tally struct{ total, auto, review, other int }

func (t tally) fixable() int { return t.auto + t.review }

func (t tally) value(key string) (int, bool) {
	switch key {
	case "findings.total":
		return t.total, true
	case "findings.fixable":
		return t.fixable(), true
	case "findings.auto":
		return t.auto, true
	case "findings.review":
		return t.review, true
	case "findings.manual":
		return t.other, true
	}
	return 0, false
}

// percents splits 100 across the three bars so they always sum to 100.
func (t tally) percents() (auto, review, other int) {
	if t.total == 0 {
		return 0, 0, 0
	}
	auto = (t.auto*100 + t.total/2) / t.total
	review = (t.review*100 + t.total/2) / t.total
	return auto, review, 100 - auto - review
}

var (
	fixCell     = regexp.MustCompile(`(<tr><td><code>([a-z0-9.\-]+)</code></td>.*?<td>)([^<]*)(</td></tr>)`)
	countedSpan = regexp.MustCompile(`(data-counted="(findings\.[a-z]+)">)[0-9]+(<)`)
	barFill     = regexp.MustCompile(`(ledger-bar-fill (signal|warning|muted)" style="--pct:)[0-9]+(%")`)
)

// syncChecks rewrites the checks page's Fix column and every findings count
// on it from the registry, and returns how the findings resolve.
//
// An Unavailable cell is left as written: the registry has no fix for it
// either way, and Unavailable — nobody can fix it, not only hostveil — is a
// fact about the finding the registry does not record.
func syncChecks(frag, lang string, r *fix.Registry) (string, tally, error) {
	labels := kindLabels[lang]
	var t tally
	frag = fixCell.ReplaceAllStringFunc(frag, func(m string) string {
		sub := fixCell.FindStringSubmatch(m)
		id, cell := sub[2], sub[3]
		t.total++
		if cell == labels[model.RemediationUnavailable] {
			t.other++
			return m
		}
		k := shownKind(r, id)
		switch k {
		case model.RemediationAuto:
			t.auto++
		case model.RemediationReview:
			t.review++
		default:
			t.other++
		}
		return sub[1] + labels[k] + sub[4]
	})
	if t.total == 0 {
		return "", t, fmt.Errorf("checks page (%s): no finding rows found; the table markup changed", lang)
	}
	frag = countedSpan.ReplaceAllStringFunc(frag, func(m string) string {
		sub := countedSpan.FindStringSubmatch(m)
		n, ok := t.value(sub[2])
		if !ok {
			return m
		}
		return sub[1] + strconv.Itoa(n) + sub[3]
	})
	auto, review, other := t.percents()
	pct := map[string]int{"signal": auto, "warning": review, "muted": other}
	frag = barFill.ReplaceAllStringFunc(frag, func(m string) string {
		sub := barFill.FindStringSubmatch(m)
		return sub[1] + strconv.Itoa(pct[sub[2]]) + sub[3]
	})
	return frag, t, nil
}

// readmeCounts is the sentence each README makes about the counts, with the
// figures in order: total, fixable, auto, review. internal/docs holds the
// READMEs to the same wording independently.
var readmeCounts = map[string]struct{ file, sentence string }{
	"en": {"README.md", "Hostveil can report **%d findings** across those domains, and **%d of them\ncarry a fix** — %d Hostveil will apply unattended, %d only after you have read\nthe diff."},
	"ko": {"README.ko.md", "Hostveil은 이 영역들에서 **발견 항목 %d개**를 보고할 수 있고, 그중 **%d개에\n수정이 붙어 있습니다.** %d개는 무인으로 적용하고, %d개는 차이를 읽은 뒤에만\n적용합니다."},
}

const (
	countsStart = "<!-- hostveil:counts -->"
	countsEnd   = "<!-- /hostveil:counts -->"
)

// syncSources writes the computed Fix column and counts back into the source
// pages and the READMEs, when sitegen is run from the repository root. It is
// what makes one `go run ./cmd/sitegen` the whole job after registering a
// fix: the embedded copy this run renders from is synced in memory by the same
// function, so the site is right on this run and the sources are right for the
// next.
func syncSources(r *fix.Registry) error {
	for _, lang := range []string{"en", "ko"} {
		page := filepath.Join("cmd", "sitegen", "content", lang, "docs", "checks.html")
		b, err := os.ReadFile(page) //nolint:gosec // G304: a fixed path in this repository
		if os.IsNotExist(err) {
			continue // not run from the repository root; the site is still synced in memory
		}
		if err != nil {
			return err
		}
		synced, t, err := syncChecks(string(b), lang, r)
		if err != nil {
			return err
		}
		if err := writeIfChanged(page, b, []byte(synced)); err != nil {
			return err
		}
		if err := syncReadme(readmeCounts[lang].file, readmeCounts[lang].sentence, t); err != nil {
			return err
		}
	}
	return nil
}

func syncReadme(path, sentence string, t tally) error {
	b, err := os.ReadFile(path) //nolint:gosec // G304: a fixed path in this repository
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	s := string(b)
	i, j := strings.Index(s, countsStart), strings.Index(s, countsEnd)
	if i < 0 || j < i {
		return fmt.Errorf("%s has no %s … %s block for the counts", path, countsStart, countsEnd)
	}
	body := fmt.Sprintf(sentence, t.total, t.fixable(), t.auto, t.review)
	out := s[:i+len(countsStart)] + "\n" + body + "\n" + s[j:]
	return writeIfChanged(path, b, []byte(out))
}

func writeIfChanged(path string, old, next []byte) error {
	if bytes.Equal(old, next) {
		return nil
	}
	//nolint:gosec // G306: a tracked source file in this repository, as readable as the rest
	return os.WriteFile(path, next, 0o644)
}
