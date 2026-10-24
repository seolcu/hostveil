package triage

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	forensiccheck "github.com/seolcu/hostveil/internal/check/forensic"
	"github.com/seolcu/hostveil/internal/platform"
)

// Run collects a bundle, analyses it, writes the analysis beside it, and
// seals the manifest. It returns the result and the manifest's SHA-256,
// which the caller shows the operator to record elsewhere.
func Run(ctx context.Context, opts Options, env platform.Env) (*Result, *Manifest, string, error) {
	opts.Runner = env.Runner
	m, err := Collect(ctx, opts)
	if err != nil {
		return nil, nil, "", err
	}
	readiness(ctx, opts, env, m)
	m.FinishedUTC = opts.Now().UTC()
	if err := writeManifest(opts.Out, m); err != nil {
		return nil, nil, "", err
	}

	res, _, err := Analyze(opts.Out)
	if err != nil {
		return nil, nil, "", err
	}
	files, err := writeAnalysis(opts.Out, res, m)
	if err != nil {
		return nil, nil, "", err
	}
	for _, f := range files {
		sum, _ := hashFile(filepath.Join(opts.Out, f))
		st, _ := os.Stat(filepath.Join(opts.Out, f))
		size := int64(0)
		if st != nil {
			size = st.Size()
		}
		m.Artifacts = append(m.Artifacts, Artifact{Name: "analysis", Path: f, Kind: "derived", SHA256: sum, Size: size, CollectedAt: opts.Now().UTC()})
	}
	m.AnalysisFiles = files
	if err := writeManifest(opts.Out, m); err != nil {
		return nil, nil, "", err
	}
	seal, err := hashFile(filepath.Join(opts.Out, "manifest.json"))
	return res, m, seal, err
}

// readiness runs the forensic-readiness checker against the live host and
// stores its findings in the bundle, so the gaps it implies can be derived
// from the bundle later like everything else.
func readiness(ctx context.Context, opts Options, env platform.Env, m *Manifest) {
	a := Artifact{Name: "readiness", Path: "artifacts/readiness.json", Phase: 3, Kind: "derived", Source: "hostveil forensic-readiness checker"}
	chk := &forensiccheck.Checker{Root: opts.Root}
	fs, err := chk.Check(ctx, env)
	if err != nil {
		a.Error = err.Error()
	}
	type row struct{ ID, Title, Description string }
	var rows []row
	for _, f := range fs {
		rows = append(rows, row{f.ID, f.Title, f.Description})
	}
	data, _ := json.MarshalIndent(rows, "", "  ")
	_ = os.WriteFile(filepath.Join(opts.Out, a.Path), data, 0o400)
	sum := sha256.Sum256(data)
	a.SHA256, a.Size, a.CollectedAt = hex.EncodeToString(sum[:]), int64(len(data)), opts.Now().UTC()
	m.Artifacts = append(m.Artifacts, a)
}

func writeManifest(dir string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(dir, "manifest.json")
	_ = os.Chmod(p, 0o600)
	if err := os.WriteFile(p, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Chmod(p, 0o400)
}

func writeAnalysis(dir string, res *Result, m *Manifest) ([]string, error) {
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "indicators.json"), append(data, '\n'), 0o400); err != nil {
		return nil, err
	}
	var tl strings.Builder
	w := csv.NewWriter(&tl)
	_ = w.Write([]string{"time_utc", "source", "event", "artifact"})
	for _, e := range res.Timeline {
		_ = w.Write([]string{e.Time.Format(time.RFC3339), e.Source, e.What, e.Artifact})
	}
	w.Flush()
	if err := os.WriteFile(filepath.Join(dir, "timeline.csv"), []byte(tl.String()), 0o400); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(Report(res, m)), 0o400); err != nil {
		return nil, err
	}
	return []string{"indicators.json", "timeline.csv", "report.md"}, nil
}

// Report renders the analysis for a person.
func Report(res *Result, m *Manifest) string {
	var b strings.Builder
	c := res.Counts()
	fmt.Fprintf(&b, "# Triage of %s\n\n", m.Host)
	fmt.Fprintf(&b, "Collected %s to %s (UTC) by %s, looking back to %s.\n\n",
		m.StartedUTC.Format(time.RFC3339), m.FinishedUTC.Format(time.RFC3339), m.Operator, m.Since.Format("2006-01-02"))
	switch {
	case c[Compromise] > 0:
		fmt.Fprintf(&b, "**%d sign(s) of compromise.** Treat this host as compromised until each one below is explained. Do not reboot it or clean it up yet: keep this bundle, copy it off the host, and only then act.\n\n", c[Compromise])
	case c[Suspicious] > 0:
		fmt.Fprintf(&b, "**No sign of compromise, %d thing(s) to confirm.** Each suspicious item below is something a normal host also does; check that each matches something you did.\n\n", c[Suspicious])
	default:
		b.WriteString("**No sign of compromise in what this host recorded.** That is a statement about the evidence, not a guarantee — see the gaps below for what it could not see.\n\n")
	}
	fmt.Fprintf(&b, "| Verdict | Count |\n|---|---|\n| compromise | %d |\n| suspicious | %d |\n| attempt | %d |\n\n", c[Compromise], c[Suspicious], c[Attempt])

	for _, v := range []Verdict{Compromise, Suspicious, Attempt} {
		var ins []Indicator
		for _, in := range res.Indicators {
			if in.Verdict == v {
				ins = append(ins, in)
			}
		}
		if len(ins) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s\n\n", strings.ToUpper(string(v[:1]))+string(v[1:]))
		for _, in := range ins {
			fmt.Fprintf(&b, "### %s (`%s`)\n\n%s\n\n", in.Title, in.ID, in.Detail)
			for _, e := range in.Evidence {
				loc := e.Artifact
				if e.Line > 0 {
					loc = fmt.Sprintf("%s:%d", e.Artifact, e.Line)
				}
				if loc != "" {
					fmt.Fprintf(&b, "- `%s` — `%s`\n", loc, oneLine(e.Text))
				} else {
					fmt.Fprintf(&b, "- %s\n", oneLine(e.Text))
				}
			}
			b.WriteString("\n")
		}
	}
	if len(res.Gaps) > 0 {
		b.WriteString("## What this bundle cannot answer\n\n")
		for _, g := range res.Gaps {
			fmt.Fprintf(&b, "- **%s** %s", g.Question, g.Reason)
			if g.Finding != "" {
				fmt.Fprintf(&b, " (`hostveil explain %s`)", g.Finding)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("## Chain of custody\n\n")
	fmt.Fprintf(&b, "Every file in this bundle is listed in `manifest.json` with its SHA-256, the command or path it came from, and when it was collected. "+
		"Re-check it with `hostveil triage verify <this directory>`, and compare the manifest's own SHA-256 with the one recorded when it was collected.\n")
	var failed []string
	for _, a := range m.Artifacts {
		if a.Error != "" && a.Kind != "command" {
			failed = append(failed, a.Path+": "+a.Error)
		}
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		b.WriteString("\nCould not collect:\n\n")
		for _, f := range failed {
			fmt.Fprintf(&b, "- %s\n", f)
		}
	}
	return b.String()
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	if len(s) > 220 {
		s = s[:220] + "…"
	}
	return s
}

// VerifyResult is what Verify found.
type VerifyResult struct {
	Checked  int
	Mismatch []string
	Missing  []string
	Extra    []string
	Seal     string
}

// OK reports whether the bundle is exactly what its manifest says.
func (v VerifyResult) OK() bool {
	return len(v.Mismatch) == 0 && len(v.Missing) == 0 && len(v.Extra) == 0
}

// Verify re-hashes every file the manifest lists and looks for files it
// does not list.
func Verify(dir string) (VerifyResult, error) {
	var v VerifyResult
	b, err := openBundle(dir)
	if err != nil {
		return v, err
	}
	v.Seal, _ = hashFile(filepath.Join(dir, "manifest.json"))
	listed := map[string]bool{"manifest.json": true}
	for _, a := range b.m.Artifacts {
		listed[a.Path] = true
		sum, err := hashFile(filepath.Join(dir, a.Path))
		if err != nil {
			if a.Size == 0 && a.Error != "" {
				continue // never written: recorded as a collection failure
			}
			v.Missing = append(v.Missing, a.Path)
			continue
		}
		v.Checked++
		if sum != a.SHA256 {
			v.Mismatch = append(v.Mismatch, a.Path)
		}
	}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if !listed[filepath.ToSlash(rel)] {
			v.Extra = append(v.Extra, rel)
		}
		return nil
	})
	return v, nil
}
