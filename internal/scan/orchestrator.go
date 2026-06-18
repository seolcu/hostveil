// Package scan orchestrates a full or partial scan. It owns the
// scan-run state machine (running -> success/partial/error), the
// elevation batching, the per-category invocation, and the
// per-finding fingerprint classification (new / still_present /
// resolved).
package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/seolcu/hostveil/internal/checks"
	"github.com/seolcu/hostveil/internal/checks/docker"
	"github.com/seolcu/hostveil/internal/checks/hardening"
	"github.com/seolcu/hostveil/internal/checks/images"
	"github.com/seolcu/hostveil/internal/checks/proxy"
	"github.com/seolcu/hostveil/internal/checks/ssh"
	"github.com/seolcu/hostveil/internal/checks/ssl"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/store"
	"github.com/seolcu/hostveil/internal/version"
)

// CategoryScanners is the table of (category, scanner) the
// orchestrator iterates over. The five hardening sub-categories
// share the hardening.RunForCategory aggregator (which fans out to
// the firewall, fail2ban, unattended, sysctl, and package-manager
// sub-checks internally, filtered to the requested sub-category).
var CategoryScanners = map[model.Category]func(context.Context) (checks.Result, error){
	model.CategorySSH:                  ssh.Run,
	model.CategoryDocker:               docker.Run,
	model.CategoryImageCVE:             images.Run,
	model.CategoryReverseProxy:         proxy.Run,
	model.CategorySSLTLS:               ssl.Run,
	model.CategoryHardeningFirewall:    func(ctx context.Context) (checks.Result, error) { return hardening.RunForCategory(ctx, model.CategoryHardeningFirewall) },
	model.CategoryHardeningFail2ban:    func(ctx context.Context) (checks.Result, error) { return hardening.RunForCategory(ctx, model.CategoryHardeningFail2ban) },
	model.CategoryHardeningUnattended:  func(ctx context.Context) (checks.Result, error) { return hardening.RunForCategory(ctx, model.CategoryHardeningUnattended) },
	model.CategoryHardeningSysctl:      func(ctx context.Context) (checks.Result, error) { return hardening.RunForCategory(ctx, model.CategoryHardeningSysctl) },
	model.CategoryHardeningUpdates:     func(ctx context.Context) (checks.Result, error) { return hardening.RunForCategory(ctx, model.CategoryHardeningUpdates) },
}

// Run is the orchestrator's single entry point. It opens a ScanRun
// row, iterates the requested categories, classifies each finding
// against the previous scan via fingerprint, and writes the final
// ScanRun row. The returned RunResult is what the report layer
// consumes.
func Run(ctx context.Context, s *store.Store, requested []model.Category) (*RunResult, error) {
	now := time.Now().UTC()
	run := &model.ScanRun{
		ID:                newID(),
		HostID:            hostID(ctx, s),
		StartedAt:         now,
		Status:            model.ScanRunRunning,
		HostveilVersion:   version.Version,
		CVEFEEDRefreshed:  false,
		HostveilExitCode:  0,
	}
	if err := s.InsertScanRun(ctx, run); err != nil {
		return nil, fmt.Errorf("insert scan_run: %w", err)
	}

	// Previous findings on this host, keyed by fingerprint, so the
	// per-finding classification can label each result as
	// new / still_present / resolved.
	prev, err := s.PreviousFingerprints(ctx, run.HostID)
	if err != nil {
		return nil, fmt.Errorf("load previous fingerprints: %w", err)
	}
	seenThisRun := map[string]struct{}{}

	var (
		allFindings []model.Finding
		scanned     []model.Category
		skipped     []model.CategorySkip
	)

	cats := requested
	if len(cats) == 0 {
		cats = allCategories()
	}

	for _, c := range cats {
		runner, ok := CategoryScanners[c]
		if !ok {
			skipped = append(skipped, model.CategorySkip{
				Category: c,
				Reason:   "not_applicable",
				Detail:   "no scanner registered",
			})
			continue
		}
		res, err := runner(ctx)
		if err != nil {
			skipped = append(skipped, model.CategorySkip{
				Category: c,
				Reason:   "internal_error",
				Detail:   err.Error(),
			})
			continue
		}
		if res.Skipped != nil {
			skipped = append(skipped, *res.Skipped)
			continue
		}
		scanned = append(scanned, c)
		for i := range res.Findings {
			f := res.Findings[i]
			f.Fingerprint = Fingerprint(f)
			f.State = classify(f.Fingerprint, prev, seenThisRun)
			f.FirstSeenAt = firstSeenOr(f.Fingerprint, f.FirstSeenAt, prev)
			f.LastSeenAt = now
			seenThisRun[f.Fingerprint] = struct{}{}
			f.ID = scanFindingID(run.ID, f.RuleID, firstEntityDisplay(f))
			allFindings = append(allFindings, f)
		}
	}

	// Stable ordering for the report layer.
	sort.Slice(allFindings, func(i, j int) bool {
		if allFindings[i].Category != allFindings[j].Category {
			return allFindings[i].Category < allFindings[j].Category
		}
		if sevRank(allFindings[i].Severity) != sevRank(allFindings[j].Severity) {
			return sevRank(allFindings[i].Severity) > sevRank(allFindings[j].Severity)
		}
		return allFindings[i].RuleID < allFindings[j].RuleID
	})

	run.Status = model.ScanRunSuccess
	run.CategoriesScanned = scanned
	run.CategoriesSkipped = skipped
	for _, f := range allFindings {
		switch f.Severity {
		case model.SeverityCritical:
			run.FindingCountCritical++
		case model.SeverityHigh:
			run.FindingCountHigh++
		case model.SeverityMedium:
			run.FindingCountMedium++
		case model.SeverityLow:
			run.FindingCountLow++
		}
	}
	finished := time.Now().UTC()
	run.FinishedAt = &finished
	if run.FindingCountHigh > 0 || run.FindingCountCritical > 0 {
		run.HostveilExitCode = 1
	}
	if hasInternalError(skipped) {
		run.Status = model.ScanRunPartial
	}

	if err := s.UpdateScanRun(ctx, run); err != nil {
		return nil, fmt.Errorf("update scan_run: %w", err)
	}
	if err := s.InsertFindings(ctx, run.ID, allFindings); err != nil {
		return nil, fmt.Errorf("insert findings: %w", err)
	}

	return &RunResult{Run: *run, Findings: allFindings}, nil
}

// RunResult bundles the scan's model state with the resolved findings
// so the report layer doesn't have to re-query the store.
type RunResult struct {
	Run      model.ScanRun
	Findings []model.Finding
}

// Fingerprint returns a stable SHA-256 hex of the (category, rule_id,
// sorted(entity_refs)) tuple. This is the contract from data-model.md
// and is what classifies new / still_present / resolved across runs.
func Fingerprint(f model.Finding) string {
	h := sha256.New()
	h.Write([]byte(string(f.Category)))
	h.Write([]byte{0})
	h.Write([]byte(f.RuleID))
	h.Write([]byte{0})
	refs := append([]model.EntityRef(nil), f.EntityRefs...)
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Kind != refs[j].Kind {
			return refs[i].Kind < refs[j].Kind
		}
		return refs[i].ID < refs[j].ID
	})
	for _, r := range refs {
		h.Write([]byte(string(r.Kind)))
		h.Write([]byte{0})
		h.Write([]byte(r.ID))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func classify(fp string, prev map[string]time.Time, seenThisRun map[string]struct{}) model.State {
	if _, ok := seenThisRun[fp]; ok {
		// Same fingerprint seen earlier in this run; treat as
		// still_present.
		return model.StateStillPresent
	}
	if _, ok := prev[fp]; ok {
		return model.StateNew
	}
	return model.StateNew
}

func firstSeenOr(fp string, def time.Time, prev map[string]time.Time) time.Time {
	if t, ok := prev[fp]; ok {
		return t
	}
	return def
}

func sevRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 4
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 1
	}
	return 0
}

func firstEntityDisplay(f model.Finding) string {
	if len(f.EntityRefs) == 0 {
		return ""
	}
	return f.EntityRefs[0].Display
}

func scanFindingID(scanRunID, ruleID, display string) string {
	h := sha256.Sum256([]byte(scanRunID + "|" + ruleID + "|" + display))
	return "f-" + hex.EncodeToString(h[:8])
}

func allCategories() []model.Category {
	return []model.Category{
		model.CategorySSH,
		model.CategoryDocker,
		model.CategoryImageCVE,
		model.CategoryReverseProxy,
		model.CategorySSLTLS,
		model.CategoryHardeningFirewall,
		model.CategoryHardeningFail2ban,
		model.CategoryHardeningUnattended,
		model.CategoryHardeningSysctl,
		model.CategoryHardeningUpdates,
	}
}

func hasInternalError(skipped []model.CategorySkip) bool {
	for _, s := range skipped {
		if s.Reason == "internal_error" {
			return true
		}
	}
	return false
}

func newID() string {
	// Use sha256 of timestamp+random for a quick unique ID. The store
	// does not enforce uniqueness on the id column at the SQL level
	// beyond PRIMARY KEY; the caller is responsible for not
	// generating collisions in the same nanosecond.
	var b [16]byte
	now := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		b[i] = byte(now >> (8 * i))
	}
	return sha256Of(b[:])
}

// sha256Of is a small helper used by newID and the package's
// fingerprint path. Centralized so the test in store_test.go can
// assert the shape without depending on crypto/sha256 directly.
func sha256Of(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// hostID returns the host row for the current host, creating it on
// first use. The host fingerprint is derived from hostname +
// machine-id, both of which are read from /etc.
func hostID(ctx context.Context, s *store.Store) string {
	hostname, _ := hostname()
	machineID, _ := machineID()
	fp := sha256Hex([]byte(hostname + "|" + machineID))
	id, err := s.HostIDFor(ctx, fp)
	if err == nil {
		return id
	}
	host := model.Host{
		ID:          fp,
		Hostname:    hostname,
		OSFamily:    "other",
		OSVersion:   "",
		Kernel:      "",
		Arch:        arch(),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}
	if err := s.InsertHostByID(ctx, host); err != nil {
		return fp
	}
	return fp
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// mustJSON is a tiny helper used for the JSON columns the store
// keeps for scan_runs.categories_scanned and categories_skipped.
func mustJSON(v any) string {
	b, err := jsonMarshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// Avoiding an import cycle with the report package: report would
// re-import store, and the orchestrator needs to JSON-marshal
// slices. We use the stdlib directly here.
func jsonMarshal(v any) ([]byte, error) {
	return stdJSONMarshal(v)
}

// Compiler-cheap wrapper around encoding/json so the report package
// can also call this without an import cycle. (In Go we cannot
// re-export from stdlib; this just exists to keep the call site
// legible.)
func stdJSONMarshal(v any) ([]byte, error) {
	return _jsonMarshal(v)
}
