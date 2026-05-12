# ADR 0009: Adapter Fix Engine Architecture

**Date:** 2026-05-12
**Status:** Accepted

## Context

The initial fix engine (ADR 0007) operated solely on findings produced by native Compose rules via `RuleEngine::scan()`. External scanner findings (Dockle, Lynis, Trivy, Gitleaks) existed in the `ScanResult` for display and scoring but were invisible to the fix pipeline.

When a user pressed `f` on a Dockle finding, the `TuiAction::TriggerFix` carried only a `finding_id` filter. Inside `build_fix_plan`, `RuleEngine::scan()` was called again — producing only `Source::NativeCompose` findings — and `classify_adapter_findings` received only native findings. Since `classify_adapter_findings` only matches `Source::Dockle` and `Source::Lynis`, the adapter classification was always a no-op.

This meant the entire adapter classification layer in `src/src/fix/adapter.rs` was dead code in production, reachable only through unit tests.

## Decision

### Data Flow

Add an `adapter_findings: Vec<Finding>` field to `TuiAction::TriggerFix` and pipe it through the fix engine as `external_findings: &[Finding]`:

```
ScanResult.findings (all sources)
  └─> TUI extracts Source::Dockle | Source::Lynis findings
       └─> TuiAction::TriggerFix { adapter_findings }
            └─> run_interactive_fix_flow(&adapter_findings)
                 └─> preview_with_external(external_findings)
                      └─> build_fix_plan(external_findings)
                           └─> adapter::classify_adapter_findings(external_findings)  (now receives real adapter data)
                                └─> FixAction::ComposeEdit / HostEdit / ShellCommand
```

### API Surface

- `preview(path, mode, filter)` — unchanged, passes `&[]` for external findings.
- `apply(path, mode, filter)` — unchanged, passes `&[]` for external findings.
- `preview_with_resolutions(path, mode, filter, resolutions)` — unchanged, delegates to `preview_with_external` with `&[]`.
- `apply_with_resolutions(path, mode, filter, resolutions)` — unchanged, delegates to `apply_with_external` with `&[]`.
- `preview_with_external(path, mode, filter, external_findings, resolutions)` — new, accepts adapter findings.
- `apply_with_external(path, mode, filter, external_findings, resolutions)` — new, accepts adapter findings.

The old entry points remain for backward compatibility. The non-TUI `--fix` path passes `&[]` since it lacks access to the `ScanResult`.

### FixPlan Struct

```
FixPlan {
    compose_file, diff_preview, updated_text, backup_path,
    auto_applied, review_applied,       // FixProposal lists (native + adapter)
    host_actions: Vec<FixAction>,       // HostEdit actions
    system_actions: Vec<FixAction>,     // ShellCommand actions only
    compose_actions: Vec<FixAction>,    // ComposeEdit actions only
}
```

The partition logic in `build_fix_plan`:

1. `classify_adapter_findings(external_findings)` returns `(Vec<FixAction>, Vec<FixProposal>, Vec<FixProposal>)`.
2. `adapter_actions` are partitioned by variant:
   - `ComposeEdit` → `compose_actions` (applied to compose document text)
   - `HostEdit` → `host_actions` (file writes with backup)
   - `ShellCommand` → `system_actions` (shell execution)
3. `adapter_auto` / `adapter_review` proposals are merged with native proposals for display.

### Action Execution

- `apply_with_external` applies compose edits first (backup + atomic write), then calls `execute_host_and_system_actions` which iterates `host_actions` and `system_actions`.
- `HostEdit` actions create parent directories, write files atomically, and set permissions.
- `ShellCommand` actions run via `sh -c` and report non-zero exit as errors.

## Consequences

- `FixPlan.compose_actions` was added to carry ComposeEdit actions separately from host/system actions.
- Dockle adapter findings now actually reach the fix pipeline and produce real ComposeEdit changes.
- Lynis adapter findings produce HostEdit or ShellCommand depending on evidence test IDs.
- The fix review TUI shows `[COMPOSE]`, `[HOST EDIT]`, and `[SHELL]` sections with color-coded labels.
- The `TuiAction::TriggerFix` struct now requires `adapter_findings: Vec<Finding>` — breaking matches must be updated.
- `run_interactive_fix_flow` now requires `external_findings: &[Finding]` — all callers must pass findings or `&[]`.
