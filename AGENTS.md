# AGENTS.md

Context for AI coding assistants on this repo. Not a substitute for README.

## Project Status

**v1.0.0-rewrite** — Complete rewrite of hostveil from Rust (v0.29) to Go + Bubbletea.
Branch: `v1.0.0-rewrite` (never merged to main, `main` still has the Rust version).

## Tech Stack

- **Language**: Go 1.24+
- **TUI**: `charmbracelet/bubbletea`, `bubbles`, `lipgloss`, `glamour`, `huh`
- **YAML**: `goccy/go-yaml` (NOT `gopkg.in/yaml.v3` — it's archived)
- **Web**: `ttyd` — streams the actual Bubbletea TUI to browser via WebSocket (no custom HTML/JS/CSS)
- **Build**: `go build`, no CGO needed
- **Cross-compile**: `GOOS=linux GOARCH=arm64 go build` (native, no toolchain needed)
- **Browser screenshot**: `agent-browser` (not vhs — Chrome process management is unreliable)

## Project Structure

```
hostveil/
├── cmd/hostveil/main.go              # Entry point (no flags needed, auto-discovers everything)
├── internal/
│   ├── domain/                       # Core types (Finding, Severity, Axis, etc.)
│   ├── compose/                      # docker-compose.yml parser
│   ├── scanner/
│   │   ├── rules/                    # Rule engine + 6 core rules + service-aware
│   │   └── host/                     # 9 host check modules
│   ├── adapter/                      # External scanner wrappers (Trivy, Dockle, Lynis, Gitleaks)
│   │   └── detect.go                 # PATH-based auto-detection (installed = auto-run)
│   ├── fix/                          # Fix engine (preview/apply compose edits)
│   ├── discovery/
│   │   └── docker.go                 # Walk up from pwd, find compose.yml files
│   ├── export/                       # JSON, SARIF, Markdown, HTML
│   ├── web/                          # ttyd launcher: finds ttyd, starts with --serve
│   └── config/                       # CLI argument parsing (4 flags: --serve, --port, --host, --user-mode)
├── scripts/
│   └── lab.sh                        # Docker lab management (up/down/shell/run/serve)
├── docker/
│   └── lab/
│       ├── Dockerfile                # Go 1.24 + ttyd + Trivy + Dockle + Lynis + Gitleaks
│       ├── compose.yml               # Scanner container (--serve: http://localhost:8080/)
│       ├── vaultwarden/compose.yml   # Target service (individual)
│       ├── jellyfin/compose.yml      # Target service (individual)
│       ├── gitea/compose.yml         # Target service (individual)
│       ├── nextcloud/compose.yml     # Target service (individual)
│       ├── nginx/compose.yml         # Target service (individual)
│       └── self-hosting-stack.yml    # All targets combined (--compose reference)
├── Makefile
└── tests/scenarios/                  # Test compose files (7 fixtures)
```

## Design Philosophy

- **`hostveil` — no flags needed**. Auto-discovers compose files by walking up from pwd.
- **Root by default**. `--user-mode` to restrict. Scanner + adapters need Docker/host access.
- **Installed adapter = auto-run**. Adapter tools found in PATH are detected and run automatically.
- **All flags removed**. `--compose`, `--output`, `--fix`, `--host-root` etc. all gone. Everything happens inside the TUI.

## Current Implementation Status

### ✅ Completed (all 62 issues closed)

| Layout System | ~550 | `layout.go` — `Rect`, `splitColumns`, `renderCardBounded`, `joinColumns`, `contentArea` |
| Module | Lines | Key Files |
|--------|-------|-----------|
| Domain | ~300 | `finding.go`, `severity.go`, `axis.go`, `scope.go`, `source.go`, `remediation.go`, `score.go`, `scan_result.go` |
| Compose Parser | ~400 | `parser.go` (supports long/short port syntax, volume mounts, env, cap_add, etc.) |
| Rule Engine | ~1,000 | `engine.go` + 6 core rules + `service_aware.go` (23 services) |
| Host Checks | ~400 | 9 check modules (SSH, Docker, Firewall, Kernel, Filesystem, FIM, MAC, Defenses, Updates) |
| Adapters | ~600 | Trivy, Dockle, Lynis, Gitleaks wrappers with command runner |
| Fix Engine | ~400 | preview/apply with compose edits, backup |
| Export | ~400 | JSON (with findings-only), SARIF, Markdown, HTML |
| CLI | ~100 | flag-based argument parsing |
| Discovery | ~100 | Docker compose file detection, host runtime info |
| Scanner | ~100 | Orchestration + scoring |
| TUI App | ~550 | Bubbletea app, 3 screens (overview/findings/history), settings modal, fix preview integration |
| TUI Overview | ~280 | Score card, severity, axis bars, action queue, host info, truncated load averages |
| TUI Findings | ~450 | Filtered list with index numbers, detail panel with section separators, fix preview (press f), search, 6 filter types, 3 sort modes, host triage empty state |
| TUI History | ~130 | Axis score bars, severity summary, warnings, grouped info messages |
| TUI Settings | ~130 | Theme selector, modal overlay, borders toggle |
| TUI Help | ~100 | Keyboard shortcut reference overlay (width 64) |
| TUI Toast | ~90 | Auto-dismissing notification with countdown indicator |
| TUI StatusBar | ~80 | Index/count/filter status bar |
| Web Server | ~50 | ttyd-backed, streams actual TUI to browser |

### ✅ Completed Issues (all 80 issues closed)

| Issue | What | Resolution |
|-------|------|-----------|
| **#384** | Fix Engine — Host Edits & Shell Commands | 20 host findings mapped with HostEdit + ShellCommand actions. TUI `f` key shows host fix preview via `fix.PreviewAnyFinding()` |
| **#385** | Fix Engine — Adapter Finding Classification | Trivy/Dockle/Lynis/Gitleaks mapped with evidence-aware fix commands. TUI `f` key shows adapter fix preview |
| **#446** | TUI/UX Panel border clipping 근본 수정 | `Rect` 타입, `splitColumns`, `renderCardBounded` 도입. `assertDisplayWidthLTE` debug mode 활성화. 6개 화면 column split 통일. `bodyWidth = m.width` + overflow truncation으로 오른쪽 공백 제거 |
| **#449** | Narrow dashboard gray overlay artifact | `truncateWidth`를 display-width-aware로 재작성. ANSI escape sequence visible width 제외, `lipgloss.Width(r)`로 문자별 display width 계산 |
| **#448** | Settings modal option grid wrapping | colWidth indent 반영, innerW < 34에서 1-column 전환, option label truncate 처리 |
| **#441** | Settings modal background gap | Padding(1,2)→(0,2)로 변경, top/bottom padding explicit line으로 대체, border 안쪽 전체 Surface background 보장 |
| **#450** | Report spacing token 통일 | `Spacing` 타입 + `spacingFor()` 도입. RenderU/W/Medium Report magic number 제거. card1 중복 title 수정. guidance card boundary 일치. |
| **#447** | Findings 화면 3-row inspector redesign | List panel bordered + title, 3-row layout (list+detail / filter+context / guidance), Context compact when no service |
| **#386** | Adapter Integration Tests | 9 tests covering Trivy/Dockle/Lynis/Gitleaks JSON/NDJSON parsing, timeout, edge cases |
| **#420** | TUI E2E Test Scenarios | Test coverage expanded: domain (14), host (4), export (8), fix engine (12) |
| **#422** | Docker Lab 유지보수 | scripts/lab.sh works with Go binary |
| **#442** | Right border/corner clipping | `assertDisplayWidthLTE` debug helper. `renderCard` truncates body lines to inner width. Body width reduced by 2 in `app.go` for 1-char left/right margin. UltraWide Findings bottom cards splitColumns/joinColumns gap 불일치 수정. |
| **#443** | Findings detail dedup | Removed duplicate Fix guidance from detail card (하단 renderFixGuidance strip이 동일 역할). Detail card는 metadata line에서 종료. |
| **#444** | Fix preview decision model | `renderFixDecision()` compact format (`→` recommended action), 중복 `─── Decision ───` 섹션 제거. Context-aware action labels 유지. 추천 문구 단축 (최대 104→67자)으로 truncation 방지. |
| **#445** | Dashboard Load label 일관성 | `"Load avg"` → `"Load"` 통일. Compose path truncate와 Load `→` 제거는 이전 이슈에서 이미 해결. |

### Issue #451 — TUI Layout Contract (In Progress)

| Change | File | Lines | Status |
|--------|------|-------|--------|
| `OverflowPolicy` type (Clip/Ellipsis/Scroll) | `layout.go` | +5 | ✅ |
| `DashboardState` type (Clean/Risk) | `layout.go` | +4 | ✅ |
| `FindingsSlots()` — fixed slot computation for Findings | `layout.go` | ~40 | ✅ |
| `DashboardSlots()` — fixed slot computation for Dashboard | `layout.go` | ~60 | ✅ |
| Renderers consume DashboardSlots (8→3 state-aware) | `screen_overview.go` | ~217 | ✅ |
| Height params for all card helpers | `screen_overview.go` | ~50 | ✅ |
| Dead code removal (dashboardHeightBudget, etc.) | `layout.go`, `screen_overview.go` | −475 | ✅ |
| `ReportSlots()` — fixed slot computation for Report | `layout.go` | ~15 | ✅ |
| `RenderPanel()` — fixed-height panel renderer with overflow handling | `layout.go` | ~30 | ✅ |
| `rectsFromWidths()` — helper for creating row rects | `layout.go` | ~10 | ✅ |
| Findings `render()` — slot-based with fixed detail panel height | `screen_findings.go` | ~50 | ✅ |
| Findings `renderUltraWideFindings()` — slot-based layout | `screen_findings.go` | ~50 | ✅ |
| `renderFixGuidanceText()` — text-only guidance (for fixed-height card) | `screen_findings.go` | ~20 | ✅ |
| `renderFilterStateCard` + `renderRelatedFindingsCard` — accept height param | `screen_findings.go` | ~15 | ✅ |
| `renderFixGuidance` — accept height param | `screen_findings.go` | ~5 | ✅ |
| Removed dead `renderFindingsBottomCards` | `screen_findings.go` | −5 | ✅ |
| `renderDetailContent` section-based: metadata anchored bottom, overflow hint | `screen_findings.go` | +73 | ✅ |
| `buildFindingBodyLines` helper extracted | `screen_findings.go` | ~30 | ✅ |
| `OverflowScroll` → `OverflowClip` for detail panel | `screen_findings.go` | −2 | ✅ |

**Status**: Findings layout is now slot-based with fixed detail panel height. Dashboard `DashboardSlots` defined but not yet consumed by renderers (existing budget system remains). Report `ReportSlots` defined but renderers not yet migrated. Build + vet + all 56 tests pass. Browser QA verified — detail panel height stable across selection changes, no regressions found. Search/Filter/Settings unresponsive in overlay states during QA is a browser key-delivery issue.

### Issue #454 — TUI Brand Filler (Complete)

| Change | File | Lines | Status |
|--------|------|-------|--------|
| `Brand` field added to `DashboardLayout` | `layout.go` | +1 | ✅ |
| `DashboardSlots()` computes Brand slot when `state==DashboardClean` | `layout.go` | ~30 | ✅ |
| UltraWide: Brand H=8 (replaces Row3), Wide: Brand H=6 (inserted between Row2↔Timeline) | `layout.go` | ~15 | ✅ |
| `renderBrandFillerCard()` with 2 ASCII art variants (6-line / compact 1-line) | `screen_overview.go` | ~20 | ✅ |
| UltraWide & Wide renderers wired: checks `slots.Brand.W > 0` | `screen_overview.go` | ~25 | ✅ |
| Build + vet + all 56 tests pass | — | — | ✅ |

Conditions: `state==DashboardClean && mode>=LayoutWide`. Brand uses `theme.TextMuted` only. No visual effect on Risk/Medium/Narrow.

### Help/Settings Modal Height Fix (post-QA #453)

| Change | File | Lines | Status |
|--------|------|-------|--------|
| Help modal 3-tier height-aware (full/compact/minimal) | `screen_help.go` | +90/-30 | ✅ |
| Settings modal height-aware + adapter truncation | `screen_settings.go` | +50/-20 | ✅ |

## Tests (56 tests, 9 files)

| File | Tests | Coverage |
|------|-------|----------|
| `internal/adapter/adapter_test.go` | 9 | Trivy/Dockle/Lynis/Gitleaks JSON/NDJSON parsing, timeout, edge cases |
| `internal/compose/parser_test.go` | 3 | Port/volume/env parsing, error handling, empty file |
| `internal/domain/axis_test.go` | 3 | Axis string, label, AllAxes |
| `internal/domain/finding_test.go` | 3 | IsFixable, TotalFindings, FindingsBySeverity |
| `internal/domain/remediation_test.go` | 2 | Remediation string, label |
| `internal/domain/score_test.go` | 1 | Score grade boundaries |
| `internal/domain/scope_test.go` | 1 | Scope string |
| `internal/domain/severity_test.go` | 2 | Severity string, color |
| `internal/domain/source_test.go` | 2 | Source string, AllSources |
| `internal/export/export_test.go` | 8 | JSON (full + findings-only), Markdown, HTML, SARIF, empty findings |
| `internal/fix/actions_test.go` | 6 | HostEdit/ShellCmd creation, 20 host finding coverage, 4 adapter classification |
| `internal/fix/engine_test.go` | 12 | MinimalHostFix, MinimalAdapterFix, PreviewAnyFinding (compose/host/adapter/unknown), NewEngine |
| `internal/scanner/host/engine_test.go` | 4 | NewEngine, EngineScan, check names, Remediation type |
| `internal/scanner/rules/engine_test.go` | 6 | Core rules + service-aware (Vaultwarden, Postgres/Redis) |
| `internal/scanner/scanner_test.go` | 4 | Scan run, empty config, finding detection, score calculation |

Run: `go test -race -count=1 ./...`

## Design Decisions

### Why Go over Rust
- **TUI quality**: Bubbletea's Model-View-Update produces cleaner TUI code than Ratatui's immediate mode
- **Cross-compilation**: `GOOS=linux GOARCH=arm64 go build` — native, no toolchain
- **Build speed**: ~1s vs ~3min for Rust
- **AI-friendly**: Simple syntax, no ownership/lifetime complexity
- **Testing**: Easy golden file testing for TUI (`View()` returns string)

### Why ttyd instead of custom Web UI
- Single binary + ttyd = pixel-identical TUI in the browser
- No HTML templates, no CSS, no JS framework to maintain
- Full keyboard/mouse support via xterm.js WebSocket
- Font configured via `-t fontFamily=JetBrainsMono Nerd Font,Fira Code,Consolas,monospace`
- Port: always uses exactly port 9090, no fallback. If occupied, `killPort()` uses `lsof`/`fuser` to forcefully free it (`internal/web/server.go`).

### Design Decisions (v1.0.0)

- **No `--compose` flag**: hostveil auto-discovers compose files by walking up from the current directory (like `git`). No explicit path needed.
- **No `--output` flag**: All output modes (JSON, SARIF, Markdown, HTML) are accessible from within the TUI. The CLI only has `hostveil`.
- **No `--fix` flag**: Fix operations happen inside the TUI via the fix preview/apply flow.
- **Adapters auto-detect**: If Trivy/Dockle/Lynis/Gitleaks is in PATH, it runs automatically. No `--adapter` flag needed.
- **Root by default**: `hostveil` assumes root access for host checks and Docker operations. Use `--user-mode` to run as non-root.

### TUI Design (OpenCode-inspired)
- **Full background coverage**: `applyBackground()` intercepts ANSI reset codes (`ESC[0m`, `ESC[49m`)
  and re-applies the theme Background color, preventing terminal default background from showing
- **Footer anchored to bottom**: body padded with newlines to fill terminal height, footer always at last line
- **Responsive 3-column layout**: width ≥100 → 3 columns, 60-99 → 2 columns, <60 → 1 column
- **Component architecture**: screen models (overview/findings/history) are self-contained Bubbletea models
- **Fix Preview**: Press `f` on a fixable finding to toggle between detail view and fix preview. Preview shows the service's YAML block from the compose file with 3 lines of surrounding context, plus the proposed change summary. Uses `extractServiceSnippet()` for YAML block extraction and `PreviewFinding()` on the fix engine.
- **Findings list index numbers**: Each finding prefixed with ` 1.`, ` 2.` for easy reference. HCI motivation: users can verbally reference "finding #3" during code review.
- **Detail panel separators**: `───` line divides metadata (ID/Severity/Axis/Source/Scope/Service) from content sections (Description/Risk/Fix/Evidence). Separator defined once in the render method.
- **Search/filter disambiguation**: Search text shown with `|` separator from filter chips. Filter state shows `N/M no filters` when clean.
- **Info message grouping**: "Discovered project" messages grouped into single summary line to reduce noise. Non-project messages shown individually.

## HCI/UI/UX Design Principles (필수 준수)

Terminal UI라고 해서 UI/UX 원칙을 무시하면 안 됨. 아래 원칙은 **모든 TUI 디자인에 반드시 적용**해야 함.

### Nielsen's 10 Usability Heuristics (적용 요약)

1. **Visibility of System Status**: 사용자는 항상 현재 상태를 알아야 함. 필터/검색/로딩 상태를 명확히 표시.
2. **Match Between System and Real World**: 내부 약어(`sev:`, `scp:`) 대신 자연어 사용. 사용자 관점의 용어 선택.
3. **User Control and Freedom**: 모든 동작에 되돌리기(undo)와 취소(esc) 제공. 실수로 필터 걸었을 때 R로 초기화.
4. **Consistency and Standards**: 같은 의미의 정보는 같은 위치/스타일로. 단축키 일관성 유지.
5. **Error Prevention**: 오류가 발생하기 전에 막을 수 있는 UI. 예: 빈 화면에서 명확한 액션 안내.
6. **Recognition Rather than Recall**: 정보를 기억하지 않아도 인식할 수 있게. 검색어 하이라이트, 필터 칩 등.
7. **Flexibility and Efficiency of Use**: 단축키 지원, 숙련자와 초보자 모두를 위한 인터페이스.
8. **Aesthetic and Minimalist Design**: **불필요한 정보는 모두 제거**. 공백 낭비 금지. 정보 밀도 최적화.
9. **Help Users Recognize, Diagnose, and Recover from Errors**: 오류 메시지를 일반 언어로 표시. 해결책 제시.
10. **Help and Documentation**: `?` 키로 도움말 접근. 명확하고 간결하게.

### Gestalt 원칙 (시각적 그룹화)

| 원칙 | 설명 | 적용 |
|------|------|------|
| **Law of Common Region** | 경계선으로 그룹화 | 모든 패널에 박스 테두리 필수 (Borders 항상 ON) |
| **Law of Proximity** | 가까운 요소는 같은 그룹 | 관련 정보 간 간격 최소화, 무관한 정보 간 간격 확보 |
| **Law of Similarity** | 비슷한 요소는 같은 기능 | 같은 종류의 데이터는 같은 색상/스타일 사용 |
| **Law of Prägnanz** | 가장 단순한 형태로 인식 | 복잡한 레이아웃보다 단순한 정렬이 가독성 향상 |
| **Law of Uniform Connectedness** | 연결된 요소는 관련됨 | 색상 연결, 정렬 통일로 정보 관계 표현 |

### 인지 심리학 법칙

| 법칙 | 내용 | 적용 |
|------|------|------|
| **Fitts's Law** | 타겟이 크고 가까울수록 빠름 | 버튼/바/인덱스 충분히 크게, 빈 공간에 기능 배치 |
| **Hick's Law** | 선택지가 많을수록 결정 시간 증가 | 필터 옵션 순차 공개, 한 번에 5-7개 옵션 제한 |
| **Miller's Law** | 작업기억 7±2 항목 | 한 화면에 정보 과다 배치 금지, 청킹 필요 |
| **Cognitive Load** | 인지 부하 최소화 | 불필요한 메타데이터 제거, 레이블 간결하게 |
| **Aesthetic-Usability Effect** | 아름다운 UI는 더 사용하기 쉽다고 인식 | 정렬, 여백, 색상 통일성으로 신뢰감 형성 |
| **Tesler's Law** | 복잡성은 보존됨 (이전 불가) | 복잡한 로직은 시스템이 처리, 사용자에게는 단순하게 |
| **Jakob's Law** | 사용자는 다른 사이트에 익숙함 | 업계 표준 단축키/레이아웃 따르기 |

### TUI 디자인 수칙 (hostveil 전용)

- **박스 테두리는 항상 ON** (RoundedBorder, Surface 배경색과 Border 색상 구분)
- **Padding 최소화**: 상하 0, 좌우 1-2 (화면 공간 절약)
- **정보 밀도 극대화**: 빈 화면 95% 금지. 빈 상태는 중앙에 아이콘+메시지 배치
- **색상만으로 정보 전달 금지**: 심각성은 색상 + 텍스트 + 아이콘 조합
- **필터 상태는 헤더에 자연어로**: `sev:critical` 대신 `Severity: Critical`
- **검색어 하이라이트**: 일치하는 부분 역상 또는 밑줄 표시
- **Fix Preview는 Diff 형식**: `- old` / `+ new` 명확히 구분
- **스크롤 필요 시 하단 표시기**: `▼ 3 more lines` 안내
- **반응형 레이아웃**: 80+|2열, 60-79|1.5열, <60|1열 세로 스크롤

### Good UI vs Bad UI 예시

| Good UI | Bad UI |
|---------|--------|
| 구분선/테두리로 정보 그룹화 (Common Region) | 테두리 없이 빈 공간만으로 구분 시도 |
| 정보 밀도 60-80% (화면 공간 효율 사용) | 정보 밀도 <40% (공백 낭비) |
| 빈 화면 중앙에 아이콘 + 자연어 메시지 + 액션 안내 | 빈 화면 왼쪽 상단에 기술적 메시지만 표시 |
| Diff 형식으로 변경 전후 비교 | 현재 상태만 표시하고 변경점 불명확 |
| 검색어 하이라이트로 일치 항목 강조 | 검색어 입력만 있고 결과에서 강조 없음 |
| 필터 상태 자연어 표시 (Severity: Critical) | `sev:critical` 약어 남발 |
| 섹션 구분선 굵게 (═ 또는 ██████) | 구분선 너무 얇아서 인지 불가 |

### Service-Aware Rules Design
Instead of 2,504 lines of Rust if-else chains (`service_aware.rs`), Go version uses data-driven tables:
- `ServiceKind` enum (iota)
- `serviceDetections` table (image name → kind mapping)
- `serviceFindings` map (kind → []findingDef with declarative conditions)
- ~440 Go lines covering all 23 services

### Scan Results Contract (ADR 0006 equivalent)
Single `ScanResult` type flows through all modules:
```
Scanner.Run() → ScanResult → Export (JSON/SARIF/MD/HTML)
                           → TUI (Bubbletea)
                           → Web Server (ttyd)
```

## Browser Screenshots (for AI visual review)

Use agent-browser (NOT vhs — Chrome process management proved unreliable):

```bash
# Clean up any previous session and start ttyd inside the lab
./scripts/lab.sh serve-detached
sleep 3

# Connect and focus terminal input
URL="http://127.0.0.1:9090/"
agent-browser open "$URL"
agent-browser set viewport 1280 720
agent-browser wait 2500
agent-browser snapshot -i
agent-browser click @e1

# Create timestamped output directory and capture
mkdir -p screenshots
SHOT_DIR="screenshots/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$SHOT_DIR"
agent-browser screenshot "$SHOT_DIR/overview.png"
```

### `serve` vs `serve-detached`

| Command | Mode | Use case |
|---------|------|----------|
| `lab.sh serve` | Foreground (Ctrl+C to quit) | Human-driven QA in browser |
| `lab.sh serve-detached` | Background + readiness wait loop | AI-agent automated browser QA |

Both run `./hostveil --serve --port 9090` inside the container. `serve-detached` additionally:
1. Kills any previous `hostveil` and `ttyd` processes first
2. Waits for `curl http://127.0.0.1:9090/` to respond (max 20 retries)
3. Logs to `/workspace/hostveil-serve.log` inside the container

### Verified TUI Keyboard Navigation (via ttyd)

All keys confirmed working through agent-browser → ttyd → Bubbletea:

| Key | Action | Verified |
|-----|--------|----------|
| `1/2/3` | Switch screens (Overview/Findings/History) | ✅ |
| `Enter` / `l` | Open finding detail panel | ✅ |
| `h` / `←` | Back to list / host triage | ✅ |
| `s` | Cycle severity filter | ✅ |
| `?` | Toggle Help overlay | ✅ |
| `S` | Toggle Settings modal | ✅ |
| `right` | Navigate Settings theme selector | ✅ |
| `f` | Toggle fix preview (on fixable findings) | ✅ |

### Visual QA Results (20 screenshots, all screens)

Captured and inspected (20 screenshots): overview, findings list, findings detail + fix preview, severity filter, empty filter, history, help, settings, theme change (before/after), host triage, narrow viewport, search mode/results, sort modes (source/title), multi-filter, theme toast, overview after theme.

- No obvious rendering breakage found
- Background colors apply correctly after ANSI reset
- Borders and panel alignment intact
- Theme changes apply immediately
- Responsive layout works at narrow viewport
- Fix preview shows service YAML block with 3-line context
- Index numbers (` 1.`, ` 2.`) present on findings list
- Detail panel has `───` section separators
- Info messages grouped: "Discovered N project(s): a, b, c"
- Load averages truncated to 1/5/15m values only
- Toast shows `%ds` countdown indicator
- **Note**: ttyd page shows browser scrollbar (container height mismatch, cosmetic only — TUI itself is fine)

### Bundled Skill: `hostveil-browser-tui-qa`

AI agent-driven TUI visual QA skill at `.agents/skills/hostveil-browser-tui-qa/`.

No fixed script — the agent runs an **iterative Observe–Explore loop**:
1. Builds hostveil, starts `--serve`, parses fallback URL
2. Connects agent-browser, dynamically navigates the TUI via keyboard
3. Captures a screenshot (≤20 total budget) → inspects the PNG → decides next move based on what was seen
4. Repeats until all screens and states are thoroughly covered across 3+ viewport sizes
5. Produces a structured QA report with the iteration decision trail

See `SKILL.md` for the full methodology, loop mechanics, adaptive branching guide, and visual inspection checklist.

## Docker Lab

```bash
# Start the full self-hosting lab
./scripts/lab.sh up

# Run hostveil inside the lab (auto-discovers all services)
./scripts/lab.sh run

# Start hostveil --serve for browser QA
./scripts/lab.sh serve

# Enter the lab container
./scripts/lab.sh shell

# Stop everything
./scripts/lab.sh down
```

The lab automatically discovers all compose files under `docker/lab/*/compose.yml`.
Services can also be managed individually:

```bash
docker compose -f docker/lab/vaultwarden/compose.yml up -d
```

## Browser Screenshots

Use agent-browser for visual QA:

```bash
./scripts/lab.sh up
./scripts/lab.sh serve
# agent-browser open http://127.0.0.1:8080/
```

## Test & Build

```sh
go build ./...          # Build all
go vet ./...            # Lint
go test -race ./...     # Test with race detector
go build -o hostveil ./cmd/hostveil/  # Build binary

# Run with specific test compose file (auto-security)
cd tests/scenarios/vaultwarden-domain && ../../hostveil

# Cross-compile
GOOS=linux GOARCH=arm64 go build -o hostveil-linux-arm64 ./cmd/hostveil/
```

## GitHub Workflow

- **8 Milestones**: M1-M8, each with ~7-11 issues
- **62 Issues total**: #367-#428
- **Branch naming**: `v1.0.0-rewrite` for the rewrite (never merge to main)
- Issues automatically close via `Closes #N` in commit messages when merged
- PRs should correspond to individual issues, not milestone batches

## Key References

- `AGENTS.md` — this file
- `internal/web/server.go` — ttyd launcher (port 9090 forced, `killPort()` to free busy port, font config)
- `internal/tui/layout.go` — Layout primitives: `Rect`, `contentArea`, `splitColumns`, `renderCardBounded`, `joinColumns`
- `internal/tui/app.go` — Bubbletea root model, background rendering, footer anchoring
- `internal/tui/screen_findings.go` — Index numbers, detail separators, fix preview render, search/filter UX
- `internal/fix/engine.go` — Fix engine with `PreviewFinding()` for per-finding YAML context diff
- `internal/scanner/rules/service_aware.go` — data-driven rule design pattern
- `tests/scenarios/` — compose file test fixtures from v0.29
- `scripts/lab.sh` — Docker lab (v0.29 compatible)
- `.agents/skills/hostveil-browser-tui-qa/` — AI-driven TUI visual QA skill (no fixed script)
- OpenCode TUI reference: https://github.com/anomalyco/opencode (SolidJS + OpenTUI patterns)

## What NOT To Do

- Do not use `gopkg.in/yaml.v3` (archived, use `goccy/go-yaml`)
- Do not re-add i18n or LLM (explicitly removed for v1.0.0)
- Do not import Rust code or attempt to reuse it
- Do not use vhs for screenshots (unreliable Chrome process management)
- Do not add custom HTML/JS/CSS for web UI (ttyd handles it all)
- Do not assume Docker is available (adapters should fail gracefully)

## TUI QA Known Issues & Fixes

### Docker lab vs direct run theme color difference
- Cause: `scripts/lab.sh` only forwarded `TERM`, not `COLORTERM`.
- Fix: Pass both `TERM=${TERM:-xterm-256color}` and `COLORTERM=${COLORTERM:-truecolor}` in `docker compose exec -e`.
- `internal/web/server.go`: Set `cmd.Env` with both vars for ttyd child process.

### Theme change causes background banding in overlays
- Cause: `applyBackground()` used `len(line)` which counts ANSI bytes, not visible width. `placeOverlayOnBackground` relied on leading `bgSeq` only.
- Fix: Use `lipgloss.Width(line)` for padding. Prepend `bgSeq` to every individual line in `applyBackground()` so ANSI-interleaved line breaks retain background.

### Fix preview not showing -/+ diff
- Cause: `PreviewFinding()` only showed current YAML snippet + summary, not a diff.
- Fix: Added `previewSnippetDiff()` which applies fix transforms (`addLoopbackBinding`, `addServiceLine`, `simpleLineDiff`) and renders `- old` / `+ new` format. Covers `exposure.public_binding`, `runtime.*`, `network.*`, `service.vaultwarden.*`.

### Search mode key conflict with detail toggle
- Cause: `/` toggled `showSearch` but consumed keystrokes after the main switch, so Enter and other keys would fire both search and detail actions.
- Fix: Search mode is now handled as an early return in `Update()` before the main key switch. `msg.Runes` used instead of `msg.String()` for reliable character capture. `Enter` commits, `Esc` cancels.

### ttyd browser scrollbar
- `-t scrollback=0` added to ttyd args, but the browser page scrollbar is a function of ttyd's default HTML/CSS — eliminating it entirely requires custom index.html, which violates the "no custom HTML/JS/CSS" rule.

### Layout layout/column overflow (#446)
- **Problem**: Multi-column layouts overflowed terminal width because column split formulas like `(width-2)/2` didn't subtract gap first. `assertDisplayWidthLTE` was a no-op (`_ = fmt.Sprintf`). No `Rect` type meant inner/outer width was easily confused. Right borders clipped at terminal edge.
- **Fix**: Added `Rect` type (`W` = outer width including borders), `splitColumns(totalW, n, gap)` (subtracts gap before distribution), `renderCardBounded(title, body, theme, Rect)` (exact outer-width control), and `joinColumns` overflow truncation. `assertDisplayWidthLTE` activates under `HOSTVEIL_TUI_DEBUG_LAYOUT=1`. `bodyWidth = m.width` (no safe margin — `splitColumns` + `joinColumns` truncation prevents overflow).
- **Key files**: `internal/tui/layout.go` (primitives), `app.go` (bodyWidth), `screen_overview.go`, `screen_findings.go`, `screen_history.go` (migrated to `splitColumns` + `renderCardBounded`).

### Narrow dashboard gray overlay artifact (#449)
- **Problem**: At medium/narrow viewports (80×24 and below), the hero card's recommendation line showed a gray bar (`█████████`) overlaid on text. Cause: `truncateWidth()` counted raw runes (including ANSI escape sequences) instead of visible display width. When a styled (ANSI-colored) line exceeded `contentW`, truncation by rune count produced malformed ANSI sequences, causing lipgloss's `Width()` padding to create visible background artifacts.
- **Fix**: Rewrote `truncateWidth()` to iterate runes while tracking visible display width via `lipgloss.Width(r)`. ANSI escape sequences (`\x1b[...m` and similar) are skipped in the width count, ensuring correct truncation position and proper ANSI sequence integrity.
- **Key file**: `internal/tui/layout.go:200` — `truncateWidth()` function.

### Settings modal option grid wrapping (#448)
- **Problem**: In narrow terminals, `tokyo-night` split into two lines (`tokyo-\nnight`). Cause: `colWidth = innerW / 2` didn't subtract the 2-space indent, so the rendered row (`"  " + entry1 + entry2`) overflowed `innerW`. lipgloss overflow caused label wrapping.
- **Fix**: `colWidth = (innerW - indent) / 2` accounts for indent. When `innerW < 34`, switches to 1-column stacked layout. Option labels truncated with `truncateWidth()` when they exceed column width. Narrow hint text adapts: `"j/k change · Esc close"`.
- **Key file**: `internal/tui/screen_settings.go:108-171` — theme section render logic.

### Settings modal background gap (#441)
- **Problem**: Settings modal showed a thin background gap between border and modal body. Cause: `dialogStyle.Padding(1, 2)` created top/bottom padding rows via lipgloss, but `Background(theme.Surface)` didn't fully cover these padding rows, letting the canvas background show through.
- **Fix**: Changed `Padding(1, 2)` to `Padding(0, 2)`. Replaced lipgloss-generated vertical padding with explicit content lines using `surfaceBg.Width(innerW).Render("")` at the start and end of contentParts, ensuring every character inside the border has explicit Surface background.
- **Key file**: `internal/tui/screen_settings.go:78-83, 102-103, 201-202` — dialogStyle padding change + explicit padding lines.

### Findings screen 3-row inspector redesign (#447)
- **Problem**: Findings list had no border, list/detail height mismatch, no-service-context took a full card, filter state always verbose.
- **Fix**: List panel wrapped in `renderCardBounded` with `Findings N/N` title. Layout restructured to 3 rows: top (list+detail via `joinColumns`), middle (filter+context cards), bottom (full-width guidance). No-service-context shows compact inline (`Scope: host · No service context · Source: ...`). Filter state shows `All filters clear` when all default.
- **Key files**: `internal/tui/screen_findings.go` — `render()` (lines 416-488), `renderUltraWideFindings()`, `renderRelatedFindingsCard()`, `renderFilterStateCard()`.

## QA Session 2026-05-21 (Commits f77f297 → 7799015)

Verification of #444 (fix preview) + #443 (findings dedup) in 1400×800 viewport.

| Shot | Focus | Finding |
|------|-------|---------|
| Findings detail wide | detail card stops at metadata, no duplicate Fix guidance | ✅ Clean — 하단 guidance strip만 표시 |
| Fix preview wide | preview diff, action buttons, status line | ✅ Clean — truncation 해결 (문구 단축 적용) |
| Report wide | right border/corner, spacing | ✅ Clean — border clipping 없음, spacing 일관됨 |

회귀: 없음.

## QA Session 2026-05-21 (Commit 8e71b77 → 1763022)

Verification of #450 (Report spacing refactor) at 3 viewports.

| Shot | Focus | Finding |
|------|-------|---------|
| Report wide (1400×800) | 2×3 row layout, col gap, guidance boundary | ✅ Clean — spacing 일관됨, right border 정상 |
| Report medium (640×480) | stacked cards, row gap | ⚠️ Export report title 중복 → 즉시 수정 |
| Report ultrawide small (316×75) | compressed layout | ✅ Clean — 모든 gap 일관됨 |

**회귀 발견 및 수정:** Medium Report의 `Export report` 카드 제목이 border title + body title로 중복 표시됨. body의 중복 `exportTitle` 라인 제거로 수정.

## QA Session 2026-05-21 (Commit e1edb04)

Verification of #442 (right border/corner clipping) — UI audit.

| Component | Finding |
|-----------|---------|
| UltraWide Findings top row (gap=1) | ✅ splitColumns + joinColumns gap 일치 |
| UltraWide Findings bottom cards | ✅ **수정 완료** — gap 불일치로 인한 1글자 overflow 해결 |
| UltraWide Report rows | ✅ 모든 row gap 일치 |
| Clean Findings UltraWide | ✅ splitColumns(width, 2, 2) + joinColumns(..., 2) 정합 |
| assertDisplayWidthLTE | ✅ 6개 render 함수에 caller 추가 (debug 모드) |

**모든 80개 이슈 해결** 🎉

v1.0.0-rewrite의 모든 TUI layout/QA 이슈가 종료되었습니다.

## QA Session 2026-05-21 (Commit d420ddd)

Browser-based visual verification of #442 at 1400×800.

| Shot | Focus | Finding |
|------|-------|---------|
| Findings wide | bottom cards right border/corner | ✅ Clean — gap 불일치 수정으로 overflow 없음 |
| Report wide | right border/corner, spacing | ✅ Clean — border clipping 없음, spacing 일관됨 |

모든 80개 이슈에 대한 최종 TUI QA 완료. v1.0.0-rewrite 마감.

## QA Session 2026-05-22 (Commit a1e49f4)

Browser-based visual verification of #451 (layout contract) at wide/medium/narrow/tiny viewports.

| Shot | Focus | Finding |
|------|-------|---------|
| Overview wide (1400×800) | fixed skeleton, borders, footer | ✅ Clean — slot-based skeleton 안정적 |
| Findings list/detail wide | detail panel height stability | ✅ Detail panel height 고정, 선택 변경에도 frame 유지 |
| Fix preview wide | YAML context + diff markers | ✅ 정상 표시 |
| History wide | axis bars, severity, info | ✅ Clean |
| Help wide | centering, overlay | ✅ 중앙 정렬, 단 높이 clip 있음 |
| Overview medium (640×480) | 2-column reflow | ✅ Clean — text truncation but no breakage |
| Overview narrow (400×300) | single-column fallback | ✅ Fallback 정상 |
| Overview tiny (280×200) | minimal fallback | ✅ 텍스트 fallback 정상 |
| Overview wide (final) | after viewport detours | ✅ 회귀 없음 |

**회귀: 없음.** Findings detail panel height가 모든 선택 항목에서 동일하게 유지됨. Search/Filter/Settings 키가 특정 overlay 상태에서 캡처되지 않은 것은 브라우저 키 전달 이슈로 추정.
