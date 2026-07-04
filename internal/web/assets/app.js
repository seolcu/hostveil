const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
const toolLabels = { trivy: "Trivy", lynis: "Lynis", compose: "Compose", update: "Update" };
const statusIcons = ["○", "◌", "✓", "−", "✗", "◪"];

const state = {
  live: null,
  phase: "loading",
  selected: 0,
  query: "",
  severity: "all",
  source: "all",
  remediation: "all",
  service: "all",
  sortBy: "severity",
  sortDir: "asc",
  pollTimer: null,
  selectedSet: new Set(),
  renderPending: false,
};

const $ = (id) => document.getElementById(id);

let fetchFailures = 0;

async function fetchResult() {
  try {
    const response = await fetch("/api/result");
    state.live = await response.json();
    state.phase = state.live.phase || "complete";
    invalidateFindingsCache();
    fetchFailures = 0;
    // Stop polling once the scan completes — the snapshot is static
    // until the user triggers a rescan.
    if (state.phase !== "loading" && state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
    render();
  } catch (error) {
    fetchFailures++;
    if (fetchFailures >= 5) {
      showToast("Connection lost — retrying...", "toast-error");
      fetchFailures = 0;
    }
  }
}

// Cached sorted+filtered findings. Invalidated when inputs change.
let cachedFindings = null;
let cachedFindingsKey = null;

function findings() {
  const items = state.live?.findings || [];
  // Build a cache key from inputs that affect the result.
  const key =
    items.length + "|" +
    state.severity + "|" +
    state.source + "|" +
    state.remediation + "|" +
    state.service + "|" +
    state.query + "|" +
    state.sortBy + "|" +
    state.sortDir;
  if (cachedFindings && cachedFindingsKey === key) {
    return cachedFindings;
  }
  const query = state.query;
  const out = items
    .filter((f) => state.severity === "all" || severity(f) === state.severity)
    .filter((f) => state.source === "all" || source(f) === state.source)
    .filter((f) => state.remediation === "all" || remediation(f) === state.remediation)
    .filter((f) => state.service === "all" || (f.service || "") === state.service)
    .filter((f) => !query || searchable(f).includes(query))
    .sort(sorter);
  cachedFindings = out;
  cachedFindingsKey = key;
  return out;
}

function invalidateFindingsCache() {
  cachedFindings = null;
  cachedFindingsKey = null;
}

async function init() {
  await fetchResult();
  if (state.phase === "loading") {
    state.pollTimer = setInterval(fetchResult, 2000);
  }
  bindControls();
  bindVisibilityPause();
}

function bindVisibilityPause() {
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      if (state.pollTimer) {
        clearInterval(state.pollTimer);
        state.pollTimer = null;
      }
    } else if (state.phase === "loading") {
      state.pollTimer = setInterval(fetchResult, 2000);
    }
  });
}

let searchTimer = null;

function bindControls() {
  $("query")?.addEventListener("input", (event) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.query = event.target.value.toLowerCase();
      state.selected = 0;
      render();
    }, 150);
  });
  $("sortBy")?.addEventListener("change", (event) => {
    state.sortBy = event.target.value;
    render();
  });
  $("clearFilters")?.addEventListener("click", () => {
    $("clearFilters").blur();
    state.query = "";
    state.severity = "all";
    state.source = "all";
    state.remediation = "all";
    state.service = "all";
    state.selected = 0;
    if ($("query")) $("query").value = "";
    render();
  });
  $("historyRefreshBtn")?.addEventListener("click", () => {
    $("historyRefreshBtn").blur();
    loadHistory();
  });

  const sortFields = { 1: "severity", 2: "source", 4: "title", 5: "remediation" };
  document.querySelectorAll("th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const col = Number(th.dataset.col);
      const field = sortFields[col];
      if (!field) return;
      if (state.sortBy === field) {
        state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
      } else {
        state.sortBy = field;
        state.sortDir = "asc";
      }
      const sel = $("sortBy");
      if (sel) sel.value = state.sortBy;
      render();
    });
  });

  $("selectAllCheck")?.addEventListener("change", (event) => {
    const visible = findings();
    if (event.target.checked) {
      visible.forEach((f) => {
        if (isBatchSelectable(f)) state.selectedSet.add(f.id);
      });
    } else {
      visible.forEach((f) => {
        if (isBatchSelectable(f)) state.selectedSet.delete(f.id);
      });
    }
    render();
  });

  const actions = document.createElement("div");
  actions.className = "panel-head-actions";

  const rescanBtn = document.createElement("button");
  rescanBtn.id = "rescanBtn";
  rescanBtn.type = "button";
  rescanBtn.textContent = "Rescan";
  actions.appendChild(rescanBtn);

  const recalcBtn = document.createElement("button");
  recalcBtn.id = "recalcBtn";
  recalcBtn.type = "button";
  recalcBtn.textContent = "Recalc";
  recalcBtn.title = "Recalculate score";
  actions.appendChild(recalcBtn);
  recalcBtn.addEventListener("click", async () => {
    recalcBtn.blur();
    try {
      const resp = await fetch("/api/recalc", { method: "POST" });
      const snap = await resp.json();
      state.live = snap;
      invalidateFindingsCache();
      render();
      showToast("Score recalculated", "toast-info");
    } catch {
      showToast("Recalculation failed", "toast-error");
    }
  });
  rescanBtn.addEventListener("click", async () => {
    rescanBtn.blur();
    rescanBtn.disabled = true;
    rescanBtn.classList.add("loading");
    rescanBtn.textContent = "Scanning...";
    try {
      await fetch("/api/rescan", { method: "POST" });
      // The rescan runs in a goroutine on the server and the snapshot
      // phase transitions to "loading" immediately. The polling loop
      // stops on its own once phase !== "loading" (see fetchResult).
      // doRender will re-set the button label and disabled state as
      // the phase changes, so we intentionally do NOT reset the
      // button here — doing so would briefly show "Rescan" while the
      // scan is still running.
      if (!state.pollTimer) {
        state.pollTimer = setInterval(fetchResult, 2000);
      }
    } catch (e) {
      console.error("Rescan failed");
      rescanBtn.disabled = false;
      rescanBtn.classList.remove("loading");
      rescanBtn.textContent = "Rescan";
    }
  });

  const exportBtn = document.createElement("button");
  exportBtn.id = "exportBtn";
  exportBtn.type = "button";
  exportBtn.textContent = "Export";
  actions.appendChild(exportBtn);

  const historyBtn = document.createElement("button");
  historyBtn.id = "historyBtn";
  historyBtn.type = "button";
  historyBtn.textContent = "History";
  historyBtn.title = "View fix checkpoints and rollback";
  actions.appendChild(historyBtn);
  historyBtn.addEventListener("click", () => {
    historyBtn.blur();
    toggleHistoryPanel();
  });

  exportBtn.addEventListener("click", () => {
    exportBtn.blur();
    showExportModal();
  });

  const fixSelectedBtn = document.createElement("button");
  fixSelectedBtn.id = "fixSelectedBtn";
  fixSelectedBtn.type = "button";
  fixSelectedBtn.className = "fix-selected-btn";
  actions.appendChild(fixSelectedBtn);
  fixSelectedBtn.addEventListener("click", () => {
    fixSelectedBtn.blur();
    applyFixBatch();
  });

  document.querySelector(".panel-head").appendChild(actions);

  document.addEventListener("keydown", (e) => {
    // Don't intercept keys while typing in form fields
    if (isTypingTarget(e.target)) {
      if (e.key === "Escape") {
        e.target.blur();
      }
      return;
    }

    // Close any open modal
    if (e.key === "Escape") {
      closeFixModal();
      closeExportModal();
      closeHelpModal();
      closeRollbackModal();
      return;
    }

    if (e.key === "?" || (e.shiftKey && e.key === "/")) {
      e.preventDefault();
      showHelpModal();
      return;
    }

    // Enter: confirm fix modal (must run before the modal-open guard)
    if (e.key === "Enter") {
      const fixModal = document.getElementById("fixModal");
      if (fixModal) {
        const yesBtn = fixModal.querySelector("#modalFixYes");
        if (yesBtn && !yesBtn.disabled) yesBtn.click();
        return;
      }
    }

    // Don't process other shortcuts if a modal is open
    const fixModal = document.getElementById("fixModal");
    const exportModal = document.getElementById("exportModal");
    const helpModal = document.getElementById("helpModal");
    if (fixModal || exportModal || helpModal) return;

    // ArrowUp / ArrowDown: navigate findings
    if (e.key === "ArrowDown") {
      e.preventDefault();
      const visible = findings();
      if (visible.length > 0) {
        state.selected = Math.min(state.selected + 1, visible.length - 1);
        render();
        scrollSelectedIntoView();
      }
      return;
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      state.selected = Math.max(state.selected - 1, 0);
      render();
      scrollSelectedIntoView();
      return;
    }

    // q: quit (leave WebUI — just close window hint)
    if (e.key === "q") {
      e.preventDefault();
      showToast("Press Ctrl+W or close the tab to leave", "toast-info");
      return;
    }

    // /: focus search
    if (e.key === "/") {
      e.preventDefault();
      const search = $("query");
      if (search) {
        search.focus();
        search.select();
      }
      return;
    }

    // f: fix selected or current finding
    if (e.key === "f") {
      e.preventDefault();
      if (state.selectedSet.size > 0) {
        applyFixBatch();
      } else {
        const visible = findings();
        const f = visible[state.selected];
        if (f) applyFix(f, $("detail")?.querySelector(".fix-btn"));
      }
      return;
    }

    // 0-4: severity filter
    const sevKeys = { "0": "all", "1": "critical", "2": "high", "3": "medium", "4": "low" };
    if (e.key in sevKeys) {
      e.preventDefault();
      state.severity = sevKeys[e.key];
      state.selected = 0;
      render();
      return;
    }

    // s: cycle source filter (all → trivy → lynis → compose → all, matching TUI)
    if (e.key === "s") {
      e.preventDefault();
      const sources = ["all", "trivy", "lynis", "compose"];
      const idx = sources.indexOf(state.source);
      state.source = sources[(idx + 1) % sources.length];
      state.selected = 0;
      render();
      return;
    }

    // r: cycle remediation filter
    if (e.key === "r") {
      e.preventDefault();
      const rems = ["all", "auto", "review", "unavailable", "manual"];
      const idx = rems.indexOf(state.remediation);
      state.remediation = rems[(idx + 1) % rems.length];
      state.selected = 0;
      render();
      return;
    }

    // o: cycle sort field
    if (e.key === "o" && !e.shiftKey) {
      e.preventDefault();
      const sorts = ["severity", "source", "title", "remediation"];
      const idx = sorts.indexOf(state.sortBy);
      state.sortBy = sorts[(idx + 1) % sorts.length];
      state.sortDir = "asc";
      const sel = $("sortBy");
      if (sel) sel.value = state.sortBy;
      render();
      return;
    }

    // O (Shift+o): toggle sort direction
    if (e.key === "O" || (e.shiftKey && e.key === "o")) {
      e.preventDefault();
      state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
      render();
      return;
    }

    // v: cycle service filter
    if (e.key === "v") {
      e.preventDefault();
      const items = state.live?.findings || [];
      const services = ["all"];
      const seen = { all: true };
      for (const f of items) {
        const s = f.service || "";
        if (s && !seen[s]) {
          seen[s] = true;
          services.push(s);
        }
      }
      if (services.length <= 1) return;
      const idx = services.indexOf(state.service);
      state.service = services[(idx + 1) % services.length];
      state.selected = 0;
      render();
      return;
    }

    // R (Shift+r): clear all filters (single press — single-press reset for WebUI)
    if (e.key === "R" || (e.shiftKey && e.key === "r")) {
      e.preventDefault();
      state.query = "";
      state.severity = "all";
      state.source = "all";
      state.remediation = "all";
      state.service = "all";
      state.selected = 0;
      if ($("query")) $("query").value = "";
      render();
      showToast("Filters cleared", "toast-info");
      return;
    }

    // ctrl+a: select all visible
    if (e.ctrlKey && (e.key === "a" || e.key === "A")) {
      e.preventDefault();
      const visible = findings();
      const selectable = visible.filter(isBatchSelectable);
      if (state.selectedSet.size === selectable.length && selectable.length > 0) {
        state.selectedSet = new Set();
      } else {
        state.selectedSet = new Set();
        for (const f of visible) {
          if (isBatchSelectable(f)) state.selectedSet.add(f.id);
        }
      }
      render();
      return;
    }

    // ctrl+r: recalc
    if (e.ctrlKey && (e.key === "r" || e.key === "R")) {
      e.preventDefault();
      $("recalcBtn")?.click();
      return;
    }

    // ctrl+s: rescan
    if (e.ctrlKey && (e.key === "s" || e.key === "S")) {
      e.preventDefault();
      $("rescanBtn")?.click();
      return;
    }

    // e: open export modal
    if (e.key === "e") {
      e.preventDefault();
      showExportModal();
      return;
    }

    // Enter: open fix for selected finding
    // (confirm-fix-modal case is handled above the modal-open guard)
    if (e.key === "Enter") {
      const fixBtn = $("detail")?.querySelector(".fix-btn");
      if (fixBtn) fixBtn.click();
      return;
    }

    // Space: toggle selection
    if (e.key === " " || e.key === "Spacebar") {
      e.preventDefault();
      const visible = findings();
      const finding = visible[state.selected];
      if (!finding) return;
      if (!isBatchSelectable(finding)) return;
      toggleFindingSelection(finding.id);
      render();
      return;
    }
  });
}

let renderTimer = null;

function render() {
  if (renderTimer) {
    cancelAnimationFrame(renderTimer);
    renderTimer = null;
  }
  renderTimer = requestAnimationFrame(doRender);
}

function doRender() {
  renderTimer = null;
  if (state.phase === "loading") {
    renderLoading();
    return;
  }
  document.querySelector(".shell").className = "shell";
  const host = state.live?.hostname || "";
  const ip = state.live?.local_ip || "";
  $("sysinfo").textContent = host ? `${host} @ ${ip}` : "";
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  // Reset the Rescan button to its idle state. It was set to
  // "Scanning..." when the user clicked it, and renderLoading()
  // hides the findings-panel (and therefore the button) during the
  // scan. Now that the scan has finished, put the button back.
  const rescanBtn = $("rescanBtn");
  if (rescanBtn) {
    rescanBtn.disabled = false;
    rescanBtn.classList.remove("loading");
    rescanBtn.textContent = "Rescan";
  }
  const visible = findings();
  if (state.selected >= visible.length) state.selected = Math.max(0, visible.length - 1);
  renderMetrics();
  renderScoreBreakdown();
  renderFilters();
  document.querySelectorAll("th.sortable").forEach((th) => {
    const col = Number(th.dataset.col);
    const sortFields = { 1: "severity", 2: "source", 4: "title", 5: "remediation" };
    const field = sortFields[col];
    th.classList.remove("asc", "desc");
    if (field === state.sortBy) {
      th.classList.add(state.sortDir);
    }
  });
  renderTable(visible);
  renderDetail(visible[state.selected]);
  updateFixSelectedBtn();
}

async function refreshResultNow() {
  try {
    const response = await fetch("/api/result");
    state.live = await response.json();
    state.phase = state.live.phase || "complete";
    invalidateFindingsCache();
    fetchFailures = 0;
    if (renderTimer) {
      cancelAnimationFrame(renderTimer);
      renderTimer = null;
    }
    doRender();
  } catch (error) {
    fetchFailures++;
    if (fetchFailures >= 5) {
      showToast("Connection lost — retrying...", "toast-error");
      fetchFailures = 0;
    }
  }
}

function renderLoading() {
  const tools = state.live.tools || {};
  document.querySelector(".shell").className = "shell loading";
  $("score").textContent = "--/100";
  $("score").className = "";
  const toolOrder = ["update", "trivy", "lynis", "compose"];
  const activeTools = toolOrder.filter((name) => tools[name]);
  const doneCount = activeTools.filter((name) => {
    const s = tools[name].status;
    return s === 2 || s === 3 || s === 4 || s === 5;
  }).length;
  const progress = activeTools.length > 0 ? Math.round((doneCount / activeTools.length) * 100) : 0;
  const toolRows = activeTools
    .map((name) => {
      const t = tools[name];
      const icon = statusIcons[t.status] || "○";
      const iconClass = ["", "running", "done", "muted", "error", "degraded"][t.status] || "";
      return `<div class="tool-row"><span class="tool-icon ${iconClass}">${icon}</span><span class="tool-name">${toolLabels[name] || name}</span><span class="tool-msg">${escapeHTML(t.message || "")}</span></div>`;
    })
    .join("");
  $("metrics").innerHTML = "";
  $("scoreBreakdown").hidden = true;
  $("scoreBreakdown").innerHTML = "";
  $("findings").innerHTML = "";
  $("detail").innerHTML = `
    <div class="loading-state">
      <h2>Scanning...</h2>
      <div class="progress-bar"><div class="progress-fill" style="width:${progress}%"></div></div>
      <p class="muted" style="margin-top:8px">${progress}% complete</p>
      <div class="tool-status">${toolRows}</div>
      <p class="muted" style="margin-top:20px">Results appear automatically when scans complete.</p>
    </div>`;
  $("findingCount").textContent = "Scanning...";
}

function scrollSelectedIntoView() {
  const row = $("findings")?.querySelector("tr.selected");
  if (row) row.scrollIntoView({ block: "nearest", behavior: "smooth" });
}



function sorter(a, b) {
  const dir = state.sortDir === "desc" ? -1 : 1;
  if (state.sortBy === "source") return dir * (source(a).localeCompare(source(b)) || severityOrder[severity(a)] - severityOrder[severity(b)]);
  if (state.sortBy === "title") return dir * title(a).localeCompare(title(b));
  if (state.sortBy === "remediation") return dir * remediation(a).localeCompare(remediation(b));
  return dir * (severityOrder[severity(a)] - severityOrder[severity(b)] || title(a).localeCompare(title(b)));
}

function renderMetrics() {
  const items = state.live?.findings || [];
  const score = state.live?.score ?? 0;
  if (items.length === 0) {
    $("score").textContent = "Clean";
    $("score").className = "low";
  } else {
    $("score").textContent = `${score}/100`;
    $("score").className = severityClassForScore(score);
  }
  const scoreplate = document.querySelector(".scoreplate");
  if (scoreplate) {
    scoreplate.className = "scoreplate score-" + severityClassForScore(score);
  }
  const counts = countBy(items, severity);
  const fixable = items.filter((f) => ["auto", "review"].includes(remediation(f))).length;
  const metrics = [
    ["Total", items.length, "", "metric--total"],
    ["Critical", counts.critical || 0, "critical", "metric--critical"],
    ["High", counts.high || 0, "high", "metric--high"],
    ["Medium", counts.medium || 0, "medium", "metric--medium"],
    ["Low", counts.low || 0, "low", "metric--low"],
    ["Fixable", fixable, "", "metric--fixable"],
  ];
  $("metrics").innerHTML = metrics.map(([label, value, cls = "", extra = ""]) => `<article class="metric ${extra}"><span>${label}</span><strong class="${cls}">${value}</strong></article>`).join("");
}

function renderScoreBreakdown() {
  const container = $("scoreBreakdown");
  if (!container) return;
  const axes = state.live?.score_breakdown?.axes || [];
  if (!axes.length) {
    container.hidden = true;
    container.innerHTML = "";
    return;
  }

  container.hidden = false;
  const cards = axes.map((axis) => {
    const axisLabel = axis.label || axis.id || "Score axis";
    const score = Math.max(0, Math.min(100, Math.round(Number(axis.score) || 0)));
    const penalty = Math.max(0, Math.round(Number(axis.penalty) || 0));
    const maxPenalty = Math.max(0, Math.round(Number(axis.max_penalty) || 0));
    const penaltyPct = maxPenalty > 0 ? Math.min(100, Math.round((penalty / maxPenalty) * 100)) : 0;
    const severityCounts = [
      ["critical", Number(axis.critical) || 0, "C"],
      ["high", Number(axis.high) || 0, "H"],
      ["medium", Number(axis.medium) || 0, "M"],
      ["low", Number(axis.low) || 0, "L"],
    ].filter(([, count]) => count > 0);
    const countSummary = severityCounts.length
      ? severityCounts.map(([cls, count, label]) => `<span class="${cls}">${count}${label}</span>`).join("")
      : `<span class="muted">No active findings</span>`;
    const capText = maxPenalty > 0 ? `${penalty}/${maxPenalty} penalty cap used` : `${penalty} penalty`;
    return `<article class="score-axis ${severityClassForScore(score)}" data-axis="${escapeHTML(axis.id || "")}">
      <div class="score-axis-top">
        <span>${escapeHTML(axisLabel)}</span>
        <strong>${score}/100</strong>
      </div>
      <div class="score-axis-bar" aria-label="${escapeHTML(`${axisLabel}: ${capText}`)}">
        <span style="width:${penaltyPct}%"></span>
      </div>
      <div class="score-axis-meta">
        <span>${escapeHTML(capText)}</span>
        <span class="score-axis-counts">${countSummary}</span>
      </div>
    </article>`;
  }).join("");

  container.innerHTML = `
    <div class="score-breakdown-head">
      <span>Score breakdown</span>
      <p>Each category has its own penalty cap, so one scanner cannot dominate the whole score.</p>
    </div>
    <div class="score-axis-grid">${cards}</div>`;
}

function renderFilters() {
  const items = state.live?.findings || [];
  renderChips("severityFilters", ["all", "critical", "high", "medium", "low"], "severity");
  renderChips("sourceFilters", ["all", ...Object.keys(countBy(items, source)).sort()], "source");
  renderChips("remediationFilters", ["all", ...Object.keys(countBy(items, remediation)).sort()], "remediation");
  const services = ["all", ...Object.keys(countBy(items, (f) => f.service || "")).sort()];
  renderChips("serviceFilters", services.filter((s) => s !== ""), "service");
}

function renderChips(id, values, key) {
  if (!$(id)) return;
  $(id).innerHTML = values.map((value) => `<button class="chip ${state[key] === value ? "active" : ""}" data-key="${key}" data-value="${escapeHTML(value)}" type="button">${escapeHTML(label(value))}</button>`).join("");
  $(id).querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => {
      state[button.dataset.key] = button.dataset.value;
      state.selected = 0;
      render();
    });
  });
}

function renderTable(visible) {
  $("findingCount").textContent = `${visible.length} visible`;
  const selectable = visible.filter(isBatchSelectable);
  const allSelected = selectable.length > 0 && selectable.every((f) => state.selectedSet.has(f.id));
  const someSelected = selectable.some((f) => state.selectedSet.has(f.id));
  const checkState = allSelected ? "checked" : someSelected ? "indeterminate" : "";

  $("findings").innerHTML = visible.map((f, index) => {
    const selectableRow = isBatchSelectable(f);
    const fixedClass = f.fixed ? "fixed" : "";
    const unavailClass = !selectableRow ? "disabled" : "";
    const selClass = index === state.selected ? "selected" : "";
    const rowSelectedClass = selectableRow && state.selectedSet.has(f.id) ? "row-selected" : "";
    const rowClass = [fixedClass, unavailClass, selClass, rowSelectedClass].filter(Boolean).join(" ");
    const sevDisplay = f.fixed ? "&#10003;" : `<span class="badge ${severity(f)}">${severity(f)}</span>`;
    const srcDisplay = f.fixed ? "" : `<span class="muted">${source(f)}</span>`;
    const fixDisplay = f.fixed ? "Fixed" : label(remediation(f));
    const titleDisplay = f.fixed ? `<span style="opacity:0.5;text-decoration:line-through">${escapeHTML(title(f))}</span>` : escapeHTML(title(f));
    const checked = selectableRow && state.selectedSet.has(f.id) ? "checked" : "";
    const disabledAttr = !selectableRow ? "disabled" : "";
    const sevAttr = f.fixed ? "" : ` data-severity="${severity(f)}"`;
    return `<tr class="${rowClass}" data-index="${index}" data-id="${escapeHTML(f.id)}"${sevAttr}>
      <td class="check-cell"><input type="checkbox" ${checked} ${disabledAttr} data-id="${escapeHTML(f.id)}" class="row-check"></td>
      <td>${sevDisplay}</td>
      <td>${srcDisplay}</td>
      <td class="id">${escapeHTML(shortId(f.id))}</td>
      <td class="title">${titleDisplay}</td>
      <td class="muted">${fixDisplay}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="6" class="muted">No findings match the current filters.</td></tr>`;

  const selectAllCheck = $("selectAllCheck");
  if (selectAllCheck) {
    selectAllCheck.checked = allSelected;
    selectAllCheck.indeterminate = someSelected && !allSelected;
  }

  $("findings").querySelectorAll("tr[data-index]").forEach((row) => {
    row.addEventListener("click", (e) => {
      if (e.target.classList.contains("row-check")) return;
      if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
      state.selected = Number(row.dataset.index);
      render();
    });
    row.addEventListener("dblclick", (e) => {
      if (e.target.classList.contains("row-check")) return;
      if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
      state.selected = Number(row.dataset.index);
      const finding = visible[state.selected];
      if (!finding) return;
      if (!isBatchSelectable(finding)) return;
      toggleFindingSelection(finding.id);
      render();
    });
  });
  $("findings").querySelectorAll(".row-check").forEach((cb) => {
    cb.addEventListener("click", (e) => {
      e.stopPropagation();
      if (cb.disabled) return;
      setFindingSelection(cb.dataset.id, cb.checked);
      render();
    });
  });
}

function isTypingTarget(target) {
  if (!target) return false;
  const tag = target.tagName;
  if (tag === "TEXTAREA" || target.isContentEditable) return true;
  if (tag === "INPUT") {
    const t = (target.type || "").toLowerCase();
    return t === "text" || t === "search" || t === "email" || t === "password" || t === "url" || t === "tel";
  }
  return false;
}

function setFindingSelection(id, selected) {
  if (!id) return;
  if (selected) {
    state.selectedSet.add(id);
  } else {
    state.selectedSet.delete(id);
  }
}

function toggleFindingSelection(id) {
  if (!id) return;
  setFindingSelection(id, !state.selectedSet.has(id));
}

function isBatchSelectable(f) {
  const r = remediation(f);
  return !f.fixed && r !== "unavailable" && r !== "manual";
}


function renderDetail(f) {
  if (!f) {
    $("detail").innerHTML = `<div class="empty-detail"><div class="empty-detail-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/></svg></div><h2>Select a finding</h2><p>Choose an item from the table to inspect evidence and remediation guidance.</p></div>`;
    return;
  }
  const evidence = f.evidence || {};
  const evKeys = Object.keys(evidence).sort();
  const evidenceHTML = evKeys.length > 0 ? `
    <details class="evidence-details">
      <summary>Evidence (${evKeys.length})</summary>
      ${evKeys.map((key) => `<pre><strong>${escapeHTML(key)}</strong>\n${escapeHTML(evidence[key])}</pre>`).join("")}
    </details>` : "";
  const metadata = f.metadata || {};
  const metaKeys = Object.keys(metadata).sort();
  const metadataHTML = metaKeys.length > 0 ? `
    <details class="evidence-details">
      <summary>Metadata (${metaKeys.length})</summary>
      ${metaKeys.map((key) => `<pre><strong>${escapeHTML(key)}</strong>\n${escapeHTML(metadata[key])}</pre>`).join("")}
    </details>` : "";
  const fixable = !f.fixed && (f.remediation === 0 || f.remediation === 1);
  $("detail").innerHTML = `
    <span class="badge ${severity(f)}">${severity(f)}</span>
    <h2>${escapeHTML(title(f))}</h2>
    ${fixable ? `<button class="fix-btn" data-finding-id="${escapeHTML(f.id)}">Fix</button>` : ""}
    <dl class="detail-meta">
      <dt>ID</dt><dd>${escapeHTML(f.id || "")}</dd>
      <dt>Source</dt><dd>${source(f)}</dd>
      <dt>Remediation</dt><dd>${label(remediation(f))} <span class="muted">— ${remediationHint(remediation(f))}</span></dd>
      ${f.service ? `<dt>Service</dt><dd>${escapeHTML(f.service)}</dd>` : ""}
    </dl>
    ${section("Description", f.description)}
    ${section("How to fix", f.how_to_fix, true)}
    ${evidenceHTML}
    ${metadataHTML}
    <div id="fixResult"></div>
  `;
  const detail = $("detail");
  detail.querySelectorAll(".toggle-more").forEach((btn) => {
    btn.onclick = () => {
      const body = btn.parentElement.querySelector(".collapse-body");
      // body.dataset.{full,truncated} are auto-decoded by the browser from the
      // data-* attribute (HTML entities become real characters). Re-escape them
      // before inserting as HTML — a malicious description from a scan source
      // (lynis, trivy, or compose YAML) would otherwise render as live markup.
      if (btn.textContent === "View more") {
        body.innerHTML = `<p>${escapeHTML(body.dataset.full)}</p>`;
        btn.textContent = "View less";
      } else {
        body.innerHTML = `<p>${escapeHTML(body.dataset.truncated)}</p>`;
        btn.textContent = "View more";
      }
    };
  });
  detail.querySelectorAll(".copy").forEach((btn) => {
    btn.onclick = () => navigator.clipboard?.writeText(f.how_to_fix || "");
  });
  const fixBtn = detail.querySelector(".fix-btn");
  if (fixBtn) fixBtn.onclick = () => applyFix(f, fixBtn);
}

async function applyFix(finding, button) {
  const resultDiv = $("fixResult");
  resultDiv.innerHTML = "";

  try {
    const infoResp = await fetch("/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding, action_index: 0, info_only: true }),
    });
    const info = await infoResp.json();
    if (!info.success) {
      resultDiv.innerHTML = `<div class="fix-error">&#10007; ${escapeHTML(info.error || "Fix info unavailable")}</div>`;
      return;
    }

    const actions = info.actions || [];
    if (actions.length === 0) {
      resultDiv.innerHTML = `<div class="fix-error">No actions available</div>`;
      return;
    }

    if (actions.length === 1) {
      showFixModal(info.label, actions[0], () => {
        closeFixModal();
        doApplyFix(finding, button, 0);
      });
    } else {
      showFixActionModal(info.label, actions, (selectedIdx) => {
        closeFixModal();
        doApplyFix(finding, button, selectedIdx);
      });
    }
  } catch (error) {
    resultDiv.innerHTML = `<div class="fix-error">&#10007; ${escapeHTML(error.message)}</div>`;
    return;
  }
}

async function doApplyFix(finding, button, actionIdx) {
  const resultDiv = $("fixResult");
  button.disabled = true;
  button.classList.add("loading");
  button.textContent = "Applying...";
  try {
    const response = await fetch("/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding, action_index: actionIdx }),
    });
    const result = await response.json();
    if (result.success) {
      const successHtml = `<div class="fix-success">&#10003; ${escapeHTML(result.label || "Fixed")}</div>`;
      const diffHtml = result.diff ? highlightDiff(result.diff) : "";
      await refreshResultNow();
      const newResultDiv = $("fixResult");
      if (newResultDiv) {
        newResultDiv.innerHTML = successHtml + diffHtml;
      }
      if (result.also_fixed?.length > 0) {
        showToast(`Also resolved ${result.also_fixed.length} related finding${result.also_fixed.length !== 1 ? "s" : ""}`, "toast-info");
      }
    } else {
      resultDiv.innerHTML = `<div class="fix-error">&#10007; ${escapeHTML(result.error || "Fix failed")}</div>`;
    }
  } catch (error) {
    resultDiv.innerHTML = `<div class="fix-error">&#10007; ${escapeHTML(error.message)}</div>`;
  }
  button.disabled = false;
  button.classList.remove("loading");
  button.textContent = "Fix";
}

function highlightDiff(diff) {
  const lines = diff.split("\n");
  const highlighted = lines.map((line) => {
    if (line.startsWith("+") && !line.startsWith("+++")) {
      return `<span class="diff-add">${escapeHTML(line)}</span>`;
    }
    if (line.startsWith("-") && !line.startsWith("---")) {
      return `<span class="diff-del">${escapeHTML(line)}</span>`;
    }
    if (line.startsWith("@@")) {
      return `<span class="diff-hunk">${escapeHTML(line)}</span>`;
    }
    return escapeHTML(line);
  }).join("\n");
  return `<pre class="fix-diff">${highlighted}</pre>`;
}

function section(name, content, copy = false) {
  if (!content) return "";
  const longText = content.length > 300;
  if (longText) {
    const truncated = content.slice(0, 300) + "...";
    return `<section class="section collapsible">
      <h3>${name}</h3>
      <div class="collapse-body" data-full="${escapeHTML(content)}" data-truncated="${escapeHTML(truncated)}">
        <p>${escapeHTML(truncated)}</p>
      </div>
      <button class="toggle-more" type="button">View more</button>
      ${copy ? `<button class="copy" type="button">Copy guidance</button>` : ""}
    </section>`;
  }
  return `<section class="section"><h3>${name}</h3><p>${escapeHTML(content)}</p>${copy ? `<button class="copy" type="button">Copy guidance</button>` : ""}</section>`;
}

function countBy(items, fn) { return items.reduce((acc, item) => ((acc[fn(item)] = (acc[fn(item)] || 0) + 1), acc), {}); }
function severity(f) { return ["critical", "high", "medium", "low"][f.severity] || String(f.severity || "unknown").toLowerCase(); }
function source(f) { return ["trivy", "lynis", "compose"][f.source] || String(f.source || "unknown").toLowerCase(); }
function remediation(f) { return ["auto", "review", "unavailable", "manual"][f.remediation] || String(f.remediation || "unknown").toLowerCase(); }
// remediationHint returns a short, user-facing explanation of what a
// remediation kind means in practice. Mirrors internal/tui/screen.go's
// remediationHint -- "auto"/"review"/"manual"/"unavailable" are not
// self-explanatory to a first-time user.
function remediationHint(kind) {
  return { auto: "one clear fix, click Apply", review: "multiple options, pick one", manual: "no automated fix, see guidance below", unavailable: "not yet classified" }[kind] || "";
}
function title(f) { return f.title || "Untitled finding"; }
function shortId(id = "") { const parts = id.split("."); return parts[parts.length - 1] || id; }
function searchable(f) { return [f.id, f.title, f.description, f.how_to_fix, f.service, severity(f), source(f), remediation(f), ...Object.values(f.evidence || {})].join(" ").toLowerCase(); }
function label(value) { return value === "all" ? "All" : value.charAt(0).toUpperCase() + value.slice(1); }
function severityClassForScore(score) { return score >= 85 ? "low" : score >= 65 ? "medium" : score >= 40 ? "high" : score >= 20 ? "critical" : "critical"; }
function escapeHTML(value = "") { return String(value).replace(/[&<>'"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[ch])); }

function showFixModal(label, action, onConfirm) {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.id = "fixModal";

  const actionTypeBadge = `<span class="action-type-badge type-${escapeHTML(action.type)}">${escapeHTML(action.type)}</span>`;
  const commandBlock = action.command ? `<div class="action-command"><span class="command-label">Command</span><code>${escapeHTML(action.command)}</code></div>` : "";
  const editPathBlock = action.edit_path ? `<div class="action-edit-path"><span class="path-label">File</span><code>${escapeHTML(action.edit_path)}</code></div>` : "";
  const diffPreviewBlock = action.diff_preview ? `<div class="diff-preview"><span class="preview-label">Diff preview</span>${highlightDiff(action.diff_preview)}</div>` : "";
  const warningBlock = action.warning ? `<p class="fix-warning">&#9888; ${escapeHTML(action.warning)}</p>` : "";

  overlay.innerHTML = `
    <div class="modal-content modal-fix">
      <h2>Apply fix</h2>
      <p class="fix-label">${escapeHTML(label)}</p>
      <div class="action-summary">
        <div class="action-header">
          ${actionTypeBadge}
          <strong>${escapeHTML(action.label)}</strong>
        </div>
        ${commandBlock}
        ${editPathBlock}
        ${diffPreviewBlock}
      </div>
      ${warningBlock}
      <div class="modal-actions">
        <button class="fix-btn" id="modalFixYes">Apply</button>
        <button class="chip" id="modalFixNo">Cancel</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.querySelector("#modalFixYes").onclick = onConfirm;
  overlay.querySelector("#modalFixNo").onclick = closeFixModal;
  // Click on overlay (outside modal) also closes — matches help modal.
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) closeFixModal();
  });
}

function showFixActionModal(label, actions, onSelect, onCancel = () => {}) {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.id = "fixModal";

  const actionItems = actions.map((action, idx) => {
    const actionTypeBadge = `<span class="action-type-badge type-${escapeHTML(action.type)}">${escapeHTML(action.type)}</span>`;
    const commandBlock = action.command ? `<div class="action-command"><span class="command-label">Command</span><code>${escapeHTML(action.command)}</code></div>` : "";
    const editPathBlock = action.edit_path ? `<div class="action-edit-path"><span class="path-label">File</span><code>${escapeHTML(action.edit_path)}</code></div>` : "";
  const diffPreviewBlock = action.diff_preview ? `<div class="diff-preview"><span class="preview-label">Diff preview</span>${highlightDiff(action.diff_preview)}</div>` : "";
    const warningBlock = action.warning ? `<p class="fix-warning">&#9888; ${escapeHTML(action.warning)}</p>` : "";

    return `
      <div class="action-option" data-idx="${idx}">
        <div class="action-option-header">
          <input type="radio" name="fixAction" value="${idx}" id="actionRadio${idx}">
          <label for="actionRadio${idx}">
            ${actionTypeBadge}
            <strong>${escapeHTML(action.label)}</strong>
          </label>
        </div>
        ${commandBlock}
        ${editPathBlock}
        ${diffPreviewBlock}
        ${warningBlock}
      </div>`;
  }).join("");

  overlay.innerHTML = `
    <div class="modal-content modal-fix">
      <h2>Choose action</h2>
      <p class="fix-label">${escapeHTML(label)}</p>
      <div class="action-options">
        ${actionItems}
      </div>
      <div class="modal-actions">
        <button class="fix-btn" id="modalFixYes" disabled>Select an action</button>
        <button class="chip" id="modalFixNo">Cancel</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);

  const radios = overlay.querySelectorAll('input[name="fixAction"]');
  const confirmBtn = overlay.querySelector("#modalFixYes");
  let selectedIdx = -1;

  radios.forEach((radio) => {
    radio.addEventListener("change", () => {
      selectedIdx = Number(radio.value);
      confirmBtn.disabled = false;
      confirmBtn.textContent = "Apply selected";
      overlay.querySelectorAll(".action-option").forEach((opt) => opt.classList.remove("selected"));
      radio.closest(".action-option").classList.add("selected");
    });
  });

  confirmBtn.onclick = () => {
    if (selectedIdx >= 0) onSelect(selectedIdx);
  };
  overlay.querySelector("#modalFixNo").onclick = () => {
    closeFixModal();
    onCancel();
  };
  // Click on overlay (outside modal) also closes — matches help modal.
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) closeFixModal();
  });
}

function closeFixModal() {
  const overlay = document.getElementById("fixModal");
  if (overlay) overlay.remove();
}

function selectedBatchFindings() {
  return findings().filter((f) => state.selectedSet.has(f.id) && isBatchSelectable(f));
}

async function applyFixBatch() {
  const selectedFindings = selectedBatchFindings();
  if (selectedFindings.length === 0) return;

  // Immediate visual feedback
  const fixSelectedBtn = $("fixSelectedBtn");
  if (fixSelectedBtn) {
    fixSelectedBtn.disabled = true;
    fixSelectedBtn.classList.add("loading");
    fixSelectedBtn.textContent = "Applying...";
  }

  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.id = "fixProgressModal";
  overlay.innerHTML = `
    <div class="modal-content modal-fix">
      <h2>Applying fixes</h2>
      <p class="fix-label" id="progressCount">0 / ${selectedFindings.length}</p>
      <div class="progress-bar"><div class="progress-fill" id="progressFill" style="width:0%"></div></div>
      <p class="muted" id="progressLabel" style="margin-top:8px;font-size:12px">Checking fixes...</p>
    </div>`;
  document.body.appendChild(overlay);

  // Parallel info-only fetches
  const results = await Promise.all(selectedFindings.map(async (f) => {
    try {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding: f, action_index: 0, info_only: true }),
      });
      const info = await resp.json();
      return { finding: f, info };
    } catch (e) {
      return { finding: f, info: { success: false, error: e.message } };
    }
  }));

  const allHaveFix = results.every((r) => r.info.success);

  if (!allHaveFix) {
    const modal = document.getElementById("fixProgressModal");
    if (modal) modal.remove();
    if (fixSelectedBtn) {
      fixSelectedBtn.disabled = false;
      fixSelectedBtn.classList.remove("loading");
      updateFixSelectedBtn();
    }
    const failed = results.filter((r) => !r.info.success).map((r) => r.finding.id);
    showToast(`No fix available for: ${failed.join(", ")}`, "toast-error");
    return;
  }

  doApplyFixBatch(results);
}

async function doApplyFixBatch(fixInfos) {
  const selectedFindings = fixInfos.map((fi) => fi.finding);
  let success = 0, fail = 0, skipped = 0, alsoFixedTotal = 0;

  for (let i = 0; i < fixInfos.length; i++) {
    const fi = fixInfos[i];
    const f = fi.finding;
    const actions = fi.info.actions || [];
    const pct = ((i + 1) / selectedFindings.length) * 100;
    const countEl = document.getElementById("progressCount");
    const fillEl = document.getElementById("progressFill");
    const labelEl = document.getElementById("progressLabel");
    if (countEl) countEl.textContent = `${i + 1} / ${selectedFindings.length}`;
    if (fillEl) fillEl.style.width = pct + "%";
    if (labelEl) labelEl.textContent = f.id || "";

    if (actions.length === 0) {
      fail++;
      continue;
    }

    let actionIdx = 0;
    if (actions.length > 1) {
      if (labelEl) labelEl.textContent = `Choose action: ${f.id || ""}`;
      actionIdx = await chooseBatchAction(f, actions, i + 1, selectedFindings.length);
      if (actionIdx < 0) {
        skipped++;
        continue;
      }
    }

    try {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding: f, action_index: actionIdx }),
      });
      const result = await resp.json();
      if (result.success) {
        success++;
        const live = state.live?.findings?.find((lf) => lf.id === f.id);
        if (live) live.fixed = true;
        if (result.also_fixed?.length) alsoFixedTotal += result.also_fixed.length;
      } else {
        fail++;
      }
    } catch {
      fail++;
    }
  }

  const modal = document.getElementById("fixProgressModal");
  if (modal) modal.remove();

  let msg = `Fixed ${success} finding${success !== 1 ? "s" : ""}`;
  if (fail > 0) msg += ` (${fail} failed)`;
  if (skipped > 0) msg += `, ${skipped} skipped`;
  if (alsoFixedTotal > 0) msg += ` — also resolved ${alsoFixedTotal} related`;
  showToast(msg, alsoFixedTotal > 0 ? "toast-info" : "toast-success");

  state.selectedSet.clear();
  await refreshResultNow();

  const batchFixBtn = $("fixSelectedBtn");
  if (batchFixBtn) {
    batchFixBtn.disabled = false;
    batchFixBtn.classList.remove("loading");
    updateFixSelectedBtn();
  }
}

function chooseBatchAction(finding, actions, current, total) {
  return new Promise((resolve) => {
    const labelText = `${current}/${total} · ${shortId(finding.id)} · ${title(finding)}`;
    showFixActionModal(labelText, actions, (selectedIdx) => {
      closeFixModal();
      resolve(selectedIdx);
    }, () => resolve(-1));
  });
}

function showBatchActionModal(fixInfos, onSelect) {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.id = "fixModal";

  // Group findings by their fix label to show unique actions
  const actionMap = new Map();
  for (const fi of fixInfos) {
    if (!fi.info.success) continue;
    const actions = fi.info.actions || [];
    for (const a of actions) {
      const key = `${a.type}:${a.label}`;
      if (!actionMap.has(key)) {
        actionMap.set(key, { ...a, count: 0 });
      }
      actionMap.get(key).count++;
    }
  }

  const uniqueActions = Array.from(actionMap.values());
  const actionItems = uniqueActions.map((action, idx) => {
    const actionTypeBadge = `<span class="action-type-badge type-${escapeHTML(action.type)}">${escapeHTML(action.type)}</span>`;
    const commandBlock = action.command ? `<div class="action-command"><span class="command-label">Command</span><code>${escapeHTML(action.command)}</code></div>` : "";
    const editPathBlock = action.edit_path ? `<div class="action-edit-path"><span class="path-label">File</span><code>${escapeHTML(action.edit_path)}</code></div>` : "";
    const diffPreviewBlock = action.diff_preview ? `<div class="diff-preview"><span class="preview-label">Diff preview</span>${highlightDiff(action.diff_preview)}</div>` : "";
    const warningBlock = action.warning ? `<p class="fix-warning">&#9888; ${escapeHTML(action.warning)}</p>` : "";
    const countBadge = action.count > 1 ? `<span class="muted">(${action.count} findings)</span>` : "";

    return `
      <div class="action-option" data-idx="${idx}">
        <div class="action-option-header">
          <input type="radio" name="batchFixAction" value="${idx}" id="batchActionRadio${idx}">
          <label for="batchActionRadio${idx}">
            ${actionTypeBadge}
            <strong>${escapeHTML(action.label)}</strong>
            ${countBadge}
          </label>
        </div>
        ${commandBlock}
        ${editPathBlock}
        ${diffPreviewBlock}
        ${warningBlock}
      </div>`;
  }).join("");

  overlay.innerHTML = `
    <div class="modal-content modal-fix">
      <h2>Choose action for batch fix</h2>
      <p class="fix-label">${fixInfos.length} findings selected</p>
      <div class="action-options">
        ${actionItems}
      </div>
      <div class="modal-actions">
        <button class="fix-btn" id="modalFixYes" disabled>Select an action</button>
        <button class="chip" id="modalFixNo">Cancel</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);

  const radios = overlay.querySelectorAll('input[name="batchFixAction"]');
  const confirmBtn = overlay.querySelector("#modalFixYes");
  let selectedIdx = -1;

  radios.forEach((radio) => {
    radio.addEventListener("change", () => {
      selectedIdx = Number(radio.value);
      confirmBtn.disabled = false;
      confirmBtn.textContent = "Apply to all selected";
      overlay.querySelectorAll(".action-option").forEach((opt) => opt.classList.remove("selected"));
      radio.closest(".action-option").classList.add("selected");
    });
  });

  confirmBtn.onclick = () => {
    if (selectedIdx >= 0) onSelect(selectedIdx);
  };
  overlay.querySelector("#modalFixNo").onclick = closeFixModal;
}

function updateFixSelectedBtn() {
  const btn = $("fixSelectedBtn");
  if (!btn) return;
  const count = selectedBatchFindings().length;
  if (count > 0) {
    btn.textContent = `Fix selected (${count})`;
    btn.style.display = "";
  } else {
    btn.style.display = "none";
  }
}

function showToast(message, cls = "toast-success") {
  const existing = document.getElementById("toast");
  if (existing) existing.remove();

  const toast = document.createElement("div");
  toast.id = "toast";
  toast.className = `toast ${cls}`;
  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.classList.add("toast-hide");
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function showExportModal() {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.id = "exportModal";
  overlay.innerHTML = `
    <div class="modal-content modal-export">
      <h2>Export report</h2>
      <p class="muted">Download scan results or an AI-ready remediation brief generated locally.</p>
      <div class="export-options">
        <button class="export-option" id="exportJson">
          <span class="export-icon">{ }</span>
          <span class="export-label">JSON</span>
          <span class="export-desc">Full scan data</span>
        </button>
        <button class="export-option" id="exportCsv">
          <span class="export-icon">CSV</span>
          <span class="export-label">CSV</span>
          <span class="export-desc">Spreadsheet friendly</span>
        </button>
        <button class="export-option" id="exportAi">
          <span class="export-icon">AI</span>
          <span class="export-label">AI brief</span>
          <span class="export-desc">Markdown prompt with redacted evidence</span>
        </button>
      </div>
      <div class="modal-actions">
        <button class="chip" id="exportClose">Close</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);

  overlay.querySelector("#exportJson").onclick = () => {
    window.location.href = "/api/export?format=json";
    closeExportModal();
  };
  overlay.querySelector("#exportCsv").onclick = () => {
    window.location.href = "/api/export?format=csv";
    closeExportModal();
  };
  overlay.querySelector("#exportAi").onclick = () => {
    window.location.href = "/api/export?format=ai";
    closeExportModal();
  };
  overlay.querySelector("#exportClose").onclick = closeExportModal;
  // Click on overlay (outside modal) also closes — matches help modal.
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) closeExportModal();
  });
}

function closeExportModal() {
  const overlay = document.getElementById("exportModal");
  if (overlay) overlay.remove();
}

function showHelpModal() {
  closeHelpModal();
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.id = "helpModal";
  overlay.innerHTML = `
    <div class="modal-content modal-help">
      <h2>Keyboard shortcuts</h2>
      <div class="help-grid">
        <div class="help-section">
          <h3>Navigation</h3>
          <dl>
            <dt><kbd>↑</kbd> <kbd>↓</kbd></dt><dd>Move selection</dd>
            <dt><kbd>Enter</kbd></dt><dd>Open fix for selected</dd>
            <dt><kbd>Space</kbd></dt><dd>Toggle selection</dd>
            <dt><kbd>Tab</kbd></dt><dd>Switch focus</dd>
          </dl>
        </div>
        <div class="help-section">
          <h3>Filters</h3>
          <dl>
            <dt><kbd>0</kbd>–<kbd>4</kbd></dt><dd>Severity (all/critical/high/medium/low)</dd>
            <dt><kbd>s</kbd></dt><dd>Cycle source (all→trivy→lynis→compose)</dd>
            <dt><kbd>r</kbd></dt><dd>Cycle remediation</dd>
            <dt><kbd>v</kbd></dt><dd>Cycle service</dd>
            <dt><kbd>/</kbd></dt><dd>Focus search</dd>
            <dt><kbd>R</kbd></dt><dd>Clear all filters</dd>
          </dl>
        </div>
        <div class="help-section">
          <h3>Actions</h3>
          <dl>
            <dt><kbd>f</kbd></dt><dd>Fix (batch if selected, else current)</dd>
            <dt><kbd>e</kbd></dt><dd>Export report</dd>
            <dt><kbd>o</kbd></dt><dd>Cycle sort field</dd>
            <dt><kbd>O</kbd></dt><dd>Toggle sort direction</dd>
            <dt><kbd>Ctrl+A</kbd></dt><dd>Select all visible</dd>
            <dt><kbd>Ctrl+R</kbd></dt><dd>Recalculate score</dd>
            <dt><kbd>Ctrl+S</kbd></dt><dd>Rescan all tools</dd>
          </dl>
        </div>
        <div class="help-section">
          <h3>Other</h3>
          <dl>
            <dt><kbd>?</kbd></dt><dd>Show this help</dd>
            <dt><kbd>Esc</kbd></dt><dd>Close modal / blur input</dd>
            <dt><kbd>q</kbd></dt><dd>Tip: close tab to leave</dd>
          </dl>
        </div>
      </div>
      <div class="modal-actions">
        <button class="fix-btn" id="modalHelpClose">Close</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.querySelector("#modalHelpClose").onclick = closeHelpModal;
  // Click on overlay (outside modal) also closes
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) closeHelpModal();
  });
}

function closeHelpModal() {
  const overlay = document.getElementById("helpModal");
  if (overlay) overlay.remove();
}

async function loadHistory() {
  const panel = $("historyPanel");
  const list = $("historyList");
  if (!panel || !list) return;
  list.innerHTML = `<p class="muted">Loading checkpoints…</p>`;
  try {
    const resp = await fetch("/api/history");
    const data = await resp.json();
    if (!data.success) {
      list.innerHTML = `<p class="muted">${escapeHTML(data.error || "Failed to load history")}</p>`;
      return;
    }
    renderHistoryList(data.checkpoints || []);
  } catch (err) {
    list.innerHTML = `<p class="muted">${escapeHTML(err.message || "Failed to load history")}</p>`;
  }
}

function renderHistoryList(checkpoints) {
  const list = $("historyList");
  if (!list) return;
  if (!checkpoints.length) {
    list.innerHTML = `<p class="muted">No fix checkpoints yet. Apply a compose file fix to create a restore point.</p>`;
    return;
  }
  list.innerHTML = checkpoints.map((cp) => {
    const when = cp.timestamp ? new Date(cp.timestamp).toLocaleString() : "Unknown time";
    const files = cp.file_count === 1 ? "1 file" : `${cp.file_count} files`;
    return `<article class="history-item" data-id="${escapeHTML(cp.id)}">
      <div class="history-item-top">
        <strong>${escapeHTML(cp.finding_id || "unknown finding")}</strong>
        <span class="muted">${escapeHTML(when)}</span>
      </div>
      <p class="history-item-action">${escapeHTML(cp.action || "Applied fix")}</p>
      <div class="history-item-meta">
        <span class="muted">${escapeHTML(files)}</span>
        ${cp.service ? `<span class="muted">${escapeHTML(cp.service)}</span>` : ""}
        <button type="button" class="chip history-rollback-btn" data-id="${escapeHTML(cp.id)}">Rollback</button>
      </div>
    </article>`;
  }).join("");
  list.querySelectorAll(".history-rollback-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      btn.blur();
      confirmRollback(btn.dataset.id);
    });
  });
}

function toggleHistoryPanel() {
  const panel = $("historyPanel");
  if (!panel) return;
  const show = panel.hidden;
  panel.hidden = !show;
  if (show) {
    loadHistory();
  }
}

function confirmRollback(id) {
  if (!id) return;
  closeRollbackModal();
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.id = "rollbackModal";
  overlay.innerHTML = `
    <div class="modal-content">
      <h2>Rollback checkpoint</h2>
      <p>Restore files from checkpoint <code>${escapeHTML(id)}</code>? This cannot be undone automatically.</p>
      <div class="modal-actions">
        <button class="chip" id="rollbackCancel">Cancel</button>
        <button class="chip critical" id="rollbackConfirm">Rollback</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.querySelector("#rollbackCancel").onclick = closeRollbackModal;
  overlay.querySelector("#rollbackConfirm").onclick = async () => {
    const btn = overlay.querySelector("#rollbackConfirm");
    btn.disabled = true;
    btn.textContent = "Rolling back…";
    try {
      const resp = await fetch("/api/rollback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      const data = await resp.json();
      closeRollbackModal();
      if (!data.success) {
        showToast(data.error || "Rollback failed", "toast-error");
        return;
      }
      showToast(data.message || "Rollback complete", "toast-success");
      loadHistory();
    } catch (err) {
      closeRollbackModal();
      showToast(err.message || "Rollback failed", "toast-error");
    }
  };
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) closeRollbackModal();
  });
}

function closeRollbackModal() {
  const overlay = document.getElementById("rollbackModal");
  if (overlay) overlay.remove();
}

init().catch((error) => {
  document.body.innerHTML = `<main class="shell"><section class="detail"><h1>hostveil</h1><p class="muted">Failed to load scan results.</p><pre>${escapeHTML(error.message)}</pre><p><button onclick="location.reload()" style="margin-top:1rem;padding:0.5rem 1.5rem;cursor:pointer;">Retry</button></p></section></main>`;
});
