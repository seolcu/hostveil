const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
const toolLabels = { trivy: "Trivy", lynis: "Lynis", update: "Update" };
const statusIcons = ["○", "◌", "✓", "−", "✗", "◪"];

const state = {
  live: null,
  phase: "loading",
  selected: 0,
  query: "",
  severity: "all",
  source: "all",
  remediation: "all",
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
    fetchFailures = 0;
    render();
  } catch (error) {
    fetchFailures++;
    if (fetchFailures >= 5) {
      showToast("Connection lost — retrying...", "toast-error");
      fetchFailures = 0;
    }
  }
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
    state.query = "";
    state.severity = "all";
    state.source = "all";
    state.remediation = "all";
    state.selected = 0;
    if ($("query")) $("query").value = "";
    render();
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
      visible.forEach((f) => state.selectedSet.add(f.ID));
    } else {
      visible.forEach((f) => state.selectedSet.delete(f.ID));
    }
    render();
  });

  const rescanBtn = document.createElement("button");
  rescanBtn.id = "rescanBtn";
  rescanBtn.type = "button";
  rescanBtn.textContent = "Re-scan";
  document.querySelector(".panel-head").appendChild(rescanBtn);
  rescanBtn.addEventListener("click", async () => {
    rescanBtn.disabled = true;
    rescanBtn.textContent = "Scanning...";
    try {
      await fetch("/api/rescan", { method: "POST" });
      state.pollTimer = setInterval(fetchResult, 2000);
    } catch (e) {
      console.error("Rescan failed");
    }
    rescanBtn.disabled = false;
    rescanBtn.textContent = "Re-scan";
  });

  const exportBtn = document.createElement("button");
  exportBtn.id = "exportBtn";
  exportBtn.type = "button";
  exportBtn.textContent = "Export";
  document.querySelector(".panel-head").appendChild(exportBtn);
  exportBtn.addEventListener("click", () => {
    showExportModal();
  });

  const fixSelectedBtn = document.createElement("button");
  fixSelectedBtn.id = "fixSelectedBtn";
  fixSelectedBtn.type = "button";
  fixSelectedBtn.className = "fix-selected-btn";
  document.querySelector(".panel-head").appendChild(fixSelectedBtn);
  fixSelectedBtn.addEventListener("click", () => {
    applyFixBatch();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeFixModal();
      closeExportModal();
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      const visible = findings();
      if (visible.length > 0) {
        state.selected = Math.min(state.selected + 1, visible.length - 1);
        render();
        scrollSelectedIntoView();
      }
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      state.selected = Math.max(state.selected - 1, 0);
      render();
      scrollSelectedIntoView();
    }
    if (e.key === "Enter") {
      const fixModal = document.getElementById("fixModal");
      const exportModal = document.getElementById("exportModal");
      if (fixModal) {
        const yesBtn = fixModal.querySelector("#modalFixYes");
        if (yesBtn && !yesBtn.disabled) yesBtn.click();
      } else if (exportModal) {
        // do nothing — export requires explicit choice
      } else {
        const fixBtn = $("detail")?.querySelector(".fix-btn");
        if (fixBtn) fixBtn.click();
      }
    }
    if (e.key === " " || e.key === "Spacebar") {
      if (isTypingTarget(e.target)) return;
      const fixModal = document.getElementById("fixModal");
      const exportModal = document.getElementById("exportModal");
      if (fixModal || exportModal) return;
      const visible = findings();
      const finding = visible[state.selected];
      if (!finding) return;
      e.preventDefault();
      toggleFindingSelection(finding.ID);
      render();
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
  const visible = findings();
  if (state.selected >= visible.length) state.selected = Math.max(0, visible.length - 1);
  renderMetrics();
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

function renderLoading() {
  const tools = state.live.tools || {};
  document.querySelector(".shell").className = "shell loading";
  $("score").textContent = "--/100";
  $("score").className = "";
  const toolOrder = ["update", "trivy", "lynis"];
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

function findings() {
  const items = [...(state.live?.findings || [])];
  const query = state.query;
  return items
    .filter((f) => state.severity === "all" || severity(f) === state.severity)
    .filter((f) => state.source === "all" || source(f) === state.source)
    .filter((f) => state.remediation === "all" || remediation(f) === state.remediation)
    .filter((f) => !query || searchable(f).includes(query))
    .sort(sorter);
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
  $("score").textContent = `${score}/100`;
  $("score").className = severityClassForScore(score);
  const counts = countBy(items, severity);
  const fixable = items.filter((f) => ["auto", "review"].includes(remediation(f))).length;
  const metrics = [
    ["Total", items.length],
    ["Critical", counts.critical || 0, "critical"],
    ["High", counts.high || 0, "high"],
    ["Medium", counts.medium || 0, "medium"],
    ["Low", counts.low || 0, "low"],
    ["Fixable", fixable],
  ];
  $("metrics").innerHTML = metrics.map(([label, value, cls = ""]) => `<article class="metric"><span>${label}</span><strong class="${cls}">${value}</strong></article>`).join("");
}

function renderFilters() {
  const items = state.live?.findings || [];
  renderChips("severityFilters", ["all", "critical", "high", "medium", "low"], "severity");
  renderChips("sourceFilters", ["all", ...Object.keys(countBy(items, source)).sort()], "source");
  renderChips("remediationFilters", ["all", ...Object.keys(countBy(items, remediation)).sort()], "remediation");
}

function renderChips(id, values, key) {
  if (!$(id)) return;
  $(id).innerHTML = values.map((value) => `<button class="chip ${state[key] === value ? "active" : ""}" data-key="${key}" data-value="${value}" type="button">${label(value)}</button>`).join("");
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
  const allSelected = visible.length > 0 && visible.every((f) => state.selectedSet.has(f.ID));
  const someSelected = visible.some((f) => state.selectedSet.has(f.ID));
  const checkState = allSelected ? "checked" : someSelected ? "indeterminate" : "";

  $("findings").innerHTML = visible.map((f, index) => {
    const fixedClass = f.Fixed ? "fixed" : "";
    const selClass = index === state.selected ? "selected" : "";
    const rowSelectedClass = state.selectedSet.has(f.ID) ? "row-selected" : "";
    const rowClass = [fixedClass, selClass, rowSelectedClass].filter(Boolean).join(" ");
    const sevDisplay = f.Fixed ? "&#10003;" : `<span class="badge ${severity(f)}">${severity(f)}</span>`;
    const srcDisplay = f.Fixed ? "" : `<span class="muted">${source(f)}</span>`;
    const fixDisplay = f.Fixed ? "Fixed" : label(remediation(f));
    const titleDisplay = f.Fixed ? `<span style="opacity:0.5;text-decoration:line-through">${escapeHTML(title(f))}</span>` : escapeHTML(title(f));
    const checked = state.selectedSet.has(f.ID) ? "checked" : "";
    return `<tr class="${rowClass}" data-index="${index}" data-id="${escapeHTML(f.ID)}">
      <td class="check-cell"><input type="checkbox" ${checked} data-id="${escapeHTML(f.ID)}" class="row-check"></td>
      <td>${sevDisplay}</td>
      <td>${srcDisplay}</td>
      <td class="id">${shortId(f.ID)}</td>
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
      state.selected = Number(row.dataset.index);
      render();
    });
    row.addEventListener("dblclick", (e) => {
      if (e.target.classList.contains("row-check")) return;
      state.selected = Number(row.dataset.index);
      const finding = visible[state.selected];
      if (!finding) return;
      toggleFindingSelection(finding.ID);
      render();
    });
  });
  $("findings").querySelectorAll(".row-check").forEach((cb) => {
    cb.addEventListener("click", (e) => {
      e.stopPropagation();
      setFindingSelection(cb.dataset.id, cb.checked);
      render();
    });
  });
}

function isTypingTarget(target) {
  if (!target) return false;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || tag === "BUTTON" || target.isContentEditable;
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

function renderDetail(f) {
  if (!f) {
    $("detail").innerHTML = `<div class="empty-detail"><span></span><h2>Select a finding</h2><p>Choose an item from the table to inspect evidence and remediation guidance.</p></div>`;
    return;
  }
  const evidence = f.Evidence || {};
  const evKeys = Object.keys(evidence).sort();
  const evidenceHTML = evKeys.length > 0 ? `
    <details class="evidence-details">
      <summary>Evidence (${evKeys.length})</summary>
      ${evKeys.map((key) => `<pre><strong>${escapeHTML(key)}</strong>\n${escapeHTML(evidence[key])}</pre>`).join("")}
    </details>` : "";
  const metadata = f.Metadata || {};
  const metaKeys = Object.keys(metadata).sort();
  const metadataHTML = metaKeys.length > 0 ? `
    <details class="evidence-details">
      <summary>Metadata (${metaKeys.length})</summary>
      ${metaKeys.map((key) => `<pre><strong>${escapeHTML(key)}</strong>\n${escapeHTML(metadata[key])}</pre>`).join("")}
    </details>` : "";
  const fixable = f.Remediation === 0 || f.Remediation === 1;
  $("detail").innerHTML = `
    <span class="badge ${severity(f)}">${severity(f)}</span>
    <h2>${escapeHTML(title(f))}</h2>
    ${fixable ? `<button class="fix-btn" data-finding-id="${escapeHTML(f.ID)}">Fix</button>` : ""}
    <dl class="detail-meta">
      <dt>ID</dt><dd>${escapeHTML(f.ID || "")}</dd>
      <dt>Source</dt><dd>${source(f)}</dd>
      <dt>Remediation</dt><dd>${label(remediation(f))}</dd>
      ${f.Service ? `<dt>Service</dt><dd>${escapeHTML(f.Service)}</dd>` : ""}
    </dl>
    ${section("Description", f.Description)}
    ${section("How to fix", f.HowToFix, true)}
    ${evidenceHTML}
    ${metadataHTML}
    <div id="fixResult"></div>
  `;
  const detail = $("detail");
  detail.querySelectorAll(".toggle-more").forEach((btn) => {
    btn.onclick = () => {
      const body = btn.parentElement.querySelector(".collapse-body");
      if (btn.textContent === "View more") {
        body.innerHTML = `<p>${body.dataset.full}</p>`;
        btn.textContent = "View less";
      } else {
        body.innerHTML = `<p>${body.dataset.truncated}</p>`;
        btn.textContent = "View more";
      }
    };
  });
  detail.querySelectorAll(".copy").forEach((btn) => {
    btn.onclick = () => navigator.clipboard?.writeText(f.HowToFix || "");
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
      finding.Fixed = true;
      const successHtml = `<div class="fix-success">&#10003; ${escapeHTML(result.label || "Fixed")}</div>`;
      const diffHtml = result.diff ? highlightDiff(result.diff) : "";
      render();
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
function severity(f) { return ["critical", "high", "medium", "low"][f.Severity] || String(f.Severity || "unknown").toLowerCase(); }
function source(f) { return ["trivy", "lynis"][f.Source] || String(f.Source || "unknown").toLowerCase(); }
function remediation(f) { return ["auto", "review", "unavailable", "manual"][f.Remediation] || String(f.Remediation || "unknown").toLowerCase(); }
function title(f) { return f.Title || "Untitled finding"; }
function shortId(id = "") { const parts = id.split("."); return parts[parts.length - 1] || id; }
function searchable(f) { return [f.ID, f.Title, f.Description, f.HowToFix, f.Service, severity(f), source(f), remediation(f), ...Object.values(f.Evidence || {})].join(" ").toLowerCase(); }
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
}

function showFixActionModal(label, actions, onSelect) {
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
  overlay.querySelector("#modalFixNo").onclick = closeFixModal;
}

function closeFixModal() {
  const overlay = document.getElementById("fixModal");
  if (overlay) overlay.remove();
}

async function applyFixBatch() {
  const selectedIds = new Set(state.selectedSet);
  if (selectedIds.size === 0) return;

  const visible = findings();
  const selectedFindings = visible.filter((f) => selectedIds.has(f.ID));
  if (selectedFindings.length === 0) return;

  // Fetch fix info for all selected findings to check action counts
  const fixInfos = [];
  for (const f of selectedFindings) {
    try {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding: f, action_index: 0, info_only: true }),
      });
      const info = await resp.json();
      fixInfos.push({ finding: f, info });
    } catch (e) {
      fixInfos.push({ finding: f, info: { success: false, error: e.message } });
    }
  }

  // Check if any fix has multiple actions
  const hasMultiAction = fixInfos.some((fi) => fi.info.success && (fi.info.actions || []).length > 1);
  const allHaveFix = fixInfos.every((fi) => fi.info.success);

  if (!allHaveFix) {
    const failed = fixInfos.filter((fi) => !fi.info.success).map((fi) => fi.finding.ID);
    showToast(`No fix available for: ${failed.join(", ")}`, "toast-error");
    return;
  }

  if (hasMultiAction) {
    showBatchActionModal(fixInfos, (actionIdx) => {
      closeFixModal();
      doApplyFixBatch(selectedFindings, actionIdx);
    });
  } else {
    doApplyFixBatch(selectedFindings, 0);
  }
}

async function doApplyFixBatch(selectedFindings, actionIdx) {
  const fixSelectedBtn = $("fixSelectedBtn");
  if (fixSelectedBtn) {
    fixSelectedBtn.disabled = true;
    fixSelectedBtn.classList.add("loading");
    fixSelectedBtn.textContent = "Applying...";
  }

  try {
    const response = await fetch("/api/fix/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ findings: selectedFindings, action_index: actionIdx }),
    });
    const result = await response.json();

    if (result.results) {
      for (const r of result.results) {
        if (r.success) {
          const f = state.live?.findings?.find((f) => f.ID === r.id);
          if (f) f.Fixed = true;
        }
      }
    }

    const alsoFixedCount = result.also_fixed?.length || 0;
    const successCount = result.results?.filter((r) => r.success).length || 0;
    const failCount = result.results?.filter((r) => !r.success).length || 0;

    let msg = `Fixed ${successCount} finding${successCount !== 1 ? "s" : ""}`;
    if (failCount > 0) msg += ` (${failCount} failed)`;
    if (alsoFixedCount > 0) msg += ` — also resolved ${alsoFixedCount} related`;

    showToast(msg, alsoFixedCount > 0 ? "toast-info" : "toast-success");

    state.selectedSet.clear();
    render();
  } catch (error) {
    showToast("Batch fix failed: " + error.message, "toast-error");
  }

  if (fixSelectedBtn) {
    fixSelectedBtn.disabled = false;
    fixSelectedBtn.classList.remove("loading");
    updateFixSelectedBtn();
  }
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
  const count = state.selectedSet.size;
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
      <p class="muted">Download scan results in your preferred format.</p>
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
  overlay.querySelector("#exportClose").onclick = closeExportModal;
}

function closeExportModal() {
  const overlay = document.getElementById("exportModal");
  if (overlay) overlay.remove();
}

init().catch((error) => {
  document.body.innerHTML = `<main class="shell"><section class="detail"><h1>hostveil</h1><p class="muted">Failed to load scan results.</p><pre>${escapeHTML(error.message)}</pre><p><button onclick="location.reload()" style="margin-top:1rem;padding:0.5rem 1.5rem;cursor:pointer;">Retry</button></p></section></main>`;
});
