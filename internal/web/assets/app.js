const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
const toolLabels = { trivy: "Trivy", lynis: "Lynis", update: "Update" };
const statusIcons = ["○", "◌", "✓", "−", "✗"];

const state = {
  live: null,
  phase: "loading",
  selected: 0,
  query: "",
  severity: "all",
  source: "all",
  remediation: "all",
  sortBy: "severity",
  pollTimer: null,
};

const $ = (id) => document.getElementById(id);

async function fetchResult() {
  try {
    const response = await fetch("/api/result");
    state.live = await response.json();
    state.phase = state.live.phase || "complete";
    render();
  } catch (error) {
    // Keep polling
  }
}

async function init() {
  await fetchResult();
  if (state.phase === "loading") {
    state.pollTimer = setInterval(fetchResult, 2000);
  }
  bindControls();
}

function bindControls() {
  $("query")?.addEventListener("input", (event) => {
    state.query = event.target.value.toLowerCase();
    state.selected = 0;
    render();
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
}

function render() {
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
  renderTable(visible);
  renderDetail(visible[state.selected]);
}

function renderLoading() {
  const tools = state.live.tools || {};
  document.querySelector(".shell").className = "shell loading";
  $("score").textContent = "--/100";
  $("score").className = "";
  const toolOrder = ["update", "trivy", "lynis"];
  const toolRows = toolOrder
    .filter((name) => tools[name])
    .map((name) => {
      const t = tools[name];
      const icon = statusIcons[t.status] || "○";
      const iconClass = ["", "running", "done", "muted", "error"][t.status] || "";
      return `<div class="tool-row"><span class="tool-icon ${iconClass}">${icon}</span><span class="tool-name">${toolLabels[name] || name}</span><span class="tool-msg">${escapeHTML(t.message || "")}</span></div>`;
    })
    .join("");
  $("metrics").innerHTML = "";
  $("findings").innerHTML = "";
  $("detail").innerHTML = `
    <div class="loading-state">
      <h2>Scanning...</h2>
      <div class="tool-status">${toolRows}</div>
      <p class="muted" style="margin-top:20px">Results appear automatically when scans complete.</p>
    </div>`;
  $("findingCount").textContent = "Scanning...";
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
  if (state.sortBy === "source") return source(a).localeCompare(source(b)) || severityOrder[severity(a)] - severityOrder[severity(b)];
  if (state.sortBy === "title") return title(a).localeCompare(title(b));
  if (state.sortBy === "remediation") return remediation(a).localeCompare(remediation(b));
  return severityOrder[severity(a)] - severityOrder[severity(b)] || title(a).localeCompare(title(b));
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
  $("findings").innerHTML = visible.map((f, index) => {
    const fixedClass = f.Fixed ? "fixed" : "";
    const selClass = index === state.selected ? "selected" : "";
    const rowClass = [fixedClass, selClass].filter(Boolean).join(" ");
    const sevDisplay = f.Fixed ? "&#10003;" : `<span class="badge ${severity(f)}">${severity(f)}</span>`;
    const srcDisplay = f.Fixed ? "" : `<span class="muted">${source(f)}</span>`;
    const fixDisplay = f.Fixed ? "Fixed" : label(remediation(f));
    const titleDisplay = f.Fixed ? `<span style="opacity:0.5;text-decoration:line-through">${escapeHTML(title(f))}</span>` : escapeHTML(title(f));
    return `<tr class="${rowClass}" data-index="${index}">
      <td>${sevDisplay}</td>
      <td>${srcDisplay}</td>
      <td class="id">${shortId(f.ID)}</td>
      <td class="title">${titleDisplay}</td>
      <td class="muted">${fixDisplay}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="5" class="muted">No findings match the current filters.</td></tr>`;
  $("findings").querySelectorAll("tr[data-index]").forEach((row) => {
    row.addEventListener("click", () => {
      state.selected = Number(row.dataset.index);
      render();
    });
  });
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

  // Step 1: Get fix info (warning, actions)
  try {
    const infoResp = await fetch("/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding, action_index: 0, info_only: true }),
    });
    const info = await infoResp.json();
    if (!info.success) {
      resultDiv.innerHTML = `<div class="fix-error">✗ ${escapeHTML(info.error || "Fix info unavailable")}</div>`;
      return;
    }

    if (info.warning) {
      showFixModal(info.label, info.warning, () => {
        closeFixModal();
        doApplyFix(finding, button);
      });
      return;
    }
  } catch (error) {
    resultDiv.innerHTML = `<div class="fix-error">✗ ${escapeHTML(error.message)}</div>`;
    return;
  }

  doApplyFix(finding, button);
}

async function doApplyFix(finding, button) {
  const resultDiv = $("fixResult");
  button.disabled = true;
  button.textContent = "Applying...";
  try {
    const response = await fetch("/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding, action_index: 0 }),
    });
    const result = await response.json();
    if (result.success) {
      resultDiv.innerHTML = `<div class="fix-success">&#10003; ${escapeHTML(result.label || "Fixed")}</div>`;
      finding.Fixed = true;
      render();
    } else {
      resultDiv.innerHTML = `<div class="fix-error">&#10007; ${escapeHTML(result.error || "Fix failed")}</div>`;
    }
    if (result.diff) {
      resultDiv.innerHTML += `<pre class="fix-diff">${escapeHTML(result.diff)}</pre>`;
    }
  } catch (error) {
    resultDiv.innerHTML = `<div class="fix-error">&#10007; ${escapeHTML(error.message)}</div>`;
  }
  button.disabled = false;
  button.textContent = "Fix";
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

function showFixModal(label, warning, onConfirm) {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.id = "fixModal";
  overlay.innerHTML = `
    <div class="modal-content">
      <h2>Apply fix</h2>
      <p><strong>${escapeHTML(label)}</strong></p>
      <p class="fix-warning">&#9888; ${escapeHTML(warning)}</p>
      <div class="modal-actions">
        <button class="fix-btn" id="modalFixYes">Apply</button>
        <button class="chip" id="modalFixNo">Cancel</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.querySelector("#modalFixYes").onclick = onConfirm;
  overlay.querySelector("#modalFixNo").onclick = closeFixModal;
}

function closeFixModal() {
  const overlay = document.getElementById("fixModal");
  if (overlay) overlay.remove();
}

init().catch((error) => {
  document.body.innerHTML = `<main class="shell"><section class="detail"><h1>hostveil</h1><p class="muted">Failed to load scan results.</p><pre>${escapeHTML(error.message)}</pre></section></main>`;
});
