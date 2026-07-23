"use strict";

const SEV = ["critical", "high", "medium", "low"];
// Finding.source (int) -> short domain label, mirrors the score axes.
const SRC = { 1: "Container", 2: "SSH", 3: "Firewall", 4: "Updates", 5: "CVEs", 6: "Ports", 7: "Accounts", 8: "File perms", 9: "AI agents" };
const REM_AUTO = 1;
// model.ScanState (int), in declaration order.
const SCAN_DONE = 2, SCAN_SKIPPED = 3, SCAN_DEGRADED = 4, SCAN_ERROR = 5;

let report = null;
let selected = null; // {id, service} — the inspected finding (single-select)

// Filter + multi-select state.
const filters = { sev: new Set(), domain: new Set(), fixable: false };
const marked = new Set(); // keys of findings picked for a batch fix

function fkey(f) { return f.id + "|" + (f.service || ""); }

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  const ct = res.headers.get("content-type") || "";
  return ct.includes("json") ? res.json() : res.text();
}

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else if (k === "onclick") e.onclick = v;
    else if (k === "html") e.innerHTML = v;
    else e.setAttribute(k, v);
  }
  for (const kid of kids) if (kid) e.append(kid);
  return e;
}

function sevName(f) { return SEV[f.severity] || "low"; }
function sevAbbr(f) { return ["crit", "high", "med", "low"][f.severity] || "low"; }
function remLabel(r) { return ["Unclassified", "Auto-fix", "Review", "Manual", "Unavailable"][r] || "?"; }
function isFixable(f) { return f.remediation === 1 || f.remediation === 2; }
function isAuto(f) { return f.remediation === REM_AUTO; }
function active(findings) { return findings.filter((x) => !x.fixed); }

// A finding row's grid class → the severity class also used for the gutter.
function rowSevClass(f) { return ["crit", "high", "medium", "low"][f.severity] || "low"; }

// Score/axis health band → meter fill color.
function band(v) { return v >= 80 ? "b-safe" : v >= 50 ? "b-med" : v >= 25 ? "b-high" : "b-crit"; }

function meter(pct, bandClass) {
  const m = el("div", { class: "meter " + bandClass });
  m.style.setProperty("--w", Math.max(0, Math.min(100, pct)) + "%");
  return m;
}

// ── filtering ──────────────────────────────────────────────────────────
function applyFilters(items) {
  return items.filter((f) => {
    if (filters.sev.size && !filters.sev.has(f.severity)) return false;
    if (filters.domain.size && !filters.domain.has(f.source)) return false;
    if (filters.fixable && !isFixable(f)) return false;
    return true;
  });
}

function filterActive() {
  return filters.sev.size || filters.domain.size || filters.fixable;
}

function chip(label, on, onclick, sevClass) {
  return el("button", { class: "chip" + (on ? " on" : "") + (sevClass ? " " + sevClass : ""), onclick }, label);
}

function renderFilterbar(all) {
  const bar = document.getElementById("filterbar");
  const kids = [];

  // Severity chips (only those present), each with a live count.
  const sevCounts = [0, 0, 0, 0];
  all.forEach((f) => { if (f.severity >= 0 && f.severity < 4) sevCounts[f.severity]++; });
  ["crit", "high", "med", "low"].forEach((abbr, i) => {
    if (!sevCounts[i]) return;
    kids.push(chip(`${abbr.toUpperCase()} ${sevCounts[i]}`, filters.sev.has(i), () => {
      filters.sev.has(i) ? filters.sev.delete(i) : filters.sev.add(i);
      render();
    }, "c-" + abbr));
  });

  // Domain chips (only sources present in the report).
  const domains = [...new Set(all.map((f) => f.source))].filter((s) => SRC[s]).sort((a, b) => a - b);
  domains.forEach((s) => {
    kids.push(chip(SRC[s], filters.domain.has(s), () => {
      filters.domain.has(s) ? filters.domain.delete(s) : filters.domain.add(s);
      render();
    }));
  });

  // Fixable-only toggle + clear.
  kids.push(chip("Fixable", filters.fixable, () => { filters.fixable = !filters.fixable; render(); }));
  if (filterActive()) {
    kids.push(chip("Clear", false, () => {
      filters.sev.clear(); filters.domain.clear(); filters.fixable = false; render();
    }));
  }
  bar.replaceChildren(...kids);
}

// ── multi-select ───────────────────────────────────────────────────────
function checkbox(f) {
  const box = Object.assign(document.createElement("input"), { type: "checkbox", checked: marked.has(fkey(f)) });
  box.className = "pick";
  box.setAttribute("aria-label", "Select for batch fix");
  box.onclick = (e) => e.stopPropagation();
  box.onchange = () => {
    box.checked ? marked.add(fkey(f)) : marked.delete(fkey(f));
    renderBatchbar();
  };
  return box;
}

function renderBatchbar() {
  const bar = document.getElementById("batchbar");
  if (marked.size === 0) { bar.hidden = true; bar.replaceChildren(); return; }
  bar.hidden = false;
  bar.replaceChildren(
    el("button", { class: "primary", onclick: applyBatch }, `Fix selected (${marked.size})`),
    el("button", { onclick: selectAllAuto }, "Select all auto"),
    el("button", { onclick: clearMarked }, "Clear")
  );
}

function selectAllAuto() {
  applyFilters(active(report.findings)).forEach((f) => { if (isAuto(f)) marked.add(fkey(f)); });
  render();
}

function clearMarked() { marked.clear(); render(); }

async function applyBatch() {
  const findings = active(report.findings)
    .filter((f) => marked.has(fkey(f)))
    .map((f) => ({ id: f.id, service: f.service || "" }));
  if (!findings.length) return;
  try {
    const o = await api("/api/fix/batch", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ findings }),
    });
    const parts = [`Applied ${o.applied ? o.applied.length : 0}`];
    if (o.skipped && o.skipped.length) parts.push(`skipped ${o.skipped.length}`);
    if (o.failed && Object.keys(o.failed).length) parts.push(`failed ${Object.keys(o.failed).length}`);
    flash(parts.join(" · ") + `. Score ${o.new_score.overall}/100.`);
    marked.clear();
    await refresh();
  } catch (e) { flash("Batch fix failed: " + e.message, true); }
}

// Show which checkers did not fully cover their domain. Without this the
// dashboard renders a score built from a partial scan exactly like one built
// from a complete scan — the CVE axis reading a confident 100 because Trivy
// could not reach a single image is the case that motivated it.
// renderDelta summarises what moved since the previous scan. The CLI prints
// the same counts and then names the findings; here it stays one line — the
// list below already shows what is outstanding, and the question this
// answers is only "did the last round of fixes help?". Hidden when there is
// no previous scan to compare against.
function renderDelta() {
  const box = document.getElementById("delta");
  const d = report.delta || {};
  const resolved = (d.resolved || []).length;
  const added = (d.new || []).length;
  const changed = (d.changed || []).length;
  if (!resolved && !added && !changed) {
    box.hidden = true;
    box.replaceChildren();
    return;
  }
  const parts = [el("span", { class: "delta-label" }, "Since last scan")];
  if (resolved) parts.push(el("span", { class: "delta-good" }, `✓ ${resolved} resolved`));
  if (added) parts.push(el("span", { class: "delta-new" }, `+ ${added} new`));
  if (changed) parts.push(el("span", { class: "delta-chg" }, `~ ${changed} changed`));
  box.hidden = false;
  box.replaceChildren(...parts);
}

function renderDomainNotice() {
  const box = document.getElementById("domains");
  const bad = (report.domains || []).filter((d) => d.state !== SCAN_DONE);
  if (!bad.length) {
    box.hidden = true;
    box.replaceChildren();
    return;
  }
  box.hidden = false;
  box.replaceChildren(...bad.map((d) => {
    const name = SRC[d.source] || d.source;
    if (d.state === SCAN_ERROR) return el("span", { class: "dom-err" }, `! ${name} failed: ${d.reason || "unknown error"}`);
    if (d.state === SCAN_DEGRADED) return el("span", {}, `~ ${name} partial: ${d.reason || ""}`);
    if (d.state === SCAN_SKIPPED) return el("span", { class: "dom-skip" }, `· ${name} skipped: ${d.reason || ""}`);
    return el("span", { class: "dom-skip" }, `· ${name} did not run`);
  }));
}

// ── main render ────────────────────────────────────────────────────────
function render() {
  const score = report.score;

  // Exposure gauge (the signature): SECURITY meter + score.
  document.getElementById("gauge").replaceChildren(
    el("span", { class: "gauge-label" }, "Security"),
    meter(score.overall, band(score.overall)),
    el("span", { class: "gauge-score", html: `${score.overall}<small>/100</small>` })
  );

  // Per-axis bars (short labels so they never crowd the meter).
  const AX = { container: "Container", ssh: "SSH", firewall: "Firewall", updates: "Updates", cve: "CVEs", ports: "Ports", accounts: "Accounts", fileperms: "File perms", agent: "AI agents" };
  document.getElementById("axes").replaceChildren(
    ...score.axes.map((ax) =>
      el("div", { class: "axis" + (ax.applicable ? "" : " na") + (ax.degraded ? " partial" : "") },
        el("span", { class: "axis-label" }, AX[ax.id] || ax.label),
        ax.applicable ? meter(ax.score, band(ax.score)) : meter(0, "b-na"),
        // A degraded axis is scored from an incomplete picture; the "~" keeps
        // it from reading as a full clean result.
        el("span", { class: "axis-val" },
          !ax.applicable ? "N/A" : ax.degraded ? `${ax.score}~` : String(ax.score))
      )
    )
  );

  renderDelta();
  renderDomainNotice();

  // Findings list.
  const list = document.getElementById("findings");
  const all = active(report.findings);
  renderFilterbar(all);
  const items = applyFilters(all).sort((a, b) => a.severity - b.severity);
  document.getElementById("findings-title").textContent =
    filterActive() ? `Findings · ${items.length}/${all.length}` : `Findings · ${all.length}`;

  if (all.length === 0) {
    marked.clear();
    renderBatchbar();
    list.replaceChildren(el("li", { class: "clean" }, "No problems found. Clean."));
    document.getElementById("detail").replaceChildren(el("p", { class: "empty" }, "Nothing to fix."));
    return;
  }
  if (items.length === 0) {
    renderBatchbar();
    list.replaceChildren(el("li", { class: "clean muted" }, "No findings match the filter."));
    return;
  }

  const rows = new Map(); // finding key -> its <li>, so the overview can jump to one
  list.replaceChildren(
    ...items.map((f) => {
      const li = el("li", { class: "finding " + rowSevClass(f) + (isAuto(f) ? " pickable" : "") },
        isAuto(f) ? checkbox(f) : el("span", { class: "pick-spacer" }),
        el("span", { class: "sev" }, sevAbbr(f)),
        el("div", { class: "title" },
          el("div", { class: "name" }, f.title),
          el("div", { class: "rem" }, f.id + "  ·  " + remLabel(f.remediation))
        ),
        f.service ? el("span", { class: "svc" }, f.service) : ""
      );
      li.onclick = () => selectFinding(f, li);
      if (selected && selected.id === f.id && selected.service === f.service) li.classList.add("active");
      rows.set(f.id + "|" + (f.service || ""), li);
      return li;
    })
  );
  renderBatchbar();

  // Orient the user in the detail pane instead of leaving it a blank "Select
  // a finding". It stays until the first selection, and comes back on rescan.
  if (!selected) renderOverview(all, items, rows);
}

// renderOverview fills the detail pane with a read of the whole scan: the
// score in words, the severity mix, how many can be fixed unattended, and the
// most severe findings as a jump list. The empty pane was wasted on the one
// view every user sees first.
function renderOverview(all, visible, rows) {
  const counts = [0, 0, 0, 0];
  for (const f of all) counts[f.severity]++;
  const autos = all.filter(isAuto).length;
  const s = report.score.overall;
  const verdict = s >= 80 ? "in good shape" : s >= 50 ? "middling" : s >= 25 ? "exposed" : "wide open";

  const d = document.getElementById("detail");
  const box = el("div", { class: "overview" });
  box.append(el("h3", {}, `This host is ${verdict}.`));
  box.append(el("p", { class: "over-lead" },
    `${all.length} unresolved finding${all.length === 1 ? "" : "s"} across the domains that ran.`));

  // Severity chips, only for severities actually present.
  const chips = el("div", { class: "over-sev" });
  [["Critical", 0], ["High", 1], ["Medium", 2], ["Low", 3]].forEach(([name, i]) => {
    if (counts[i] > 0) chips.append(el("span", { class: "over-chip sev-" + SEV[i] }, `${counts[i]} ${name}`));
  });
  box.append(chips);

  // The one action that needs no per-finding decision.
  if (autos > 0) {
    const btn = el("button", { class: "primary over-fixall" },
      `Fix all ${autos} safe finding${autos === 1 ? "" : "s"}`);
    btn.onclick = () => document.getElementById("fixall").click();
    box.append(btn);
    box.append(el("p", { class: "over-note" },
      "Each is previewed and backed up first, and reversible from History."));
  }

  // Jump list: the most severe handful, so the worst problems are one click
  // away rather than a scroll-and-hunt.
  const top = visible.slice(0, 6);
  if (top.length) {
    box.append(el("div", { class: "over-head" }, "Most severe"));
    const ul = el("ul", { class: "over-jump" });
    for (const f of top) {
      const li = el("li", { class: "over-jump-row" },
        el("span", { class: "sev " + rowSevClass(f) }, sevAbbr(f)),
        el("span", { class: "over-jump-title" }, f.title),
        f.service ? el("span", { class: "svc" }, f.service) : ""
      );
      li.onclick = () => {
        const row = rows.get(f.id + "|" + (f.service || ""));
        if (row) { row.scrollIntoView({ block: "nearest" }); selectFinding(f, row); }
      };
      ul.append(li);
    }
    box.append(ul);
  }

  d.replaceChildren(box);
}

function selectFinding(f, li) {
  selected = { id: f.id, service: f.service };
  document.querySelectorAll(".finding").forEach((n) => n.classList.remove("active"));
  if (li) li.classList.add("active");
  const meta = [f.id, sevName(f), remLabel(f.remediation)];
  if (f.service) meta.push("service: " + f.service);
  const d = document.getElementById("detail");
  d.replaceChildren(
    el("h3", {}, f.title),
    el("div", { class: "meta" }, meta.join("  ·  ")),
    f.description ? el("p", {}, f.description) : "",
    f.how_to_fix ? el("div", { class: "howto" }, "How to fix") : "",
    f.how_to_fix ? el("p", {}, f.how_to_fix) : ""
  );
  if (isFixable(f)) {
    d.append(el("button", { class: "primary", onclick: () => preview(f) }, "Preview fix"));
  }
}

async function preview(f) {
  try {
    const p = await api(`/api/preview?id=${encodeURIComponent(f.id)}&service=${encodeURIComponent(f.service || "")}`);
    showPreview(f, p);
  } catch (e) { flash("Preview failed: " + e.message, true); }
}

function showPreview(f, p) {
  let chosen = 0;
  const box = el("div", { class: "fixbox" });
  const head = el("div", { class: "fixbox-head" });
  const body = el("div", { class: "fixbox-body" });
  box.append(head, body);
  const draw = () => {
    const a = p.actions[chosen];
    head.textContent = p.label;
    body.replaceChildren(
      p.actions.length > 1 ? altPicker(p, chosen, (i) => { chosen = i; draw(); }) : "",
      a.warning ? el("div", { class: "warn" }, "⚠  " + a.warning) : "",
      actionBody(a),
      el("div", { class: "row" },
        el("button", { class: "primary", onclick: () => applyFix(f, chosen) }, "Apply"),
        el("button", { onclick: () => selectFinding(f, document.querySelector(".finding.active")) }, "Cancel")
      )
    );
  };
  draw();
  document.getElementById("detail").append(box);
}

function altPicker(p, chosen, onpick) {
  return el("div", { class: "alts" },
    ...p.actions.map((a, i) => {
      const input = Object.assign(document.createElement("input"),
        { type: "radio", name: "alt", checked: i === chosen });
      input.onchange = () => onpick(i);
      return el("label", {}, input, " " + a.label);
    })
  );
}

// An unrecognised action type must never render as an empty box beside a
// live Apply button — that reads as "this fix changes nothing".
function actionBody(a) {
  if (a.type === "edit" || a.type === "mode") return diffPre(a.diff);
  if (a.type === "exec") return cmdList(a.commands);
  return el("pre", { class: "diff" }, `(no preview available for action type ${a.type})`);
}

function diffPre(diff) {
  const pre = el("pre", { class: "diff" });
  (diff || "").split("\n").forEach((line) => {
    let cls = "ctx";
    if (line.startsWith("+") && !line.startsWith("+++")) cls = "add";
    else if (line.startsWith("-") && !line.startsWith("---")) cls = "del";
    pre.append(el("span", { class: cls }, line + "\n"));
  });
  return pre;
}

function cmdList(cmds) {
  const pre = el("pre", { class: "diff" });
  (cmds || []).forEach((c) => pre.append(el("span", { class: "ctx" }, "$ " + c.join(" ") + "\n")));
  return pre;
}

async function applyFix(f, action) {
  try {
    const o = await api("/api/fix", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: f.id, service: f.service || "", action }),
    });
    flash(`Fix applied. Score ${o.new_score.overall}/100.` +
      (o.checkpoint_id ? `  Rollback: ${o.checkpoint_id}` : ""));
    await refresh();
  } catch (e) { flash("Fix failed: " + e.message, true); }
}

// ── history + rollback ─────────────────────────────────────────────────
// Every applied fix leaves a checkpoint; this panel is how the web UI
// makes them reversible, so a fix applied here can be undone here rather
// than only from the CLI.
async function showHistory() {
  let cps;
  try {
    cps = await api("/api/history");
  } catch (e) { flash("Could not load history: " + e.message, true); return; }

  selected = null;
  document.querySelectorAll(".finding").forEach((n) => n.classList.remove("active"));
  const d = document.getElementById("detail");
  d.replaceChildren(
    el("h3", {}, "Applied fixes"),
    el("div", { class: "meta" }, `${cps.length} checkpoint${cps.length === 1 ? "" : "s"}  ·  newest first`)
  );
  if (!cps.length) {
    d.append(el("p", { class: "empty" }, "No fixes have been applied yet."));
    return;
  }
  cps.forEach((cp) => d.append(checkpointBox(cp)));
}

function checkpointBox(cp) {
  const when = new Date(cp.created_at).toLocaleString();
  const body = el("div", { class: "fixbox-body" });

  if (cp.reversible) {
    if (cp.diff) body.append(diffPre(cp.diff));
    if (cp.restart_service) {
      body.append(el("div", { class: "warn" },
        `⚠  Rolling back may require restarting '${cp.restart_service}'.`));
    }
    body.append(el("div", { class: "row" },
      el("button", { onclick: () => rollback(cp) }, "Roll back")));
  } else {
    // Exec fixes back up no files, so there is nothing to restore. Show
    // what ran instead of a button that would lead nowhere.
    if (cp.commands) body.append(cmdList(cp.commands));
    body.append(el("p", { class: "empty" },
      "This fix ran a command rather than editing a file, so there is nothing to restore automatically. Undo it by hand if you need to."));
  }

  return el("div", { class: "fixbox" },
    el("div", { class: "fixbox-head" }, `${when}  ·  ${cp.finding_id}  ·  ${cp.label}`),
    body);
}

async function rollback(cp) {
  if (!confirm(`Roll back "${cp.label}"?\n\nThis restores the original file as it was before the fix was applied.`)) return;
  try {
    const o = await api("/api/rollback", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ checkpoint_id: cp.id }),
    });
    const n = o.restored_files ? o.restored_files.length : 0;
    flash(`Rolled back. Restored ${n} file${n === 1 ? "" : "s"}. Score ${o.new_score.overall}/100.` +
      (o.restart_service ? `  You may need to restart '${o.restart_service}'.` : ""));
    await refresh();
    await showHistory();
  } catch (e) { flash("Rollback failed: " + e.message, true); }
}

async function refresh() { report = await api("/api/result"); render(); }

function flash(msg, isErr) {
  const s = document.getElementById("status");
  s.textContent = msg;
  s.className = "status" + (isErr ? " err" : "");
  s.hidden = false;
  clearTimeout(flash._t);
  flash._t = setTimeout(() => (s.hidden = true), 6000);
}

// ── theme picker ───────────────────────────────────────────────────────
// The list and the applier come from /theme.js, generated by
// internal/ui/theme, which has already restored the saved choice before this
// script runs. All that is left is the control itself.
function initThemePicker() {
  const sel = document.getElementById("theme");
  const themes = window.HOSTVEIL_THEMES || [];
  if (!sel || !themes.length) return;

  const current = document.documentElement.getAttribute("data-theme") ||
    window.HOSTVEIL_THEME_DEFAULT || themes[0].id;
  sel.replaceChildren(...themes.map((t) => {
    const o = el("option", { value: t.id }, t.name);
    if (t.id === current) o.selected = true;
    return o;
  }));
  sel.onchange = () => {
    document.documentElement.setAttribute("data-theme", sel.value);
    // Per browser, not per host: the server's theme stays whatever hostveil
    // was started with, so two people reading the same dashboard can each
    // have their own.
    try { localStorage.setItem("hostveil.theme", sel.value); } catch (e) { /* private mode */ }
  };
}

initThemePicker();

document.getElementById("history").onclick = showHistory;

document.getElementById("rescan").onclick = async () => {
  flash("Rescanning…");
  marked.clear();
  report = await api("/api/rescan", { method: "POST", headers: { "Content-Type": "application/json" } });
  render();
  flash("Rescan complete.");
};

document.getElementById("fixall").onclick = async () => {
  if (!confirm("Apply every safe (Auto) fix now?")) return;
  try {
    const o = await api("/api/fix/all", { method: "POST", headers: { "Content-Type": "application/json" } });
    flash(`Applied ${o.applied ? o.applied.length : 0} fixes. Score ${o.new_score.overall}/100.`);
    marked.clear();
    await refresh();
  } catch (e) { flash("Batch fix failed: " + e.message, true); }
};

refresh().catch((e) => flash("Failed to load: " + e.message, true));
