"use strict";

const SEV = ["critical", "high", "medium", "low"];
// Finding.source (int) -> short domain label, mirrors the score axes.
const SRC = { 1: "Container", 2: "SSH", 3: "Firewall", 4: "Updates", 5: "CVEs", 6: "Ports", 7: "Accounts", 8: "File perms" };
const REM_AUTO = 1;

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
  const AX = { container: "Container", ssh: "SSH", firewall: "Firewall", updates: "Updates", cve: "CVEs", ports: "Ports", accounts: "Accounts", fileperms: "File perms" };
  document.getElementById("axes").replaceChildren(
    ...score.axes.map((ax) =>
      el("div", { class: "axis" + (ax.applicable ? "" : " na") },
        el("span", { class: "axis-label" }, AX[ax.id] || ax.label),
        ax.applicable ? meter(ax.score, band(ax.score)) : meter(0, "b-na"),
        el("span", { class: "axis-val" }, ax.applicable ? String(ax.score) : "N/A")
      )
    )
  );

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
      return li;
    })
  );
  renderBatchbar();
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
      a.type === "edit" ? diffPre(a.diff) : cmdList(a.commands),
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

async function refresh() { report = await api("/api/result"); render(); }

function flash(msg, isErr) {
  const s = document.getElementById("status");
  s.textContent = msg;
  s.className = "status" + (isErr ? " err" : "");
  s.hidden = false;
  clearTimeout(flash._t);
  flash._t = setTimeout(() => (s.hidden = true), 6000);
}

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
