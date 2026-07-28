"use strict";

const SEV = ["critical", "high", "medium", "low"];
// Finding.source (int) -> {id, label}, served by /domains.js and generated
// from model.AllSources. This used to be an object literal written out by
// hand here; it fell a domain behind the engine and took the sysctl filter
// chip with it. Read it through srcLabel, never directly, so a source the
// table somehow lacks still renders as a name.
const SRC = window.HOSTVEIL_DOMAINS || {};
function srcLabel(s) { return (SRC[s] && SRC[s].label) || String(s); }
const REM_AUTO = 1;
// model.ScanState (int), in declaration order.
const SCAN_DONE = 2, SCAN_SKIPPED = 3, SCAN_DEGRADED = 4, SCAN_ERROR = 5;

let report = null;
// trend is fetched separately from the report: the report is refetched
// after every fix, and the trend only moves when a scan does.
let trend = null;
let selected = null; // {id, service} — the inspected finding (single-select)

// Filter + multi-select state.
const filters = { sev: new Set(), domain: new Set(), fixable: false };
const marked = new Set(); // keys of findings picked for a batch fix

function fkey(f) { return f.id + "|" + (f.service || ""); }

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    // The status matters on one route: a declined rollback answers 409,
    // and a decline is a question for the operator rather than a failure
    // to report. Carrying it on the error is what lets the caller tell
    // them apart — without it the dashboard turned every decline into
    // "Rollback failed" and offered nothing further, while the server had
    // supported force all along.
    const err = new Error((await res.text()) || res.statusText);
    err.status = res.status;
    throw err;
  }
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

  // Domain chips (every source present in the report — filtering this list
  // by the label table is what hid the sysctl domain when the table was a
  // hand-written copy).
  const domains = [...new Set(all.map((f) => f.source))].sort((a, b) => a - b);
  domains.forEach((s) => {
    kids.push(chip(srcLabel(s), filters.domain.has(s), () => {
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

// renderTrend draws the score of every retained scan beside the delta.
//
// The glyphs come from the server, rendered by model.Sparkline — the same
// function the TUI draws from. Bucketing scores into blocks again here
// would be a second implementation of one rule, which is the shape that
// already cost this file its domain table.
//
// Nothing is drawn for a single scan: a sparkline of one point is a shape
// with no information in it, and a first run should not be handed a chart
// implying a history it does not have.
function renderTrend() {
  const box = document.getElementById("trend");
  const pts = (trend && trend.points) || [];
  if (pts.length < 2) { box.hidden = true; box.replaceChildren(); return; }

  const score = (p) => (p.applicable ? String(p.overall) : "N/A");
  const last = pts[pts.length - 1];
  const spark = el("span", { class: "spark " + (last.applicable ? band(last.overall) : "b-na") },
    trend.sparkline);
  spark.title = pts.map((p) => new Date(p.at).toLocaleString() + "  " + score(p)).join("\n");

  box.hidden = false;
  box.replaceChildren(
    el("span", { class: "delta-label" }, "Score over " + pts.length + " scans"),
    el("span", { class: "spark-end" }, score(pts[0])),
    spark,
    el("span", { class: "spark-end" }, score(last)));
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
    const name = srcLabel(d.source);
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
  //
  // When no domain ran there is nothing to average, so the number would be
  // arbitrary — and an empty meter next to a digit reads as "terrible host"
  // rather than "nothing was examined", which are opposite messages.
  document.getElementById("gauge").replaceChildren(
    el("span", { class: "gauge-label" }, "Security"),
    ...(score.applicable === false
      ? [el("span", { class: "gauge-na" }, "N/A — nothing could be scanned")]
      : [meter(score.overall, band(score.overall)),
         el("span", { class: "gauge-score", html: `${score.overall}<small>/100</small>` })])
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
  renderTrend();
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
  d.append(el("button", { onclick: (ev) => explainAI(f, ev.target) }, "Explain with AI"));
}

// explainAI asks the server for the advisory AI explanation. It degrades in
// place: with no Ollama reachable the server answers with ai_error, which
// renders as a note rather than an error state — AI is optional everywhere.
async function explainAI(f, btn) {
  const d = document.getElementById("detail");
  const old = d.querySelector(".aibox");
  if (old) old.remove();
  const box = el("div", { class: "aibox" }, el("div", { class: "meta" }, "Asking the local AI model…"));
  d.append(box);
  if (btn) btn.disabled = true;
  try {
    const ex = await api(`/api/explain?id=${encodeURIComponent(f.id)}&service=${encodeURIComponent(f.service || "")}`);
    box.replaceChildren(
      el("div", { class: "howto" }, "AI explanation (advisory)"),
      ex.ai ? el("p", {}, ex.ai) : el("p", { class: "meta" }, ex.ai_error || "The AI provider returned nothing.")
    );
  } catch (e) {
    box.replaceChildren(el("p", { class: "meta" }, "AI explanation failed: " + e.message));
  } finally {
    if (btn) btn.disabled = false;
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
    // The restart hint is not decoration. An edit fix writes the file and
    // nothing reloads the service, so until the operator restarts it the
    // score has improved for a change that is not yet in effect. The CLI has
    // always said so; the dashboard used to show only the new number.
    flash(`Fix applied. Score ${o.new_score.overall}/100.` +
      (o.restart_hint ? `  Restart '${o.restart_hint}' for it to take effect.` : "") +
      (o.checkpoint_id ? `  Rollback: ${o.checkpoint_id}` : ""));
    await refresh();
  } catch (e) { flash("Fix failed: " + e.message, true); }
}

// ── history + rollback ─────────────────────────────────────────────────
// Every applied fix leaves a checkpoint; this panel is how the web UI
// makes them reversible, so a fix applied here can be undone here rather
// than only from the CLI.
async function showHistory() {
  let res;
  try {
    res = await api("/api/history");
  } catch (e) { flash("Could not load history: " + e.message, true); return; }

  const cps = res.checkpoints || [];
  selected = null;
  document.querySelectorAll(".finding").forEach((n) => n.classList.remove("active"));
  const d = document.getElementById("detail");
  d.replaceChildren(
    el("h3", {}, "Applied fixes"),
    el("div", { class: "meta" }, `${cps.length} checkpoint${cps.length === 1 ? "" : "s"}  ·  newest first`)
  );
  // Some checkpoints on disk could not be read. The list below is still
  // usable; what is missing from it cannot be rolled back at all, which is
  // exactly the thing an operator must not discover only when they try.
  if (res.warning) {
    d.append(el("div", { class: "warn" }, `⚠  ${res.warning}`));
  }
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

async function rollback(cp, force = false) {
  if (!force && !confirm(`Roll back "${cp.label}"?\n\nThis restores the original file as it was before the fix was applied.`)) return;
  try {
    const o = await api("/api/rollback", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ checkpoint_id: cp.id, force }),
    });
    const n = o.restored_files ? o.restored_files.length : 0;
    flash(`Rolled back. Restored ${n} file${n === 1 ? "" : "s"}. Score ${o.new_score.overall}/100.` +
      (o.restart_service ? `  You may need to restart '${o.restart_service}'.` : ""));
    await refresh();
    await showHistory();
  } catch (e) {
    // 409 is the engine declining, not failing: the file changed after
    // hostveil wrote it, so restoring the backup would discard whatever
    // was done in between. Rollback keeps no checkpoint of its own, so
    // say that plainly and make the override a second, informed answer.
    if (e.status === 409) {
      if (confirm(`${e.message}\n\nOverwrite it anyway?\n\nThis restores hostveil's backup over the current file, discarding those changes. Rollback writes no checkpoint of its own, so this cannot be undone.`)) {
        await rollback(cp, true);
      }
      return;
    }
    flash("Rollback failed: " + e.message, true);
  }
}

async function refresh() { report = await api("/api/result"); render(); }

// refreshTrend is called on load and after a rescan, never after a fix — a
// fix changes the live score, not the series of saved scans.
async function refreshTrend() {
  try {
    trend = await api("/api/trend");
  } catch (e) {
    trend = null; // a trend that cannot be read costs the trend line, nothing else
  }
  if (report) renderTrend();
}

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

// whileBusy disables a button for the duration of the work it starts, and
// reports a failure instead of leaving one unhandled.
//
// Both of these routes take minutes on a real host and the engine serialises
// them behind one mutex, so a second click does not run anything sooner — it
// queues another multi-minute request behind the first and holds a
// connection open for it. And a rejected promise with no catch left the user
// on "Rescanning…" forever with the reason only in the browser console.
async function whileBusy(el, label, fn) {
  if (el.disabled) return;
  const original = el.textContent;
  el.disabled = true;
  el.textContent = label;
  try {
    await fn();
  } catch (e) {
    flash(original + " failed: " + e.message, true);
  } finally {
    el.disabled = false;
    el.textContent = original;
  }
}

// A rescan is started, not awaited: the server answers 202 immediately and
// the scan runs in the background, so the page polls the status route and
// narrates which domains are still working instead of freezing a button
// for minutes. A 409 means a scan is already running — poll that one.
const rescanBtn = document.getElementById("rescan");
rescanBtn.onclick = () => whileBusy(rescanBtn, "Rescanning…", async () => {
  flash("Rescanning…");
  marked.clear();
  const res = await fetch("/api/rescan", { method: "POST", headers: { "Content-Type": "application/json" } });
  if (!res.ok && res.status !== 409) throw new Error((await res.text()) || res.statusText);
  await pollRescan();
  report = await api("/api/result");
  render();
  // A scan is the one thing that moves the series, so this is the one place
  // besides load that refetches it.
  await refreshTrend();
  flash("Rescan complete.");
});

// pollRescan resolves when the running scan finishes, updating the status
// line with the per-domain picture roughly once a second.
async function pollRescan() {
  for (;;) {
    const st = await api("/api/rescan/status");
    if (!st.running) return;
    const working = (st.domains || []).filter((d) => d.state === "running").map((d) => d.source);
    const done = (st.domains || []).filter((d) => d.state !== "running" && d.state !== "pending").length;
    flash("Rescanning… " + (working.length ? "checking " + working.join(", ") : done + " domain(s) finished"));
    await new Promise((r) => setTimeout(r, 1000));
  }
}

const fixallBtn = document.getElementById("fixall");
fixallBtn.onclick = () => {
  if (!confirm("Apply every safe (Auto) fix now?")) return;
  whileBusy(fixallBtn, "Applying…", async () => {
    const o = await api("/api/fix/all", { method: "POST", headers: { "Content-Type": "application/json" } });
    flash(`Applied ${o.applied ? o.applied.length : 0} fixes. Score ${o.new_score.overall}/100.`
      + (o.interrupted ? "  Interrupted — the rest were never attempted." : ""));
    marked.clear();
    await refresh();
  });
};

refresh().then(refreshTrend).catch((e) => flash("Failed to load: " + e.message, true));
