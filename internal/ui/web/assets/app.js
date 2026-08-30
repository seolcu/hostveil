"use strict";

// Drop the access token out of the address bar.
//
// It arrives in the URL because that is the one channel a terminal can hand
// to a browser, and the server converts it into a SameSite=Strict session
// cookie on the very first request. Past that point the copy in the query
// string is residue: every fetch below authenticates with the cookie and not
// one of them carries ?t=. Residue is not free — it sits in the address bar,
// in the history entry, in a bookmark made without thinking, and in every
// screenshot of the dashboard anyone pastes into an issue. `Referrer-Policy:
// no-referrer` already stops it leaving over the network; this is the rest.
//
// Reloading the stripped URL works for as long as the session cookie lives.
// Past that the server answers 401 with the sentence telling the operator to
// reopen the URL hostveil printed, and `serve` is still printing it in the
// terminal that is still running.
(function stripToken() {
  if (!location.search) return;
  const q = new URLSearchParams(location.search);
  if (!q.has("t")) return;
  q.delete("t");
  const rest = q.toString();
  history.replaceState(null, "", location.pathname + (rest ? "?" + rest : "") + location.hash);
})();

// The model's vocabulary, served by /model.js and generated from
// internal/model. /api/result carries these as bare integers, so the page
// cannot say anything about a finding without a table to look them up in.
//
// Every one of these used to be written out here by hand. Two of them
// drifted: the domain labels fell a release behind and took the sysctl
// filter chip with them, and a second axis-label copy fell two behind and
// started substituting long scoring labels into a narrow column. Read
// everything through the accessors below, never the tables directly, so a
// value the engine knows and the page does not still renders as something
// rather than as undefined.
const M = window.HOSTVEIL_MODEL || {};
const SRC = M.domains || {};
const SEV = M.severities || {};
const REM = M.remediations || {};
const SCAN = M.scanStates || {};
const BANDS = M.bands || [];

function srcLabel(s) { return (SRC[s] && SRC[s].label) || String(s); }

// Enum values arrive as names now, not ordinals, so anything that needs the
// model's ordering asks for it. rank is the row's position in the table the
// engine declared; sorting by the name itself would put "low" before
// "medium" and domains in alphabetical order, which is not an ordering
// anyone chose.
function rank(table, key) { return (table[key] && table[key].rank) ?? 1e9; }
function byRank(table) { return (a, b) => rank(table, a) - rank(table, b); }

// ── layout (temporary; see internal/ui/web/layout.go) ───────────────────
// Which of the six arrangements is on. /layout.js has already put it on
// <html> before first paint, so this is a read, never a decision.
function layout() {
  return document.documentElement.getAttribute("data-layout") ||
    window.HOSTVEIL_LAYOUT_DEFAULT || "split";
}
function layoutIs(...ids) { return ids.includes(layout()); }

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

// sevName doubles as the CSS class for a finding's gutter and its severity
// chip (.finding.high, .over-chip.sev-high), so the stylesheet and the
// exports share one spelling. There used to be two tables here that
// differed only in whether Medium was "med" or "medium", and only the
// second one matched the stylesheet.
function sevName(f) { return (SEV[f.severity] && SEV[f.severity].name) || "unknown"; }

// topSeverity is the most urgent level the engine declared — rank 0 in the
// table it exported, whatever that level is called this release.
//
// Asking for it by name is what this used to do, against a name the model
// had stopped using: the verdict headline counted findings whose severity
// was "critical" long after the four-level scale was gone, so the count was
// always zero and the headline it gates silently never appeared again. A
// hard-coded enum name in a renderer is a bug with a delayed fuse; the
// export carries rank precisely so nothing here has to spell a level.
function topSeverity() {
  for (const [key, sev] of Object.entries(SEV)) if (sev.rank === 0) return key;
  return null;
}
function sevAbbr(f) { return (SEV[f.severity] && SEV[f.severity].abbr) || "?"; }
function remLabel(r) { return (REM[r] && REM[r].label) || "Unclassified"; }
function isFixable(f) { return !!(REM[f.remediation] && REM[f.remediation].fixable); }
// isAuto asks whether "fix all safe" would apply this row now, so a pending
// row answers false: its fix has been applied and what is left is the
// restart. Marking one would put it in a batch that reported it back as
// skipped, the word that also means "there is no fix for this".
function isAuto(f) { return !f.fixed && !!(REM[f.remediation] && REM[f.remediation].auto); }
// A pending finding is still active: the file is written and the host has not
// changed, so the score still charges it and the row has to stay on the page
// to account for the number. This is the copy of model.Finding.Active that
// cannot call into Go, so it is the copy that has to be read.
function active(findings) { return findings.filter((x) => !x.fixed || x.pending); }
function isPending(f) { return !!f.pending; }

// A domain that did not cover all of its ground. Degraded counts: it ran,
// and it is scored, but it cannot vouch for what it did not look at.
function scanComplete(state) { return !!(SCAN[state] && SCAN[state].complete); }

// Score/axis health band. BANDS is ordered best-first with an inclusive
// floor each, so the first row the score clears is its band — the same walk
// model.BandFor does. The thresholds were written out four times before
// this, and the CLI's copy had one fewer arm than the rest.
function bandFor(v) { return BANDS.find((b) => v >= b.min) || { cls: "b-na", verdict: "unscored" }; }
// afterFixesNote decides whether the headroom is worth a cell, and returns
// zero or one of them so a caller can spread it into a child list.
//
// Two refusals, and every interface makes the same two: nothing beside an N/A
// axis, because a number there is a claim about a domain nobody looked at;
// and nothing when the figure equals the score, because an arrow pointing at
// where it already is says the fixes are worth nothing. On a well-kept host
// that is most rows, and the column has to stay quiet on them or it becomes
// decoration.
function afterFixesNote(applicable, score, after, render) {
  if (applicable === false || typeof after !== "number" || after <= score) return [];
  return [render(after)];
}

// The axis's score as every interface writes it. model.ScoreAxis.ValueText is
// the same three arms in Go; this is the one copy that cannot call it, and
// internal/docs/afterfixes_test.go holds the two together by reading this
// file.
//
// The "~" is the load-bearing part: a degraded axis is scored from an
// incomplete picture, and an unmarked score on one says a domain vouches for
// ground it never looked at.
function axisValueText(ax) {
  if (!ax.applicable) return "N/A";
  return ax.degraded ? `${ax.score}~` : String(ax.score);
}

function band(v) { return bandFor(v).cls; }

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

  // Severity chips (only those present), each with a live count. Ordered
  // by the model's table, so the chips run most-severe-first for the same
  // reason the findings do, rather than because a literal here says so.
  const sevCounts = {};
  all.forEach((f) => { if (SEV[f.severity]) sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1; });
  for (const [key, sev] of Object.entries(SEV)) {
    const n = sevCounts[key] || 0;
    if (!n) continue;
    kids.push(chip(`${sev.abbr.toUpperCase()} ${n}`, filters.sev.has(key), () => {
      filters.sev.has(key) ? filters.sev.delete(key) : filters.sev.add(key);
      render();
    }, "c-" + sev.abbr));
  }

  // Domain chips (every source present in the report — filtering this list
  // by the label table is what hid the sysctl domain when the table was a
  // hand-written copy).
  const domains = [...new Set(all.map((f) => f.source))].sort(byRank(SRC));
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
    // The engine's own sentence. Written here by hand it counted applied,
    // skipped and failed but never mentioned o.interrupted, so a batch cut
    // short read exactly like one that ran to completion — which is the one
    // thing that flag exists to prevent.
    flash(o.message);
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

// incompleteDomains is the model's Report.IncompleteDomains, and it gates
// two things: this notice, and whether the findings list may call the host
// clean. Both must ask the same question or the page contradicts itself.
function incompleteDomains() {
  return (report.domains || []).filter((d) => !scanComplete(d.state));
}

function renderDomainNotice() {
  const box = document.getElementById("domains");
  const bad = incompleteDomains();
  if (!bad.length) {
    box.hidden = true;
    box.replaceChildren();
    return;
  }
  box.hidden = false;
  box.replaceChildren(...bad.map((d) => {
    const name = srcLabel(d.source);
    const state = (SCAN[d.state] && SCAN[d.state].name) || "";
    if (state === "error") return el("span", { class: "dom-err" }, `! ${name} failed: ${d.reason || "unknown error"}`);
    if (state === "degraded") return el("span", {}, `~ ${name} partial: ${d.reason || ""}`);
    if (state === "skipped") return el("span", { class: "dom-skip" }, `· ${name} skipped: ${d.reason || ""}`);
    return el("span", { class: "dom-skip" }, `· ${name} did not run`);
  }));
}

// ── verdict band (temporary layouts B, G) ──────────────────────────────
// The same reading the overview panel gives, said as a sentence with the one
// action that answers it beside. It is built on every render whatever the
// layout, so switching the picker never leaves a stale band behind — CSS
// decides whether it is on screen.
function renderVerdict(all) {
  const box = document.getElementById("verdict");
  const autos = all.filter(isAuto).length;
  const top = topSeverity();
  const crit = top === null ? 0 : all.filter((f) => f.severity === top).length;
  const scored = (report.score.axes || []).filter((a) => a.applicable).length;
  const gaps = incompleteDomains().length;

  // The headline is a claim the scan can defend. With nothing scannable
  // there is no claim to make, which is the same reason the gauge refuses a
  // number: "nothing reachable" and "nobody looked" are opposite readings.
  const head = report.score.applicable === false
    ? "This host could not be scanned."
    : crit > 0
      ? `${crit} finding${crit === 1 ? " is" : "s are"} reachable right now.`
      : `This host is ${bandFor(report.score.overall).verdict}.`;

  const acts = el("div", { class: "v-acts" });
  if (autos > 0) {
    const fix = el("button", { class: "primary" },
      `Fix ${autos} safe finding${autos === 1 ? "" : "s"}`);
    fix.onclick = () => document.getElementById("fixall").click();
    acts.append(fix, el("span", { class: "v-note" },
      "Each is previewed and backed up first, and reversible from History."));
  } else {
    acts.append(el("span", { class: "v-note" }, "Nothing here can be fixed unattended."));
  }

  box.replaceChildren(
    el("h2", {}, head),
    el("p", {}, `${all.length} unresolved · ${scored} of ${(report.score.axes || []).length} ` +
      `domains scored${gaps ? ` · ${gaps} could not be fully checked` : ""}`),
    acts
  );
}

// ── domain rail (temporary layouts C, G) ───────────────────────────────
// Every axis as a row: score, bar, severity mix, and for a domain that did
// not run, the reason instead of a number. It doubles as the domain filter,
// which is the point — the rail is the only place in these layouts where a
// skipped domain is both visible and clickable.
function renderRail(all) {
  const rail = document.getElementById("rail");
  const byDomain = {};
  for (const f of all) (byDomain[f.source] = byDomain[f.source] || []).push(f);

  const rows = (report.score.axes || []).map((ax) => {
    const dom = (report.domains || []).find((d) => d.source === ax.source) || {};
    const state = (SCAN[dom.state] && SCAN[dom.state].name) || "done";
    const on = filters.domain.has(ax.source);
    const row = el("button", {
      class: "dom" + (ax.applicable ? "" : " na") + (ax.degraded ? " partial" : "") + (on ? " on" : ""),
    });
    row.append(
      el("span", { class: "n" }, srcLabel(ax.source)),
      el("span", { class: "s" }, axisValueText(ax)),
      ax.applicable ? meter(ax.score, band(ax.score)) : meter(0, "b-na"),
      ...afterFixesNote(ax.applicable, ax.score, ax.after_fixes,
                        (n) => el("span", { class: "after" }, `\u2192${n}`))
    );

    if (!ax.applicable) {
      row.append(el("span", { class: "c" }, `${state} — ${dom.reason || "did not run"}`));
    } else {
      const mix = el("span", { class: "c" });
      const counts = {};
      for (const f of byDomain[ax.source] || []) counts[f.severity] = (counts[f.severity] || 0) + 1;
      const parts = [];
      for (const [i, sev] of Object.entries(SEV)) {
        if (counts[i]) parts.push(el("span", { class: sev.name }, `${counts[i]} ${sev.abbr}`));
      }
      if (!parts.length) parts.push(el("span", {}, "clean"));
      parts.forEach((pnode, i) => { if (i) mix.append(" · "); mix.append(pnode); });
      row.append(mix);
    }

    // Selecting a domain here is the same filter the chips set, so the two
    // controls cannot disagree about what the list is showing.
    row.onclick = () => {
      if (filters.domain.has(ax.source)) filters.domain.delete(ax.source);
      else { filters.domain.clear(); filters.domain.add(ax.source); }
      render();
    };
    return row;
  });

  rail.replaceChildren(el("div", { class: "rail-head" }, `Domains · ${all.length} findings`), ...rows);
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
         el("span", { class: "gauge-score", html: `${score.overall}<small>/100</small>` }),
         ...afterFixesNote(score.applicable, score.overall, score.after_fixes,
                           (n) => el("span", { class: "gauge-after" }, `${n} after fixes`))])
  );

  // Per-axis bars. The short domain label, not the axis label: the column
  // is 72px with an ellipsis, and "Container exposure" does not fit where
  // "Container" does. This was a hand-written table of short labels keyed
  // by axis ID, nine rows for eleven domains, so the two domains added
  // after it was written fell through to the long label and rendered
  // truncated. The axis already carries its source; ask the domain table.
  document.getElementById("axes").replaceChildren(
    ...(score.axes || []).map((ax) =>
      el("div", { class: "axis" + (ax.applicable ? "" : " na") + (ax.degraded ? " partial" : "") },
        el("span", { class: "axis-label" }, srcLabel(ax.source)),
        ax.applicable ? meter(ax.score, band(ax.score)) : meter(0, "b-na"),
        // A degraded axis is scored from an incomplete picture; the "~" keeps
        // it from reading as a full clean result.
        el("span", { class: "axis-val" }, axisValueText(ax)),
        ...afterFixesNote(ax.applicable, ax.score, ax.after_fixes,
                          (n) => el("span", { class: "axis-after" }, `\u2192${n}`))
      )
    )
  );

  renderDelta();
  renderTrend();
  renderDomainNotice();

  // Findings list.
  const list = document.getElementById("findings");
  // The inline arrangement parks the one detail node *inside* this list, under
  // the row that opened it (see selectFinding). Rebuilding the list with it
  // still in there deletes it — and every later getElementById("detail")
  // returns null, so History, Preview and opening any finding all threw
  // "Cannot read properties of null" until the page was reloaded. One node,
  // three placements: whoever rebuilds the list puts it back first.
  const det = document.getElementById("detail");
  if (det && list.contains(det)) {
    document.querySelector("main").insertBefore(det, document.getElementById("scrim"));
  }
  const all = active(report.findings);
  // Both are built whatever the layout, and before the early returns below:
  // a clean host and a filtered-to-nothing list still need a correct verdict
  // and a correct rail, and building them only on the happy path is how a
  // layout switch would show the previous host's numbers.
  renderVerdict(all);
  renderRail(all);
  renderFilterbar(all);
  const items = applyFilters(all).sort((a, b) => rank(SEV, a.severity) - rank(SEV, b.severity));
  document.getElementById("findings-title").textContent =
    filterActive() ? `Findings · ${items.length}/${all.length}` : `Findings · ${all.length}`;

  if (all.length === 0) {
    marked.clear();
    renderBatchbar();
    // "Clean" is a claim about the whole host, so it may only be made when
    // the whole host was actually examined. Finding nothing and being
    // unable to look score the same and mean opposite things — and this
    // page said "Clean." either way, so a host whose every checker had
    // failed was reported spotless right above the notice saying so.
    const missing = incompleteDomains().length;
    list.replaceChildren(missing > 0
      ? el("li", { class: "clean muted" },
        `No problems found in the domains that ran — but ${missing} did not complete.`)
      : el("li", { class: "clean" }, "No problems found. Clean."));
    document.getElementById("detail").replaceChildren(el("p", { class: "empty" }, "Nothing to fix."));
    return;
  }
  if (items.length === 0) {
    renderBatchbar();
    list.replaceChildren(el("li", { class: "clean muted" }, "No findings match the filter."));
    return;
  }

  const rows = new Map(); // finding key -> its <li>, so the overview can jump to one
  const row = (f) => {
    const li = el("li", { class: "finding " + sevName(f) + (isAuto(f) ? " pickable" : "") + (isPending(f) ? " pending" : "") },
      isAuto(f) ? checkbox(f) : el("span", { class: "pick-spacer" }),
      el("span", { class: "sev" }, sevAbbr(f)),
      el("div", { class: "title" },
        el("div", { class: "name" }, f.title),
        el("div", { class: "rem" }, f.id + "  ·  " +
          (isPending(f) ? "Applied — not in force yet" : remLabel(f.remediation)))
      ),
      f.service ? el("span", { class: "svc" }, f.service) : ""
    );
    li.onclick = () => selectFinding(f, li);
    if (selected && selected.id === f.id && selected.service === f.service) li.classList.add("active");
    rows.set(fkey(f), li);
    return li;
  };

  list.replaceChildren(...(layoutIs("lanes") ? laneRows(items, row) : items.map(row)));
  renderBatchbar();
  // The inline layout parks the detail node in the list, and replaceChildren
  // above has just thrown that placement away. Put the open finding back.
  if (layoutIs("inline") && selected) {
    const back = rows.get(selected.id + "|" + (selected.service || ""));
    if (back) back.after(document.getElementById("detail"));
  }
  document.body.classList.toggle("detail-open", !!selected);

  // Orient the user in the detail pane instead of leaving it a blank "Select
  // a finding". It stays until the first selection, and comes back on rescan.
  if (!selected) renderOverview(all, items, rows);
}

// laneRows groups the list into one section per severity, each with its own
// count and its own batch action.
//
// The lane header is an <li> rather than a <div> because it lives inside the
// findings <ul> — a <div> there is invalid, and a browser is free to hoist it
// out of the list, which is exactly the kind of thing that looks fine until
// it does not.
//
// A severity with nothing at it gets no lane. A "High · 0" header is a
// row of screen spent announcing that nothing happened, and four of them on
// a clean host is the whole list.
function laneRows(items, row) {
  const out = [];
  for (const [i, sev] of Object.entries(SEV)) {
    const group = items.filter((f) => String(f.severity) === String(i));
    if (!group.length) continue;
    const autos = group.filter(isAuto);
    const acts = el("span", { class: "a" });
    if (autos.length) {
      // "Select", not "Fix". This button hands the lane's Auto findings to
      // the batch bar and stops there — it does not apply anything — and a
      // button that says Fix and then appears to do nothing is the worst
      // reading of that. It is also what the terminal's `m` does and says,
      // and the same key in the same arrangement has to mean the same thing.
      const btn = el("button", { class: "primary" }, `Select the ${autos.length} safe`);
      // The batch bar already knows how to preview, apply and report a batch.
      // A second path to the same POST is a second place for it to go wrong.
      btn.onclick = (ev) => {
        ev.stopPropagation();
        marked.clear();
        for (const f of autos) marked.add(fkey(f));
        render();
      };
      acts.append(btn);
    } else {
      acts.append(el("em", {}, "none fix themselves"));
    }
    out.push(el("li", { class: "lane-head " + sev.name },
      el("span", { class: "n" }, sev.name),
      el("span", { class: "c" }, String(group.length)),
      acts));
    out.push(...group.map(row));
  }
  return out;
}

// renderOverview fills the detail pane with a read of the whole scan: the
// score in words, the severity mix, how many can be fixed unattended, and the
// most severe findings as a jump list. The empty pane was wasted on the one
// view every user sees first.
function renderOverview(all, visible, rows) {
  const counts = {};
  for (const f of all) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const autos = all.filter(isAuto).length;

  const d = document.getElementById("detail");
  const box = el("div", { class: "overview" });
  // The verdict reads the same band table the meter does, so the wording
  // and the colour cannot disagree. With no applicable score there is no
  // band and no verdict to give: an unscannable host is not a bad host,
  // and "wide open" is the number-shaped version of the lie the gauge's
  // N/A already refuses to tell.
  box.append(el("h3", {}, report.score.applicable === false
    ? "This host could not be scanned."
    : `This host is ${bandFor(report.score.overall).verdict}.`));
  box.append(el("p", { class: "over-lead" },
    `${all.length} unresolved finding${all.length === 1 ? "" : "s"} across the domains that ran.`));

  // Severity chips, only for severities actually present. Ordered by the
  // model's table, which is most-severe-first.
  const chips = el("div", { class: "over-sev" });
  for (const [i, sev] of Object.entries(SEV)) {
    const n = counts[i] || 0;
    if (n > 0) chips.append(el("span", { class: "over-chip sev-" + sev.name },
      `${n} ${sev.name.charAt(0).toUpperCase() + sev.name.slice(1)}`));
  }
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
        el("span", { class: "sev " + sevName(f) }, sevAbbr(f)),
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
  // Three placements, one node: the pane keeps it where it is, the overlay
  // layouts lift it in CSS, and the inline layout moves it into the list
  // under the row that opened it. Moving beats cloning — a second detail
  // node would be a second thing for the preview and the AI box to be
  // appended to, and only one of them would be the one on screen.
  if (layoutIs("inline") && li) li.after(d);
  else if (d.parentElement !== document.querySelector("main")) {
    document.querySelector("main").insertBefore(d, document.getElementById("scrim"));
  }
  document.body.classList.add("detail-open");
  d.replaceChildren(
    el("h3", {}, f.title),
    el("div", { class: "meta" }, meta.join("  ·  ")),
    f.description ? el("p", {}, f.description) : "",
    f.how_to_fix ? el("div", { class: "howto" }, "How to fix") : "",
    f.how_to_fix ? el("p", {}, f.how_to_fix) : "",
    // Under the instructions, not above them. A reader with no Preview fix
    // button still needs the how-to first; this answers the question they
    // ask second, and it is absent entirely on anything fixable.
    f.why_no_fix ? el("div", { class: "howto" }, "Why there is no fix button") : "",
    f.why_no_fix ? el("p", { class: "whynofix" }, f.why_no_fix) : ""
  );
  if (isFixable(f)) {
    d.append(el("button", { class: "primary", onclick: () => preview(f) }, "Preview fix"));
  }
  d.append(el("button", { onclick: (ev) => explainAI(f, ev.target) }, "Explain with AI"));
  // The overlay and inline layouts need a way out that is not "pick another
  // finding": an overlay covers the list it was opened from, and an inline
  // panel has pushed the next finding off the bottom. The pane layouts have
  // neither problem, so CSS hides it there.
  const close = el("button", { class: "detail-close" }, "Close");
  close.onclick = closeDetail;
  d.append(close);
}

// closeDetail returns to the unselected state: the overview comes back in
// the pane layouts, the overlay lifts, and the inline panel goes back to
// <main> where it is out of the flow.
function closeDetail() {
  selected = null;
  render();
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
      a.benefit ? el("div", { class: "benefit" }, "✓  " + a.benefit) : "",
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
    // verify_message is rendered by the engine, not composed here: the
    // difference between "re-checked and gone" and "applied but not yet in
    // force" is subtle enough that three interfaces phrasing it themselves
    // would make three different claims.
    flash(`Fix applied. Score ${o.new_score.overall}/100.` +
      (o.restart_hint ? `  Restart '${o.restart_hint}' for it to take effect.` : "") +
      (o.verify_message ? `  ${o.verify_message}` : "") +
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
// ── layout picker (temporary) ──────────────────────────────────────────
// Same shape as the theme picker, and for the same reason: /layout.js has
// already applied the saved choice before first paint, so all that is left
// is the control. This one exists to settle which arrangement hostveil
// keeps; when that is decided it goes, along with five of the six.
function initLayoutPicker() {
  const sel = document.getElementById("layout");
  const list = window.HOSTVEIL_LAYOUTS || [];
  if (!sel || !list.length) return;

  const current = layout();
  sel.replaceChildren(...list.map((l) => {
    const o = el("option", { value: l.id, title: l.note }, l.name);
    if (l.id === current) o.selected = true;
    return o;
  }));
  sel.onchange = () => {
    document.documentElement.setAttribute("data-layout", sel.value);
    try { localStorage.setItem("hostveil.layout", sel.value); } catch (e) { /* private mode */ }
    // A re-render, not just a repaint: two of the six restructure the list
    // and move the detail node, and a CSS-only switch would leave the DOM
    // arranged for the layout you just left.
    if (report) render();
    const l = list.find((x) => x.id === sel.value);
    if (l) flash(l.name + " — " + l.note);
  };
}

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
initLayoutPicker();

document.getElementById("scrim").onclick = closeDetail;
// Escape is what people press at an overlay before they look for a button.
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && selected && layoutIs("triage", "railverdict")) closeDetail();
});

document.getElementById("history").onclick = showHistory;

// Export downloads /api/export as a file rather than navigating to it: the
// route can answer 409 (no scan yet) or 400 (bad format), and a plain <a
// href> navigation on an error response would replace this whole page with
// a blank error document instead of leaving flash() to say what happened.
const exportBtn = document.getElementById("export");
exportBtn.onclick = () => whileBusy(exportBtn, "Exporting…", async () => {
  const format = document.getElementById("export-format").value;
  const res = await fetch("/api/export?format=" + encodeURIComponent(format));
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  const blob = await res.blob();
  const cd = res.headers.get("content-disposition") || "";
  const name = /filename="([^"]+)"/.exec(cd)?.[1] || ("hostveil-report." + format);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
});

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
  await watchScan("Rescanning");
  flash("Rescan complete.");
});

// pollRescan resolves when the running scan finishes, updating the status
// line with the per-domain picture roughly once a second. verb is what the
// status line calls the scan in progress — "Rescanning" from the button
// above, "Scanning" from boot() below, where there may be no prior result
// to justify the "re-".
async function pollRescan(verb) {
  for (;;) {
    const st = await api("/api/rescan/status");
    if (!st.running) return;
    const working = (st.domains || []).filter((d) => d.state === "running").map((d) => d.source);
    const done = (st.domains || []).filter((d) => d.state !== "running" && d.state !== "pending").length;
    flash(verb + "… " + (working.length ? "checking " + working.join(", ") : done + " domain(s) finished"));
    await new Promise((r) => setTimeout(r, 1000));
  }
}

// watchScan waits out a running scan and then reloads everything it moved —
// the result and the trend line, the one place besides load that refetches
// either. It is the sequence the rescan button and boot()'s first load both
// need, pulled out so the two could not drift the way one inline copy of it
// already had before this existed.
async function watchScan(verb) {
  await pollRescan(verb);
  report = await api("/api/result");
  render();
  await refreshTrend();
}

const fixallBtn = document.getElementById("fixall");
fixallBtn.onclick = () => {
  if (!confirm("Apply every safe (Auto) fix now?")) return;
  whileBusy(fixallBtn, "Applying…", async () => {
    const o = await api("/api/fix/all", { method: "POST", headers: { "Content-Type": "application/json" } });
    // Same route's outcome as the batch button above, so the same sentence.
    // This one used to report only the applied count and the interruption,
    // so a fix that errored was invisible: the score moved, nothing said
    // why, and the failure was in the response all along.
    flash(o.message);
    marked.clear();
    await refresh();
  });
};

// boot loads the page for the first time. hostveil's own first scan is now
// asynchronous (ListenAndServe opens the listener before it finishes), so
// the very first page load can land while it is still running — the same
// state a rescan puts the page in, and answered the same way: disable the
// buttons that would race it, narrate it, then load the result it produced.
//
// The status check and the result both fire at once rather than one after
// the other. The ordinary case — a page opened long after the only scan
// there has ever been — needs both regardless, so making the second wait on
// the first would only have added a network round trip to every load for a
// question the running flag alone can't answer. Fetched early and running
// is false, rep is already the answer; running and it is a stale read of
// whatever the last scan left behind, thrown away in favour of the fresh
// one watchScan fetches once the running scan finishes.
async function boot() {
  const [st, rep] = await Promise.all([api("/api/rescan/status"), api("/api/result")]);
  if (!st.running) {
    report = rep;
    render();
    await refreshTrend();
    return;
  }
  rescanBtn.disabled = true;
  fixallBtn.disabled = true;
  try {
    await watchScan("Scanning");
  } finally {
    rescanBtn.disabled = false;
    fixallBtn.disabled = false;
  }
}

boot().catch((e) => flash("Failed to load: " + e.message, true));
