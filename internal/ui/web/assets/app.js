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

// Filter + multi-select + sort state.
const filters = { sev: new Set(), domain: new Set(), fixable: false };
const marked = new Set(); // keys of findings picked for a batch fix
let sortBy = "severity"; // "severity" | "domain" | "remediation" — see #sort

// Comparators for the findings list. Each reads the same rank() the model's
// own tables carry, so "Domain" and "Remediation" sort in the order the
// engine declared them in, not alphabetically or by whichever order the
// scan happened to enumerate them.
const sortComparators = {
  severity: (a, b) => rank(SEV, a.severity) - rank(SEV, b.severity),
  domain: (a, b) => rank(SRC, a.source) - rank(SRC, b.source),
  remediation: (a, b) => rank(REM, a.remediation) - rank(REM, b.remediation),
};

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

function applyBatch() {
  const findings = active(report.findings)
    .filter((f) => marked.has(fkey(f)))
    .map((f) => ({ id: f.id, service: f.service || "", title: f.title }));
  return applyMany(findings, "Fixing");
}

// applyMany drives a per-item progress modal over `findings`, calling
// /api/fix/one once per finding in sequence rather than the batch routes'
// one-shot /api/fix/all or /api/fix/batch. That endpoint is Engine.ApplyOne
// — the batch loop's own eligibility rule and no-verify semantics exposed
// per item, not a loop over the single-fix endpoint, which would re-run
// each finding's domain checker (expensive for compose and cve) once per
// item instead of zero times. See internal/core.ApplyOne's doc comment.
async function applyMany(findings, verb) {
  if (!findings.length) return;
  const body = el("div", {}, el("p", {}, `${verb} 1 of ${findings.length}…`));
  openModal(el("div", {}, el("h3", {}, verb + "…"), body), { blocking: true });

  let applied = 0, skipped = 0, failed = 0;
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    body.replaceChildren(el("p", {}, `${verb} ${i + 1} of ${findings.length}: ${f.title || f.id}`));
    try {
      const o = await api("/api/fix/one", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: f.id, service: f.service || "" }),
      });
      o.skipped ? skipped++ : applied++;
    } catch (e) {
      failed++;
    }
  }

  document.getElementById("modal").removeAttribute("data-busy");
  const done = el("button", { class: "primary" }, "Done");
  done.onclick = closeModal;
  body.replaceChildren(
    el("p", {}, `Applied ${applied} · skipped ${skipped} · failed ${failed}.`),
    el("div", { class: "row" }, done)
  );
  marked.clear();
  await refresh();
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
  // lanes always groups by severity regardless of sortBy (see laneRows) — a
  // domain/remediation sort applies within each lane, not instead of it.
  const items = applyFilters(all).sort(sortComparators[sortBy] || sortComparators.severity);
  document.getElementById("findings-title-text").textContent =
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
        el("div", { class: "rem rem-" + f.remediation }, f.id + "  ·  " +
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
    // Under the instructions, not above them: this answers the question a
    // reader asks second, and it is absent entirely on anything fixable.
    f.why_no_fix ? el("div", { class: "howto" }, "Why there is no fix button") : "",
    f.why_no_fix ? el("p", { class: "whynofix" }, f.why_no_fix) : ""
  );
  // Shown immediately rather than behind a "Preview fix" click: there is
  // nothing to decide before seeing it, and gating it behind a button meant
  // a second click re-appended a second copy underneath the first, since
  // nothing ever removed the one already there.
  if (isFixable(f)) {
    const box = el("div", { class: "fixbox" },
      el("div", { class: "fixbox-head" }, "Fix preview"),
      el("div", { class: "fixbox-body" }, el("p", { class: "meta" }, "Loading fix preview…")));
    d.append(box);
    loadPreview(f, box);
  }
  // A row, not two bare buttons appended straight to #detail: without a
  // wrapper neither had any margin of its own, so whichever came right
  // before (a paragraph, or the fixbox) butted straight up against
  // "Explain with AI" with no breathing room at all.
  const explainBtn = el("button", { onclick: (ev) => explainAI(f, ev.target) }, "Explain with AI");
  // The overlay and inline layouts need a way out that is not "pick another
  // finding": an overlay covers the list it was opened from, and an inline
  // panel has pushed the next finding off the bottom. The pane layouts have
  // neither problem, so CSS hides it there.
  const close = el("button", { class: "detail-close" }, "Close");
  close.onclick = closeDetail;
  d.append(el("div", { class: "detail-actions" }, explainBtn, close));
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

// loadPreview fetches a finding's fix preview into a box selectFinding has
// already appended to #detail, replacing its "Loading…" placeholder either
// way — with the diff, or with why it could not be fetched.
async function loadPreview(f, box) {
  try {
    const p = await api(`/api/preview?id=${encodeURIComponent(f.id)}&service=${encodeURIComponent(f.service || "")}`);
    drawPreviewInto(box, f, p);
  } catch (e) {
    box.querySelector(".fixbox-body").replaceChildren(el("p", { class: "meta" }, "Preview failed: " + e.message));
  }
}

// drawPreviewInto renders a fetched preview into a box already in the DOM —
// the alternative-picker/Apply pair a Review finding needs, redrawn in
// place each time a different alternative is chosen.
function drawPreviewInto(box, f, p) {
  let chosen = 0;
  const head = box.querySelector(".fixbox-head");
  const body = box.querySelector(".fixbox-body");
  const draw = () => {
    const a = p.actions[chosen];
    head.textContent = p.label;
    body.replaceChildren(
      p.actions.length > 1 ? altPicker(p, chosen, (i) => { chosen = i; draw(); }) : "",
      a.benefit ? el("div", { class: "benefit" }, "✓  " + a.benefit) : "",
      a.warning ? el("div", { class: "warn" }, "⚠  " + a.warning) : "",
      actionBody(a),
      el("div", { class: "row" },
        el("button", { class: "primary", onclick: () => applyFix(f, chosen) }, "Apply")
      )
    );
  };
  draw();
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
    // always said so. verify_message is rendered by the engine, not composed
    // here: the difference between "re-checked and gone" and "applied but
    // not yet in force" is subtle enough that three interfaces phrasing it
    // themselves would make three different claims.
    showOutcomeModal("Fix applied", o);
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

// ── AI advisory ───────────────────────────────────────────────────────
// The whole-scan counterpart to explainAI: every fixable finding's
// benefit/cost, judged against the host description saved here, which
// this panel is also where that description gets edited. GET/POST
// /api/ai-context and GET /api/advise are the whole surface; nothing
// beyond what is on screen is kept client-side.
async function showAdvise() {
  selected = null;
  document.querySelectorAll(".finding").forEach((n) => n.classList.remove("active"));
  const d = document.getElementById("detail");
  d.replaceChildren(el("h3", {}, "Should these fixes be applied here?"));

  let ctx = "";
  try {
    ctx = (await api("/api/ai-context")).text || "";
  } catch (e) { flash("Could not load the host description: " + e.message, true); }

  const textarea = Object.assign(document.createElement("textarea"), {
    className: "ctxinput", value: ctx,
    placeholder: "Describe this host in one line — its purpose, and whether it favors staying current or staying stable.",
  });
  const saveBtn = el("button", {}, "Save");
  d.append(el("div", { class: "fixbox ctxbox" },
    el("div", { class: "fixbox-head" }, "This host"),
    el("div", { class: "fixbox-body" }, textarea, el("div", { class: "row" }, saveBtn))));

  const resultBody = el("div", { class: "fixbox-body" }, el("p", { class: "meta" }, "Judging every fixable finding…"));
  d.append(el("div", { class: "fixbox" }, resultBody));

  const loadAdvice = async () => {
    resultBody.replaceChildren(el("p", { class: "meta" }, "Judging every fixable finding…"));
    try {
      const adv = await api("/api/advise");
      resultBody.replaceChildren(
        el("pre", { class: "advise-plain" }, adv.plain),
        adv.ai ? el("div", { class: "aibox" },
          el("div", { class: "howto" }, "AI verdict (advisory)"), el("p", {}, adv.ai)) : "",
        !adv.ai && adv.ai_error ? el("div", { class: "aibox" },
          el("div", { class: "howto" }, "AI verdict (advisory)"), el("p", { class: "meta" }, adv.ai_error)) : ""
      );
    } catch (e) {
      resultBody.replaceChildren(el("p", { class: "meta" }, "Advise failed: " + e.message));
    }
  };

  saveBtn.onclick = () => whileBusy(saveBtn, "Saving…", async () => {
    await api("/api/ai-context", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: textarea.value }),
    });
    await loadAdvice();
  });

  await loadAdvice();
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
  if (!force) {
    const ok = await confirmModal(`Roll back "${cp.label}"?`,
      "This restores the original file as it was before the fix was applied.", "Roll back");
    if (!ok) return;
  }
  try {
    const o = await api("/api/rollback", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ checkpoint_id: cp.id, force }),
    });
    const n = o.restored_files ? o.restored_files.length : 0;
    showOutcomeModal("Rolled back", {
      new_score: o.new_score,
      restart_hint: o.restart_service,
      verify_message: `Restored ${n} file${n === 1 ? "" : "s"}.`,
    });
    await refresh();
    await showHistory();
  } catch (e) {
    // 409 is the engine declining, not failing: the file changed after
    // hostveil wrote it, so restoring the backup would discard whatever
    // was done in between. Rollback keeps no checkpoint of its own, so
    // say that plainly and make the override a second, informed answer.
    if (e.status === 409) {
      const ok = await confirmModal("Overwrite it anyway?",
        `${e.message} This restores hostveil's backup over the current file, discarding those changes. ` +
        "Rollback writes no checkpoint of its own, so this cannot be undone.", "Overwrite");
      if (ok) await rollback(cp, true);
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

// ── modal ──────────────────────────────────────────────────────────────
// One overlay for what used to be three different things: a native
// <select> glued to a separate Export button, a one-line toast that a fix
// or a rollback had to compress its whole outcome into, and no feedback at
// all for a batch's progress beyond a disabled button. <dialog> gives
// Escape-to-close and a ::backdrop for free; blocking is set while a batch
// is mid-run so it cannot be dismissed out from under itself.
function openModal(contentEl, { blocking = false } = {}) {
  const dlg = document.getElementById("modal");
  document.getElementById("modal-body").replaceChildren(contentEl);
  dlg.toggleAttribute("data-busy", blocking);
  if (!dlg.open) dlg.showModal();
}
function closeModal() {
  const dlg = document.getElementById("modal");
  if (dlg.open) dlg.close();
}
document.getElementById("modal").addEventListener("cancel", (e) => {
  if (e.target.hasAttribute("data-busy")) e.preventDefault();
});
document.getElementById("modal").addEventListener("click", (e) => {
  // A click that lands on the <dialog> itself rather than on modal-body's
  // content is a click on the ::backdrop — <dialog> has no other way to
  // tell the two apart.
  if (e.target === e.currentTarget && !e.currentTarget.hasAttribute("data-busy")) closeModal();
});

// showOutcomeModal renders one fix's or one rollback's result — score,
// restart hint, verify message, checkpoint id — as a modal with a Done
// button, instead of compressing it into a one-line toast that disappears
// in six seconds. o is either a model.FixOutcome or the shape rollback()
// below builds to match it.
function showOutcomeModal(title, o) {
  const lines = [];
  if (o.new_score) lines.push(el("p", {}, `Score: ${o.new_score.overall}/100`));
  if (o.restart_hint) lines.push(el("p", { class: "warn" }, `Restart '${o.restart_hint}' for it to take effect.`));
  if (o.verify_message) lines.push(el("p", {}, o.verify_message));
  if (o.checkpoint_id) lines.push(el("p", { class: "meta" }, `Rollback checkpoint: ${o.checkpoint_id}`));
  const done = el("button", { class: "primary" }, "Done");
  done.onclick = closeModal;
  openModal(el("div", {}, el("h3", {}, title), ...lines, el("div", { class: "row" }, done)));
}

// confirmModal replaces window.confirm() with the same modal every other
// dialog in this file uses — a native confirm() looks like the browser
// interrupting the page, not the dashboard asking a question, and it can't
// carry more than one line of plain text. Resolves true on the confirm
// button, false on Cancel *or* on any other way the dialog closes (Escape,
// a click on the backdrop) — a dismissal is a "no" here the same way it is
// for a native confirm().
function confirmModal(title, message, confirmLabel = "Confirm") {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
      closeModal();
    };
    const yes = el("button", { class: "primary", onclick: () => finish(true) }, confirmLabel);
    const no = el("button", { onclick: () => finish(false) }, "Cancel");
    openModal(el("div", {}, el("h3", {}, title), el("p", {}, message), el("div", { class: "row" }, yes, no)));
    document.getElementById("modal").addEventListener("close", () => finish(false), { once: true });
  });
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

// ── sort control ───────────────────────────────────────────────────────
// Lives in the findings pane's own header, not the top statusbar — it is a
// list-scoped choice, not a global one. Same read-then-write pattern as the
// theme/layout pickers, minus the localStorage: a sort choice is about what
// you are looking at right now, not a standing preference across sessions.
function initSortPicker() {
  const sel = document.getElementById("sort");
  if (!sel) return;
  sel.value = sortBy;
  sel.onchange = () => {
    sortBy = sel.value;
    if (report) render();
  };
}

initThemePicker();
initLayoutPicker();
initSortPicker();

document.getElementById("scrim").onclick = closeDetail;
// Escape is what people press at an overlay before they look for a button.
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && selected && layoutIs("triage", "railverdict")) closeDetail();
});

document.getElementById("history").onclick = showHistory;
document.getElementById("advise").onclick = showAdvise;

// Export opens a modal to choose the format, then downloads /api/export as
// a file rather than navigating to it: the route can answer 409 (no scan
// yet) or 400 (bad format), and a plain <a href> navigation on an error
// response would replace this whole page with a blank error document
// instead of leaving flash() to say what happened.
//
// The format list used to be a second <select> beside this button, styled
// like nothing else in the bar (app.css had rules for #theme/#layout and
// none for it) and taking a second control to say one thing. exportFormats
// comes from /model.js — core.ExportFormats(), the same table the CLI's
// --format flag and the TUI's picker resolve against — so a sixth format
// only ever needs the one new row there.
const exportBtn = document.getElementById("export");
exportBtn.onclick = () => {
  const formats = M.exportFormats || [];
  let chosen = formats[0] && formats[0].id;
  const list = el("div", { class: "modal-fmt" },
    ...formats.map((f, i) => {
      const input = Object.assign(document.createElement("input"),
        { type: "radio", name: "fmt", checked: i === 0 });
      input.onchange = () => { chosen = f.id; };
      return el("label", {}, input, " " + f.label);
    })
  );
  const dl = el("button", { class: "primary" }, "Download");
  dl.onclick = () => whileBusy(dl, "Exporting…", async () => {
    const res = await fetch("/api/export?format=" + encodeURIComponent(chosen));
    if (!res.ok) throw new Error((await res.text()) || res.statusText);
    const blob = await res.blob();
    const cd = res.headers.get("content-disposition") || "";
    const name = /filename="([^"]+)"/.exec(cd)?.[1] || ("hostveil-report." + chosen);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
    closeModal();
  });
  openModal(el("div", {}, el("h3", {}, "Export"), list, el("div", { class: "row" }, dl)));
};

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
  marked.clear();
  const res = await fetch("/api/rescan", { method: "POST", headers: { "Content-Type": "application/json" } });
  if (!res.ok && res.status !== 409) throw new Error((await res.text()) || res.statusText);
  await watchScan("Rescanning");
  flash("Rescan complete.");
});

// scanStartedAt is set once per poll loop (pollRescan) and read by
// renderScanProgress for the elapsed clock. Module-level rather than a
// parameter because whileBusy/watchScan/pollRescan's call chain has no
// natural place to thread it through, and there is only ever one scan
// running at a time (the engine serialises scan/apply/rollback behind one
// mutex, so a second poll loop can never overlap this one).
let scanStartedAt = null;

// formatElapsed mirrors the TUI's clock: seconds under a minute, minutes and
// seconds after. No ETA anywhere near this — most domains finish in well
// under a second and the CVE domain's Trivy run can take minutes, so a
// remaining-time estimate would be confidently wrong for most of the wait.
// See internal/ui/tui/scanning_test.go's
// TestTheScanScreenDoesNotEstimateWhatItCannotKnow for why the TUI refuses
// one too.
function formatElapsed(ms) {
  const total = Math.floor(ms / 1000);
  if (total < 60) return total + "s";
  const m = Math.floor(total / 60), s = total % 60;
  return m + ":" + String(s).padStart(2, "0");
}

// scanStateWord is the label a domain's row shows, in the TUI's own
// wording (internal/ui/tui/view.go's scanDomainRow) — not SCAN[state].name,
// which is the stable wire name ("degraded"), not the word a reader wants
// ("partial").
function scanStateWord(state) {
  switch (state) {
    case "running": return "scanning…";
    case "done": return "done";
    case "skipped": return "skipped";
    case "degraded": return "partial";
    case "error": return "failed";
    default: return "waiting"; // pending, or a state this page has never seen
  }
}

// scanStateClass picks up colors this file already assigns the same states
// elsewhere — .dom-err is --crit, .axis.partial is --med — rather than
// inventing a fourth place these four colors get decided.
function scanStateClass(state) {
  switch (state) {
    case "done": return "scan-done";
    case "error": return "scan-error";
    case "degraded": return "scan-degraded";
    case "skipped": return "scan-skipped";
    case "running": return "scan-running";
    default: return "scan-pending";
  }
}

// renderScanProgress is the whole of what a running scan shows: an overall
// bar in the axes strip (where the finished score normally sits), a
// per-domain checklist in the detail pane (where a selected finding
// normally sits), and a one-line placeholder in the findings list instead
// of a bare, silent <ul>. Before this, the entire page showed one line of
// toast text and nothing else moved until the scan finished.
//
// domains is /api/rescan/status's own array — every domain that has
// reported at least once, in no particular order, some of them possibly
// absent (not yet started). The full roster comes from SRC (the model's own
// domain table, already loaded for the filter chips), so an absent domain
// reads as "waiting" rather than not appearing at all — the same thing
// internal/ui/tui/tui.go's scanDomains() does with its fetched plan.
function renderScanProgress(verb, domains) {
  const bySource = {};
  (domains || []).forEach((d) => { bySource[d.source] = d; });
  const roster = Object.keys(SRC).sort(byRank(SRC));
  const total = roster.length;
  const done = roster.filter((s) => {
    const state = (bySource[s] || {}).state;
    return state && state !== "running" && state !== "pending";
  }).length;

  const elapsed = scanStartedAt ? formatElapsed(Date.now() - scanStartedAt) : "0s";
  const pct = total ? (done / total) * 100 : 0;
  // At least one segment lit as soon as real progress exists — an empty bar
  // reads as "stuck", not "just started", the same reason the TUI's own
  // meter (meterAtLeastOne) guarantees the same floor.
  const bar = meter(done > 0 ? Math.max(pct, 100 / total) : pct, "b-safe");
  document.getElementById("axes").replaceChildren(
    el("div", { class: "scan-status" },
      el("span", {}, `${verb}… ${done} of ${total} domains`),
      bar,
      el("span", { class: "scan-elapsed" }, elapsed))
  );

  document.getElementById("detail").replaceChildren(
    el("div", { class: "scan-domains" },
      ...roster.map((s) => {
        const state = (bySource[s] || {}).state || "pending";
        return el("div", { class: "scan-domain-row" },
          el("span", {}, srcLabel(s)),
          el("span", { class: scanStateClass(state) }, scanStateWord(state)));
      }))
  );

  document.getElementById("findings").replaceChildren(
    el("li", { class: "clean muted" }, "Scanning the host…")
  );
}

// pollRescan resolves when the running scan finishes, rendering the
// per-domain progress roughly once a second (and once immediately, before
// the first poll response, so there is never a blank frame). verb is what
// the progress view calls the scan in progress — "Rescanning" from the
// button above, "Scanning" from boot() below, where there may be no prior
// result to justify the "re-".
async function pollRescan(verb) {
  scanStartedAt = Date.now();
  renderScanProgress(verb, []);
  for (;;) {
    const st = await api("/api/rescan/status");
    renderScanProgress(verb, st.domains);
    if (!st.running) return;
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
fixallBtn.onclick = async () => {
  const ok = await confirmModal("Apply every safe fix?",
    "Every Auto finding is applied now. Each is previewed and backed up first, and reversible from History.",
    "Fix all safe");
  if (!ok) return;
  const findings = active(report.findings).filter(isAuto)
    .map((f) => ({ id: f.id, service: f.service || "", title: f.title }));
  applyMany(findings, "Fixing");
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
