"use strict";

// Drop the access token out of the address bar.
//
// It arrives in the URL because that is the one channel a terminal can hand
// to a browser, and the server converts it into a SameSite=Strict session
// cookie on the very first request. Past that point the copy in the query
// string is residue: every fetch below authenticates with the cookie and not
// one of them carries ?t=. Residue is not free: it sits in the address bar,
// in the history entry, in a bookmark made without thinking, and in every
// screenshot of the dashboard anyone pastes into an issue. `Referrer-Policy:
// no-referrer` already stops it leaving over the network; this is the rest.
//
// Reloading the stripped URL works for as long as the session cookie lives.
// Past that the server answers 401 with the sentence telling the operator to
// reopen the URL Hostveil printed, and `serve` is still printing it in the
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
// readable.
const M = window.HOSTVEIL_MODEL || {};
const SRC = M.domains || {};
const SEV = M.severities || {};
const REM = M.remediations || {};
const SCAN = M.scanStates || {};
const BANDS = M.bands || [];

// ── language ───────────────────────────────────────────────────────────
// The dashboard is the one interface translated: the TUI and the CLI stay in
// English. The English text stays where it is written (this file, and the Go
// code that builds findings and fixes), and a catalog per language maps it:
//
//   messages  text this file writes, for t(). A {name} is filled from vars.
//   server    text the server sends, for tr(): labels, fix sentences,
//             reasons. A {name} in a key matches any run of text, and the
//             same {name} in the translation receives it, so one key
//             "Set X for {svc}" covers every service.
//   findings  finding ID → {title, description, how_to_fix}.
//
// The two text tables are kept apart because a t() key such as "{n} new"
// would match far too much server text as a pattern.
//
// Anything the catalog does not know renders in English.
// internal/docs/i18n_test.go checks every key this file asks for, every
// finding ID, and every string the fix registry can build.
const LANGS = [{ id: "en", name: "English" }, { id: "ko", name: "한국어" }];
const CAT = { messages: {}, server: {}, findings: {} };
let LANG = pickLang();
let PATTERNS = [];

function pickLang() {
  let saved = null;
  try { saved = localStorage.getItem("hostveil.lang"); } catch (e) { /* private mode */ }
  if (LANGS.some((l) => l.id === saved)) return saved;
  const wanted = (navigator.languages || [navigator.language || ""]).map((l) => String(l).slice(0, 2));
  return wanted.find((l) => LANGS.some((x) => x.id === l)) || "en";
}

async function loadCatalog() {
  if (LANG !== "en") {
    try {
      Object.assign(CAT, await api(`/i18n/${LANG}.json`));
    } catch (e) {
      LANG = "en";
    }
  }
  // Most literal text first, so a specific key wins over a general one
  // that would also match.
  const literal = (k) => k.replace(/\{\w+\}/g, "").length;
  PATTERNS = Object.entries(CAT.server)
    .filter(([k, v]) => k.includes("{") && v)
    .sort(([a], [b]) => literal(b) - literal(a))
    .map(([k, v]) => ({ re: patternFor(k), out: v }));
  document.documentElement.lang = LANG;
  translateStatic();
}

// patternFor turns a catalog key into a whole-string match: the text is
// literal and each {name} captures what stands there.
function patternFor(key) {
  const src = key.split(/(\{\w+\})/).map((part) => {
    const m = /^\{(\w+)\}$/.exec(part);
    return m ? `(?<${m[1]}>.+?)` : part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }).join("");
  return new RegExp("^" + src + "$", "s");
}

function fill(s, vars) {
  return s.replace(/\{(\w+)\}/g, (m, k) => (vars && k in vars ? String(vars[k]) : m));
}

// t is for text this file writes. The key is the English.
function t(key, vars) {
  const s = CAT.messages[key];
  return fill(s === undefined || s === "" ? key : s, vars);
}

// tr is for text the server sent: a label, a fix's benefit, a reason.
function tr(s) {
  if (!s || LANG === "en") return s;
  const hit = CAT.server[s];
  if (hit) return hit;
  for (const p of PATTERNS) {
    const m = p.re.exec(s);
    if (m) return fill(p.out, m.groups);
  }
  return s;
}

// ft is a finding's own text in the reader's language, or the English.
function ft(f, field) {
  const e = CAT.findings[f.id];
  return (e && e[field]) || f[field];
}
function translated(f) { return LANG !== "en" && !!CAT.findings[f.id]; }

// translateStatic covers index.html: every element marked data-i18n has its
// English text as the key, and data-i18n-aria does the same for its English
// aria-label.
function translateStatic() {
  document.querySelectorAll("[data-i18n]").forEach((n) => {
    if (!n.dataset.en) n.dataset.en = n.textContent.trim();
    n.textContent = t(n.dataset.en);
  });
  document.querySelectorAll("[data-i18n-aria]").forEach((n) => {
    if (!n.dataset.enAria) n.dataset.enAria = n.getAttribute("aria-label") || "";
    n.setAttribute("aria-label", t(n.dataset.enAria));
  });
}

function initLangPicker() {
  const sel = document.getElementById("lang");
  if (!sel) return;
  sel.replaceChildren(...LANGS.map((l) => {
    const o = el("option", { value: l.id }, l.name);
    if (l.id === LANG) o.selected = true;
    return o;
  }));
  sel.onchange = () => {
    try { localStorage.setItem("hostveil.lang", sel.value); } catch (e) { /* private mode */ }
    location.reload();
  };
}

function srcLabel(s) { return tr((SRC[s] && SRC[s].label) || String(s)); }

// Enum values arrive as names now, so anything that needs the
// model's ordering asks for it. rank is the row's position in the table the
// engine declared; sorting by the name itself would put "low" before
// "medium" and domains in alphabetical order, which is not an ordering
// anyone chose.
function rank(table, key) { return (table[key] && table[key].rank) ?? 1e9; }
function byRank(table) { return (a, b) => rank(table, a) - rank(table, b); }

let report = null;
// trend is fetched separately from the report: the report is refetched
// after every fix, and the trend only moves when a scan does.
let trend = null;
let selected = null; // {id, service}; the inspected finding (single-select)

// Filter + multi-select + sort state.
const filters = { sev: new Set(), domain: new Set(), fixable: false };
const marked = new Set(); // keys of findings picked for a batch fix
let sortBy = "severity"; // "severity" | "domain" | "remediation"; see #sort

// Comparators for the findings list. Each reads the same rank() the model's
// own tables carry, so "Domain" and "Remediation" sort in the order the
// engine declared them in.
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
    // and a decline is a question for the operator. Carrying it on the error is what lets the caller tell
    // them apart, without it the dashboard turned every decline into
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

function sevAbbr(f) { return (SEV[f.severity] && SEV[f.severity].abbr) || "?"; }
function remLabel(r) { return tr((REM[r] && REM[r].label) || "Unclassified"); }
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
// floor each, so the first row the score clears is its band: the same walk
// model.BandFor does. The thresholds were written out four times before
// this, and the CLI's copy had one fewer arm than the rest.
function bandFor(v) { return BANDS.find((b) => v >= b.min) || { cls: "b-na", verdict: "unscored" }; }
// afterFixesNote decides whether the headroom is worth a cell, and returns
// zero or one of them so a caller can spread it into a child list.
//
// Two refusals, and every interface makes the same two: nothing beside an N/A
// axis, because a number there is a claim about a domain the scan never looked at;
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
// The "~" is the important part: a degraded axis is scored from an
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
  // reason the findings do.
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

  // Domain chips (every source present in the report: filtering this list
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
  kids.push(chip(t("Fixable"), filters.fixable, () => { filters.fixable = !filters.fixable; render(); }));
  if (filterActive()) {
    kids.push(chip(t("Clear"), false, () => {
      filters.sev.clear(); filters.domain.clear(); filters.fixable = false; render();
    }));
  }
  bar.replaceChildren(...kids);
}

// ── multi-select ───────────────────────────────────────────────────────
function checkbox(f) {
  const box = Object.assign(document.createElement("input"), { type: "checkbox", checked: marked.has(fkey(f)) });
  box.className = "pick";
  box.setAttribute("aria-label", t("Select for batch fix"));
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
    el("button", { class: "primary", onclick: applyBatch }, t("Fix selected ({n})", { n: marked.size })),
    el("button", { onclick: selectAllAuto }, t("Select all auto")),
    el("button", { onclick: clearMarked }, t("Clear"))
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
    .map((f) => ({ id: f.id, service: f.service || "", title: ft(f, "title") }));
  return applyMany(findings, t("Fixing"));
}

// applyMany drives a per-item progress modal over `findings`, calling
// /api/fix/one once per finding in sequence. That endpoint is Engine.ApplyOne:
// the batch loop's own eligibility rule and no-verify semantics exposed
// per item. A loop over the single-fix endpoint would re-run
// each finding's domain checker (expensive for compose and cve) once per
// item instead of zero times. See internal/core.ApplyOne's doc comment.
async function applyMany(findings, verb) {
  if (!findings.length) return;
  const body = el("div", {}, el("p", {}, t("{verb} {i} of {n}…", { verb, i: 1, n: findings.length })));
  openModal(el("div", {}, el("h3", {}, verb + "…"), body), { blocking: true });

  let applied = 0, skipped = 0, failed = 0;
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    body.replaceChildren(el("p", {}, t("{verb} {i} of {n}: {title}", { verb, i: i + 1, n: findings.length, title: f.title || f.id })));
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
  const done = el("button", { class: "primary" }, t("Done"));
  done.onclick = closeModal;
  body.replaceChildren(
    el("p", {}, t("Applied {applied} · skipped {skipped} · failed {failed}.", { applied, skipped, failed })),
    el("div", { class: "row" }, done)
  );
  marked.clear();
  await refresh();
}

// Show which checkers did not fully cover their domain. Without this the
// dashboard renders a score built from a partial scan exactly like one built
// from a complete scan: the CVE axis reading a confident 100 because Trivy
// could not reach a single image is the case that motivated it.
// renderDelta summarises what moved since the previous scan. The CLI prints
// the same counts and then names the findings; here it stays one line: the
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
  const parts = [el("span", { class: "delta-label" }, t("Since last scan"))];
  if (resolved) parts.push(el("span", { class: "delta-good" }, "✓ " + t("{n} resolved", { n: resolved })));
  if (added) parts.push(el("span", { class: "delta-new" }, "+ " + t("{n} new", { n: added })));
  if (changed) parts.push(el("span", { class: "delta-chg" }, "~ " + t("{n} changed", { n: changed })));
  box.hidden = false;
  box.replaceChildren(...parts);
}

// renderTrend draws the score of every retained scan beside the delta.
//
// The glyphs come from the server, rendered by model.Sparkline: the same
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
    el("span", { class: "delta-label" }, t("Score over {n} scans", { n: pts.length })),
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
    const reason = tr(d.reason || "");
    if (state === "error") return el("span", { class: "dom-err" }, "! " + t("{name} failed: {reason}", { name, reason: reason || t("unknown error") }));
    if (state === "degraded") return el("span", {}, "~ " + t("{name} partial: {reason}", { name, reason }));
    if (state === "skipped") return el("span", { class: "dom-skip" }, "· " + t("{name} skipped: {reason}", { name, reason }));
    return el("span", { class: "dom-skip" }, "· " + t("{name} did not run", { name }));
  }));
}

// ── domain rail ──────────────────────────────────────────────────────
// Every axis as a row: score, bar, severity mix, and for a domain that did
// not run, the reason instead of a number. It doubles as the domain filter,
// as intended: the rail is where a skipped domain is both visible
// and clickable.
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
      row.append(el("span", { class: "c" }, `${scanStateWord(state)}; ${tr(dom.reason) || t("did not run")}`));
    } else {
      const mix = el("span", { class: "c" });
      const counts = {};
      for (const f of byDomain[ax.source] || []) counts[f.severity] = (counts[f.severity] || 0) + 1;
      const parts = [];
      for (const [i, sev] of Object.entries(SEV)) {
        if (counts[i]) parts.push(el("span", { class: sev.name }, `${counts[i]} ${sev.abbr}`));
      }
      if (!parts.length) parts.push(el("span", {}, t("clean")));
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

  rail.replaceChildren(el("div", { class: "rail-head" }, t("Domains · {n} findings", { n: all.length })), ...rows);
}

// ── main render ────────────────────────────────────────────────────────
function render() {
  const score = report.score;

  // Exposure gauge (the signature): SECURITY meter + score.
  //
  // When no domain ran there is nothing to average, so the number would be
  // arbitrary, and an empty meter next to a digit reads as "terrible host"
  // when the truth is "nothing was examined".
  document.getElementById("gauge").replaceChildren(
    el("span", { class: "gauge-label" }, t("Security")),
    ...(score.applicable === false
      ? [el("span", { class: "gauge-na" }, t("N/A; nothing could be scanned"))]
      : [meter(score.overall, band(score.overall)),
         el("span", { class: "gauge-score", html: `${score.overall}<small>/100</small>` }),
         ...afterFixesNote(score.applicable, score.overall, score.after_fixes,
                           (n) => el("span", { class: "gauge-after" }, t("{n} after fixes", { n })))])
  );

  // Per-axis bars. The short domain label: the column
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
  const all = active(report.findings);
  // Built before the early returns below: a clean host and a
  // filtered-to-nothing list still need a correct rail.
  renderRail(all);
  renderFilterbar(all);
  const items = applyFilters(all).sort(sortComparators[sortBy] || sortComparators.severity);
  document.getElementById("findings-title-text").textContent =
    filterActive() ? t("Findings · {shown}/{n}", { shown: items.length, n: all.length }) : t("Findings · {n}", { n: all.length });

  if (all.length === 0) {
    marked.clear();
    renderBatchbar();
    // "Clean" is a claim about the whole host, so it may only be made when
    // the whole host was examined. Finding nothing and being
    // unable to look score the same and mean opposite things, and this
    // page said "Clean." either way, so a host whose every checker had
    // failed was reported spotless right above the notice saying so.
    const missing = incompleteDomains().length;
    list.replaceChildren(missing > 0
      ? el("li", { class: "clean muted" },
        t("No problems found in the domains that ran, but {n} did not complete.", { n: missing }))
      : el("li", { class: "clean" }, t("No problems found. Clean.")));
    document.getElementById("detail").replaceChildren(el("p", { class: "empty" }, t("Nothing to fix.")));
    return;
  }
  if (items.length === 0) {
    renderBatchbar();
    list.replaceChildren(el("li", { class: "clean muted" }, t("No findings match the filter.")));
    return;
  }

  const rows = new Map(); // finding key -> its <li>, so the overview can jump to one
  const row = (f) => {
    const li = el("li", { class: "finding " + sevName(f) + (isAuto(f) ? " pickable" : "") + (isPending(f) ? " pending" : "") },
      isAuto(f) ? checkbox(f) : el("span", { class: "pick-spacer" }),
      el("span", { class: "sev" }, sevAbbr(f)),
      el("div", { class: "title" },
        el("div", { class: "name" }, ft(f, "title")),
        el("div", { class: "rem rem-" + f.remediation }, f.id + "  ·  " +
          (isPending(f) ? t("Applied, waiting to take effect") : remLabel(f.remediation)))
      ),
      f.service ? el("span", { class: "svc" }, f.service) : ""
    );
    li.onclick = () => selectFinding(f, li);
    if (selected && selected.id === f.id && selected.service === f.service) li.classList.add("active");
    rows.set(fkey(f), li);
    return li;
  };

  list.replaceChildren(...items.map(row));
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
    ? t("This host could not be scanned.")
    : t("This host is {verdict}.", { verdict: tr(bandFor(report.score.overall).verdict) })));
  box.append(el("p", { class: "over-lead" }, all.length === 1
    ? t("{n} unresolved finding across the domains that ran.", { n: all.length })
    : t("{n} unresolved findings across the domains that ran.", { n: all.length })));

  // Severity chips, only for severities present. Ordered by the
  // model's table, which is most-severe-first.
  const chips = el("div", { class: "over-sev" });
  for (const [i, sev] of Object.entries(SEV)) {
    const n = counts[i] || 0;
    if (n > 0) chips.append(el("span", { class: "over-chip sev-" + sev.name },
      t("{n} {severity}", { n, severity: tr(sev.name.charAt(0).toUpperCase() + sev.name.slice(1)) })));
  }
  box.append(chips);

  // The one action that needs no per-finding decision.
  if (autos > 0) {
    const btn = el("button", { class: "primary over-fixall" }, autos === 1
      ? t("Fix all {n} safe finding", { n: autos })
      : t("Fix all {n} safe findings", { n: autos }));
    btn.onclick = () => document.getElementById("fixall").click();
    box.append(btn);
    box.append(el("p", { class: "over-note" },
      t("Each is previewed and backed up first, and reversible from History.")));
  }

  // Where the points between the score and 100 are, by what it takes to
  // win them back. Shown so a score that stays below 100 after every fix
  // reads as a list of reasons. The parts come from the model
  // (ScoreBreakdown.Left), so every interface states the same numbers.
  const left = report.score.left || {};
  const pts = (n) => (n === 1 ? t("{n} pt", { n }) : t("{n} pts", { n }));
  const leftRows = [];
  if (left.pending > 0)
    leftRows.push(["+" + pts(left.pending), left.pending_count === 1
      ? t("when {n} applied fix takes effect. Restart the services they name.", { n: 1 })
      : t("when {n} applied fixes take effect. Restart the services they name.", { n: left.pending_count })]);
  if (left.manual > 0)
    leftRows.push([pts(left.manual), left.manual_count === 1
      ? t("held by {n} finding Hostveil leaves to you. Each one says why and how to fix it by hand.", { n: 1 })
      : t("held by {n} findings Hostveil leaves to you. Each one says why and how to fix it by hand.", { n: left.manual_count })]);
  if (left.unavailable > 0)
    leftRows.push([pts(left.unavailable), left.unavailable_count === 1
      ? t("held by {n} finding with no fix published yet. They clear when the vendor ships a patch.", { n: 1 })
      : t("held by {n} findings with no fix published yet. They clear when the vendor ships a patch.", { n: left.unavailable_count })]);
  if (report.score.applicable !== false && leftRows.length) {
    box.append(el("div", { class: "over-head" }, t("Points left")));
    const ul = el("ul", { class: "over-left" });
    for (const [pts, text] of leftRows)
      ul.append(el("li", {}, el("span", { class: "pts" }, pts), el("span", {}, text)));
    box.append(ul);
  }

  // Jump list: the most severe handful, so the worst problems are one click
  // away.
  const top = visible.slice(0, 6);
  if (top.length) {
    box.append(el("div", { class: "over-head" }, t("Most severe")));
    const ul = el("ul", { class: "over-jump" });
    for (const f of top) {
      const li = el("li", { class: "over-jump-row" },
        el("span", { class: "sev " + sevName(f) }, sevAbbr(f)),
        el("span", { class: "over-jump-title" }, ft(f, "title")),
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
  const meta = [f.id, tr(sevName(f)), remLabel(f.remediation)];
  if (f.service) meta.push(t("service: {svc}", { svc: f.service }));
  const d = document.getElementById("detail");
  d.replaceChildren(
    el("h3", {}, ft(f, "title")),
    el("div", { class: "meta" }, meta.join("  ·  ")),
    f.description ? el("p", {}, ft(f, "description")) : "",
    f.how_to_fix ? el("div", { class: "howto" }, t("How to fix")) : "",
    f.how_to_fix ? el("p", {}, ft(f, "how_to_fix")) : "",
    // Under the instructions: this answers the question a
    // reader asks second, and it is absent entirely on anything fixable.
    f.why_no_fix ? el("div", { class: "howto" }, t("Why there is no fix button")) : "",
    f.why_no_fix ? el("p", { class: "whynofix" }, tr(f.why_no_fix)) : "",
    // The translation is written per finding ID, so it cannot carry the
    // names, paths and counts the English was built with. The English is
    // one click away for those.
    translated(f) ? el("details", { class: "original" },
      el("summary", {}, t("Original text (English)")),
      el("p", {}, el("b", {}, f.title)),
      f.description ? el("p", {}, f.description) : "",
      f.how_to_fix ? el("p", {}, f.how_to_fix) : "") : ""
  );
  // Shown immediately: there is
  // nothing to decide before seeing it, and gating it behind a button meant
  // a second click re-appended a second copy underneath the first, since
  // nothing ever removed the one already there.
  if (isFixable(f)) {
    const box = el("div", { class: "fixbox" },
      el("div", { class: "fixbox-head" }, t("Fix preview")),
      el("div", { class: "fixbox-body" }, el("p", { class: "meta" }, t("Loading fix preview…"))));
    d.append(box);
    loadPreview(f, box);
  }
  // A row: without a
  // wrapper neither had any margin of its own, so whichever came right
  // before (a paragraph, or the fixbox) butted straight up against
  // "Explain with AI" with no breathing room at all.
  const explainBtn = el("button", { onclick: (ev) => explainAI(f, ev.target) }, t("Explain with AI"));
  d.append(el("div", { class: "detail-actions" }, explainBtn));
}

// explainAI asks the server for the advisory AI explanation. It degrades in
// place: with no Ollama reachable the server answers with ai_error, which
// renders as a note; AI is optional everywhere.
async function explainAI(f, btn) {
  const d = document.getElementById("detail");
  const old = d.querySelector(".aibox");
  if (old) old.remove();
  const box = el("div", { class: "aibox" }, el("div", { class: "meta" }, t("Asking the local AI model…")));
  d.append(box);
  if (btn) btn.disabled = true;
  try {
    const ex = await api(`/api/explain?id=${encodeURIComponent(f.id)}&service=${encodeURIComponent(f.service || "")}`);
    box.replaceChildren(
      el("div", { class: "howto" }, t("AI explanation (advisory)")),
      ex.ai ? el("p", {}, ex.ai) : el("p", { class: "meta" }, tr(ex.ai_error) || t("The AI provider returned nothing."))
    );
  } catch (e) {
    box.replaceChildren(el("p", { class: "meta" }, t("AI explanation failed: {err}", { err: e.message })));
  } finally {
    if (btn) btn.disabled = false;
  }
}

// loadPreview fetches a finding's fix preview into a box selectFinding has
// already appended to #detail, replacing its "Loading…" placeholder either
// way, with the diff, or with why it could not be fetched.
async function loadPreview(f, box) {
  try {
    const p = await api(`/api/preview?id=${encodeURIComponent(f.id)}&service=${encodeURIComponent(f.service || "")}`);
    drawPreviewInto(box, f, p);
  } catch (e) {
    box.querySelector(".fixbox-body").replaceChildren(el("p", { class: "meta" }, t("Preview failed: {err}", { err: e.message })));
  }
}

// drawPreviewInto renders a fetched preview into a box already in the DOM:
// the alternative-picker/Apply pair a Review finding needs, redrawn in
// place each time a different alternative is chosen.
function drawPreviewInto(box, f, p) {
  let chosen = 0;
  const head = box.querySelector(".fixbox-head");
  const body = box.querySelector(".fixbox-body");
  const draw = () => {
    const a = p.actions[chosen];
    head.textContent = tr(p.label);
    const apply = el("button", { class: "primary", onclick: () => applyFix(f, chosen) }, t("Apply"));
    // A fix that names something to check first keeps Apply off until the
    // reader says they checked it. The sentence is written for someone who
    // has not read an sshd_config before (internal/fix/checkfirst.go).
    let confirm = "";
    if (a.check_first) {
      apply.disabled = true;
      const tick = Object.assign(document.createElement("input"), { type: "checkbox" });
      tick.onchange = () => { apply.disabled = !tick.checked; };
      confirm = el("div", { class: "checkfirst" },
        el("div", { class: "howto" }, t("Before you apply")),
        el("label", {}, tick, " " + tr(a.check_first)));
    }
    body.replaceChildren(
      p.actions.length > 1 ? altPicker(p, chosen, (i) => { chosen = i; draw(); }) : "",
      a.benefit ? el("div", { class: "benefit" }, "✓  " + tr(a.benefit)) : "",
      a.warning ? el("div", { class: "warn" }, "⚠  " + tr(a.warning)) : "",
      el("ul", { class: "fixfacts" }, ...fixFacts(a).map((t) => el("li", {}, t))),
      confirm,
      // The exact change is one click away. The sentences above are what a
      // first-time reader decides on; the diff is for whoever wants proof.
      el("details", { class: "change" },
        el("summary", {}, a.type === "exec" ? t("Show the commands") : t("Show the exact change")),
        actionBody(a)),
      el("div", { class: "row" }, apply)
    );
  };
  draw();
}

// fixFacts is what applying this action means for undoing it and for when
// it reaches the host, in the order a reader asks.
function fixFacts(a) {
  const out = [];
  if (a.type === "exec") out.push(t("Runs a command. Hostveil cannot undo it from History."));
  else if (a.irreversible) out.push(t("Recorded in History, but it cannot be rolled back."));
  else out.push(t("Backed up first. You can undo it from History."));
  if (a.takes_effect_on) out.push(t("Takes effect after {when}.", { when: tr(a.takes_effect_on) }));
  return out;
}

function altPicker(p, chosen, onpick) {
  return el("div", { class: "alts" },
    ...p.actions.map((a, i) => {
      const input = Object.assign(document.createElement("input"),
        { type: "radio", name: "alt", checked: i === chosen });
      input.onchange = () => onpick(i);
      return el("label", {}, input, " " + tr(a.label) + (i === 0 ? " " + t("(recommended)") : ""));
    })
  );
}

// An unrecognised action type must never render as an empty box beside a
// live Apply button, that reads as "this fix changes nothing".
function actionBody(a) {
  // An edit that restarts something afterwards shows both halves: the diff
  // is what changes, the commands are what puts it in force.
  if (a.type === "edit" && a.commands && a.commands.length)
    return el("div", {}, diffPre(a.diff), el("p", { class: "muted" }, t("Then these commands run:")), cmdList(a.commands));
  if (a.type === "edit" || a.type === "mode") return diffPre(a.diff);
  if (a.type === "exec") return cmdList(a.commands);
  return el("pre", { class: "diff" }, t("(no preview available for action type {type})", { type: a.type }));
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
    // always said so. verify_message is rendered by the engine: the difference between "re-checked and gone" and "applied but
    // not yet in force" is subtle enough that three interfaces phrasing it
    // themselves would make three different claims.
    showOutcomeModal(t("Fix applied"), o);
    await refresh();
  } catch (e) { flash(t("Fix failed: {err}", { err: e.message }), true); }
}

// ── history + rollback ─────────────────────────────────────────────────
// Every applied fix leaves a checkpoint; this panel is how the web UI
// makes them reversible, so a fix applied here can be undone here rather
// than only from the CLI.
async function showHistory() {
  let res;
  try {
    res = await api("/api/history");
  } catch (e) { flash(t("Could not load history: {err}", { err: e.message }), true); return; }

  const cps = res.checkpoints || [];
  selected = null;
  document.querySelectorAll(".finding").forEach((n) => n.classList.remove("active"));
  const d = document.getElementById("detail");
  d.replaceChildren(
    el("h3", {}, t("Applied fixes")),
    el("div", { class: "meta" }, cps.length === 1
      ? t("{n} checkpoint  ·  newest first", { n: 1 })
      : t("{n} checkpoints  ·  newest first", { n: cps.length }))
  );
  // Some checkpoints on disk could not be read. The list below is still
  // usable; what is missing from it cannot be rolled back at all, which is
  // exactly the thing an operator must not discover only when they try.
  if (res.warning) {
    d.append(el("div", { class: "warn" }, "⚠  " + tr(res.warning)));
  }
  if (!cps.length) {
    d.append(el("p", { class: "empty" }, t("No fixes have been applied yet.")));
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
  d.replaceChildren(el("h3", {}, t("Should these fixes be applied here?")));

  let ctx = "";
  try {
    ctx = (await api("/api/ai-context")).text || "";
  } catch (e) { flash(t("Could not load the host description: {err}", { err: e.message }), true); }

  const textarea = Object.assign(document.createElement("textarea"), {
    className: "ctxinput", value: ctx,
    placeholder: t("Describe this host in one line; its purpose, and whether it favors staying current or staying stable."),
  });
  const saveBtn = el("button", {}, t("Save"));
  d.append(el("div", { class: "fixbox ctxbox" },
    el("div", { class: "fixbox-head" }, t("This host")),
    el("div", { class: "fixbox-body" }, textarea, el("div", { class: "row" }, saveBtn))));

  const resultBody = el("div", { class: "fixbox-body" }, el("p", { class: "meta" }, t("Judging every fixable finding…")));
  d.append(el("div", { class: "fixbox" }, resultBody));

  const loadAdvice = async () => {
    resultBody.replaceChildren(el("p", { class: "meta" }, t("Judging every fixable finding…")));
    try {
      const adv = await api("/api/advise");
      resultBody.replaceChildren(
        el("pre", { class: "advise-plain" }, adv.plain),
        adv.ai ? el("div", { class: "aibox" },
          el("div", { class: "howto" }, t("AI verdict (advisory)")), el("p", {}, adv.ai)) : "",
        !adv.ai && adv.ai_error ? el("div", { class: "aibox" },
          el("div", { class: "howto" }, t("AI verdict (advisory)")), el("p", { class: "meta" }, tr(adv.ai_error))) : ""
      );
    } catch (e) {
      resultBody.replaceChildren(el("p", { class: "meta" }, t("Advise failed: {err}", { err: e.message })));
    }
  };

  saveBtn.onclick = () => whileBusy(saveBtn, t("Saving…"), async () => {
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
        "⚠  " + t("Rolling back may require restarting '{svc}'.", { svc: cp.restart_service })));
    }
    body.append(el("div", { class: "row" },
      el("button", { onclick: () => rollback(cp) }, t("Roll back"))));
  } else {
    // Exec fixes back up no files, so there is nothing to restore. Show
    // what ran instead of a button that would lead nowhere.
    if (cp.commands) body.append(cmdList(cp.commands));
    body.append(el("p", { class: "empty" },
      t("This fix ran a command and edited no file, so there is nothing to restore automatically. Undo it by hand if you need to.")));
  }

  return el("div", { class: "fixbox" },
    el("div", { class: "fixbox-head" }, `${when}  ·  ${cp.finding_id}  ·  ${tr(cp.label)}`),
    body);
}

async function rollback(cp, force = false) {
  if (!force) {
    const ok = await confirmModal(t("Roll back \"{label}\"?", { label: tr(cp.label) }),
      t("This restores the original file as it was before the fix was applied."), t("Roll back"));
    if (!ok) return;
  }
  try {
    const o = await api("/api/rollback", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ checkpoint_id: cp.id, force }),
    });
    const n = o.restored_files ? o.restored_files.length : 0;
    showOutcomeModal(t("Rolled back"), {
      new_score: o.new_score,
      restart_hint: o.restart_service,
      verify_message: n === 1 ? t("Restored {n} file.", { n }) : t("Restored {n} files.", { n }),
    });
    await refresh();
    await showHistory();
  } catch (e) {
    // 409 is the engine declining: the file changed after
    // Hostveil wrote it, so restoring the backup would discard whatever
    // was done in between. Rollback keeps no checkpoint of its own, so
    // say that and make the override a second, informed answer.
    if (e.status === 409) {
      const ok = await confirmModal(t("Overwrite it anyway?"),
        tr(e.message) + " " + t("This restores Hostveil's backup over the current file and discards those changes. Rollback writes no checkpoint of its own, so this cannot be undone."),
        t("Overwrite"));
      if (ok) await rollback(cp, true);
      return;
    }
    flash(t("Rollback failed: {err}", { err: e.message }), true);
  }
}

async function refresh() { report = await api("/api/result"); render(); }

// refreshTrend is called on load and after a rescan, never after a fix: a
// fix changes the live score and leaves the saved scans alone.
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
  // A click that lands on the <dialog> itself, outside modal-body's
  // content, is a click on the ::backdrop. A <dialog> has no other way to
  // tell the two apart.
  if (e.target === e.currentTarget && !e.currentTarget.hasAttribute("data-busy")) closeModal();
});

// showOutcomeModal renders one fix's or one rollback's result (score,
// restart hint, verify message, checkpoint id) as a modal with a Done
// button, instead of compressing it into a one-line toast that disappears
// in six seconds. o is either a model.FixOutcome or the shape rollback()
// below builds to match it.
function showOutcomeModal(title, o) {
  const lines = [];
  if (o.new_score) lines.push(el("p", {}, t("Score: {n}/100", { n: o.new_score.overall })));
  if (o.restart_hint) lines.push(el("p", { class: "warn" }, t("Restart '{svc}' for it to take effect.", { svc: o.restart_hint })));
  if (o.verify_message) lines.push(el("p", {}, tr(o.verify_message)));
  if (o.checkpoint_id) lines.push(el("p", { class: "meta" }, t("Rollback checkpoint: {id}", { id: o.checkpoint_id })));
  const done = el("button", { class: "primary" }, t("Done"));
  done.onclick = closeModal;
  openModal(el("div", {}, el("h3", {}, title), ...lines, el("div", { class: "row" }, done)));
}

// confirmModal replaces window.confirm() with the same modal every other
// dialog in this file uses: a native confirm() looks like the browser
// interrupting the page, and it can't
// carry more than one line of plain text. Resolves true on the confirm
// button, false on Cancel *or* on any other way the dialog closes (Escape,
// a click on the backdrop): a dismissal is a "no" here the same way it is
// for a native confirm().
function confirmModal(title, message, confirmLabel = t("Confirm")) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
      closeModal();
    };
    const yes = el("button", { class: "primary", onclick: () => finish(true) }, confirmLabel);
    const no = el("button", { onclick: () => finish(false) }, t("Cancel"));
    openModal(el("div", {}, el("h3", {}, title), el("p", {}, message), el("div", { class: "row" }, yes, no)));
    document.getElementById("modal").addEventListener("close", () => finish(false), { once: true });
  });
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
    // Per browser: the server's theme stays whatever Hostveil
    // was started with, so two people reading the same dashboard can each
    // have their own.
    try { localStorage.setItem("hostveil.theme", sel.value); } catch (e) { /* private mode */ }
  };
}

// ── sort control ───────────────────────────────────────────────────────
// Lives in the findings pane's own header: it is a list-scoped choice. Same read-then-write pattern as the
// theme picker, minus the localStorage: a sort choice is about what
// you are looking at right now, so it is not remembered across sessions.
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
initSortPicker();

document.getElementById("history").onclick = showHistory;
document.getElementById("advise").onclick = showAdvise;

// Export opens a modal to choose the format, then downloads /api/export as
// a file: the route can answer 409 (no scan
// yet) or 400 (bad format), and a plain <a href> navigation on an error
// response would replace this whole page with a blank error document
// instead of leaving flash() to say what happened.
//
// The format list used to be a second <select> beside this button, styled
// like nothing else in the bar (app.css had rules for #theme and
// none for it) and taking a second control to say one thing. exportFormats
// comes from /model.js (core.ExportFormats(), the same table the CLI's
// --format flag and the TUI's picker resolve against) so a sixth format
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
      return el("label", {}, input, " " + tr(f.label));
    })
  );
  const dl = el("button", { class: "primary" }, t("Download"));
  dl.onclick = () => whileBusy(dl, t("Exporting…"), async () => {
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
  openModal(el("div", {}, el("h3", {}, t("Export")), list, el("div", { class: "row" }, dl)));
};

// whileBusy disables a button for the duration of the work it starts, and
// reports a failure instead of leaving one unhandled.
//
// Both of these routes take minutes on a real host and the engine serialises
// them behind one mutex, so a second click does not run anything sooner: it
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
    flash(t("{action} failed: {err}", { action: original, err: e.message }), true);
  } finally {
    el.disabled = false;
    el.textContent = original;
  }
}

// A rescan is started and not awaited: the server answers 202 immediately and
// the scan runs in the background, so the page polls the status route and
// narrates which domains are still working instead of freezing a button
// for minutes. A 409 means a scan is already running: poll that one.
const rescanBtn = document.getElementById("rescan");
rescanBtn.onclick = () => whileBusy(rescanBtn, t("Rescanning…"), async () => {
  marked.clear();
  const res = await fetch("/api/rescan", { method: "POST", headers: { "Content-Type": "application/json" } });
  if (!res.ok && res.status !== 409) throw new Error((await res.text()) || res.statusText);
  await watchScan(t("Rescanning"));
  flash(t("Rescan complete."));
});

// scanStartedAt is set once per poll loop (pollRescan) and read by
// renderScanProgress for the elapsed clock. Module-level because whileBusy/watchScan/pollRescan's call chain has no
// natural place to thread it through, and there is only ever one scan
// running at a time (the engine serialises scan/apply/rollback behind one
// mutex, so a second poll loop can never overlap this one).
let scanStartedAt = null;

// formatElapsed mirrors the TUI's clock: seconds under a minute, minutes and
// seconds after. No ETA anywhere near this: most domains finish in well
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
// wording (internal/ui/tui/view.go's scanDomainRow). SCAN[state].name is
// the stable wire name ("degraded"), and a reader wants "partial".
function scanStateWord(state) {
  switch (state) {
    case "running": return t("scanning…");
    case "done": return t("done");
    case "skipped": return t("skipped");
    case "degraded": return t("partial");
    case "error": return t("failed");
    default: return t("waiting"); // pending, or a state this page has never seen
  }
}

// scanStateClass picks up colors this file already assigns the same states
// elsewhere (.dom-err is --crit, .axis.partial is --med), so there is no
// fourth place these four colors get decided.
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
// domains is /api/rescan/status's own array: every domain that has
// reported at least once, in no particular order, some of them possibly
// absent (not yet started). The full roster comes from SRC (the model's own
// domain table, already loaded for the filter chips), so an absent domain
// reads as "waiting": the same thing
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
  // At least one segment lit as soon as real progress exists; an empty bar
  // reads as "stuck", not "just started", the same reason the TUI's own
  // meter (meterAtLeastOne) guarantees the same floor.
  const bar = meter(done > 0 ? Math.max(pct, 100 / total) : pct, "b-safe");
  document.getElementById("axes").replaceChildren(
    el("div", { class: "scan-status" },
      el("span", {}, t("{verb}… {done} of {total} domains", { verb, done, total })),
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
    el("li", { class: "clean muted" }, t("Scanning the host…"))
  );
}

// pollRescan resolves when the running scan finishes, rendering the
// per-domain progress roughly once a second (and once immediately, before
// the first poll response, so there is never a blank frame). verb is what
// the progress view calls the scan in progress: "Rescanning" from the
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

// watchScan waits out a running scan and then reloads everything it moved:
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
  const ok = await confirmModal(t("Apply every safe fix?"),
    t("Every Auto finding is applied now. Each is previewed and backed up first, and reversible from History."),
    t("Fix all safe"));
  if (!ok) return;
  const findings = active(report.findings).filter(isAuto)
    .map((f) => ({ id: f.id, service: f.service || "", title: ft(f, "title") }));
  applyMany(findings, t("Fixing"));
};

// boot loads the page for the first time. Hostveil's own first scan is now
// asynchronous (ListenAndServe opens the listener before it finishes), so
// the very first page load can land while it is still running: the same
// state a rescan puts the page in, and answered the same way: disable the
// buttons that would race it, narrate it, then load the result it produced.
//
// The status check and the result both fire at once. The ordinary case (a page opened long after the only scan
// there has ever been) needs both regardless, so making the second wait on
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
    await watchScan(t("Scanning"));
  } finally {
    rescanBtn.disabled = false;
    fixallBtn.disabled = false;
  }
}

// The catalog loads first: the first frame is drawn in the reader's language.
loadCatalog()
  .then(() => { initLangPicker(); return boot(); })
  .catch((e) => flash(t("Failed to load: {err}", { err: e.message }), true));
