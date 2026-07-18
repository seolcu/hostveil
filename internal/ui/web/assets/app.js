"use strict";

const SEV = ["critical", "high", "medium", "low"];
let report = null;
let selected = null; // {id, service}

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

function render() {
  const score = report.score;

  // Exposure gauge (the signature): SECURITY meter + score.
  document.getElementById("gauge").replaceChildren(
    el("span", { class: "gauge-label" }, "Security"),
    meter(score.overall, band(score.overall)),
    el("span", { class: "gauge-score", html: `${score.overall}<small>/100</small>` })
  );

  // Per-axis bars (short labels so they never crowd the meter).
  const AX = { container: "Container", ssh: "SSH", firewall: "Firewall", updates: "Updates", cve: "CVEs" };
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
  const items = active(report.findings);
  document.getElementById("findings-title").textContent = `Findings · ${items.length}`;
  if (items.length === 0) {
    list.replaceChildren(el("li", { class: "clean" }, "No problems found. Clean."));
    document.getElementById("detail").replaceChildren(el("p", { class: "empty" }, "Nothing to fix."));
    return;
  }
  items.sort((a, b) => a.severity - b.severity);
  list.replaceChildren(
    ...items.map((f) => {
      const li = el("li", { class: "finding " + rowSevClass(f) },
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
  report = await api("/api/rescan", { method: "POST", headers: { "Content-Type": "application/json" } });
  render();
  flash("Rescan complete.");
};

document.getElementById("fixall").onclick = async () => {
  if (!confirm("Apply every safe (Auto) fix now?")) return;
  try {
    const o = await api("/api/fix/all", { method: "POST", headers: { "Content-Type": "application/json" } });
    flash(`Applied ${o.applied ? o.applied.length : 0} fixes. Score ${o.new_score.overall}/100.`);
    await refresh();
  } catch (e) { flash("Batch fix failed: " + e.message, true); }
};

refresh().catch((e) => flash("Failed to load: " + e.message, true));
