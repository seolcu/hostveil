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
    else e.setAttribute(k, v);
  }
  for (const kid of kids) e.append(kid);
  return e;
}

function active(findings) {
  return findings.filter((f) => !f.fixed);
}

function render() {
  const score = report.score;
  document.getElementById("score").innerHTML =
    `${score.overall}<small>/100</small>`;

  const axes = document.getElementById("axes");
  axes.replaceChildren(
    ...score.axes.map((ax) =>
      el("span", { class: ax.applicable ? "" : "na" },
        ax.applicable ? `${ax.label}: ${ax.score}` : `${ax.label}: N/A`)
    )
  );

  const list = document.getElementById("findings");
  const items = active(report.findings);
  document.getElementById("findings-title").textContent = `Findings (${items.length})`;
  if (items.length === 0) {
    list.replaceChildren(el("li", { class: "clean" }, "No problems found. Clean."));
    document.getElementById("detail").replaceChildren(
      el("p", { class: "empty" }, "Nothing to fix.")
    );
    return;
  }
  items.sort((a, b) => SEV.indexOf(a.severity_s || sevName(a)) - SEV.indexOf(b.severity_s || sevName(b)));
  list.replaceChildren(
    ...items.map((f) => {
      const li = el("li", { class: "finding" },
        el("span", { class: "badge " + sevName(f) }, sevName(f)),
        el("div", { class: "title" },
          el("div", {}, f.title),
          el("div", { class: "rem" }, f.id + " · " + remLabel(f.remediation))
        ),
        f.service ? el("span", { class: "svc" }, f.service) : ""
      );
      li.onclick = () => selectFinding(f, li);
      if (selected && selected.id === f.id && selected.service === f.service) li.classList.add("active");
      return li;
    })
  );
}

function sevName(f) { return SEV[f.severity] || "low"; }
function remLabel(r) { return ["Unclassified", "Auto-fix", "Review", "Manual", "Unavailable"][r] || "?"; }
function isFixable(f) { return f.remediation === 1 || f.remediation === 2; }

function selectFinding(f, li) {
  selected = { id: f.id, service: f.service };
  document.querySelectorAll(".finding").forEach((n) => n.classList.remove("active"));
  li.classList.add("active");
  const d = document.getElementById("detail");
  d.replaceChildren(
    el("h3", {}, f.title),
    el("div", { class: "meta" }, `${f.id}   ${remLabel(f.remediation)}${f.service ? "   service: " + f.service : ""}`),
    el("p", {}, f.description || ""),
    f.how_to_fix ? el("p", {}, el("strong", {}, "How to fix: "), f.how_to_fix) : ""
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
  const render = () => {
    const a = p.actions[chosen];
    box.replaceChildren(
      el("strong", {}, p.label),
      p.actions.length > 1 ? altPicker(p, chosen, (i) => { chosen = i; render(); }) : "",
      a.warning ? el("div", { class: "warn" }, "⚠ " + a.warning) : "",
      a.type === "edit" ? diffPre(a.diff) : cmdList(a.commands),
      el("div", {},
        el("button", { class: "primary", onclick: () => applyFix(f, chosen) }, "Apply"),
        " ",
        el("button", { onclick: () => selectFinding(f, document.querySelector(".finding.active")) }, "Cancel")
      )
    );
  };
  render();
  document.getElementById("detail").append(box);
}

function altPicker(p, chosen, onpick) {
  return el("div", { class: "alts" },
    ...p.actions.map((a, i) => {
      const l = el("label", {},
        Object.assign(document.createElement("input"), {
          type: "radio", name: "alt", checked: i === chosen, onchange: () => onpick(i),
        }),
        " " + a.label
      );
      return l;
    })
  );
}

function diffPre(diff) {
  const pre = el("pre", { class: "diff" });
  (diff || "").split("\n").forEach((line) => {
    let cls = "";
    if (line.startsWith("+") && !line.startsWith("+++")) cls = "add";
    else if (line.startsWith("-") && !line.startsWith("---")) cls = "del";
    pre.append(el("span", { class: cls }, line + "\n"));
  });
  return pre;
}

function cmdList(cmds) {
  const pre = el("pre", { class: "diff" });
  (cmds || []).forEach((c) => pre.append("$ " + c.join(" ") + "\n"));
  return pre;
}

async function applyFix(f, action) {
  try {
    const o = await api("/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: f.id, service: f.service || "", action }),
    });
    flash(`Fix applied. New score ${o.new_score.overall}/100.` +
      (o.checkpoint_id ? ` Rollback id: ${o.checkpoint_id}` : ""));
    await refresh();
  } catch (e) { flash("Fix failed: " + e.message, true); }
}

async function refresh() {
  report = await api("/api/result");
  render();
}

function flash(msg, isErr) {
  const s = document.getElementById("status");
  s.textContent = msg;
  s.style.color = isErr ? "var(--crit)" : "var(--ok)";
  s.hidden = false;
  setTimeout(() => (s.hidden = true), 6000);
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
    flash(`Applied ${o.applied ? o.applied.length : 0} fixes. New score ${o.new_score.overall}/100.`);
    await refresh();
  } catch (e) { flash("Batch fix failed: " + e.message, true); }
};

refresh().catch((e) => flash("Failed to load: " + e.message, true));
