#!/usr/bin/env python3
"""Score the forensics experiments in results/ against truth.json.

Writes results/summary.json (every number the paper quotes) and
results/summary.md (the same, as tables). Nothing is typed by hand: each
figure is computed here from the tools' own output.
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
TRUTH = json.load(open(os.path.join(HERE, "truth.json")))["elements"]
TOOLS = ["triage", "rkhunter", "chkrootkit", "lynis", "uac"]

# Files every run touches whatever the tool does: the system's own logging
# and timers. Excluded from the footprint, and listed so the exclusion is
# visible.
NOISE = [r"^/var/log/journal/", r"^/var/log/(syslog|auth\.log|kern\.log)$", r"^/var/log/apache2/",
         r"^/var/log/audit/", r"^/var/lib/systemd/", r"^/var/lib/rsyslog/", r"^/var/log/wtmp$",
         r"^/var/log/lastlog$", r"^/var/lib/logrotate/", r"^/var/log/sysstat/", r"^/var/cache/apparmor/",
         r"^/var/lib/apt/", r"^/var/cache/apt/", r"^/var/lib/update-notifier/", r"^/var/lib/ubuntu-advantage/",
         r"^/var/lib/snapd/", r"^/var/log/cloud-init", r"^/var/lib/cloud/", r"^/var/log/dpkg\.log$"]


def read(*p):
    try:
        with open(os.path.join(RES, *p), errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return None


def warnings(tool, label):
    """The tool's findings as a list of text blocks."""
    if tool == "rkhunter":
        out = read(label, tool, "stdout.txt") or ""
        blocks, cur = [], None
        for line in out.splitlines():
            if line.startswith("Warning:"):
                cur = [line]
                blocks.append(cur)
            elif cur is not None and line.startswith(" "):
                cur.append(line)
            else:
                cur = None
        return ["\n".join(b) for b in blocks]
    if tool == "chkrootkit":
        out = read(label, tool, "stdout.txt") or ""
        return [l for l in out.splitlines() if l.strip()]
    if tool == "lynis":
        out = read(label, tool, "report.dat") or ""
        return [l for l in out.splitlines() if l.startswith("warning[]=")]
    return []


def indicators(label):
    t = read(label, "triage", "bundle", "indicators.json")
    return json.loads(t)["indicators"] if t else []


def detect(tool, label):
    hits = {}
    if tool == "triage":
        ins = indicators(label)
        for e in TRUTH:
            m = [i for i in ins if i["id"] == e["triage"] and (not e["tokens"][0] or any(k and k in json.dumps(i) for k in e["tokens"]))]
            hits[e["id"]] = {"detected": bool(m), "verdict_ok": any(i["verdict"] == e["verdict"] for i in m)}
        return hits
    if tool == "uac":
        return {e["id"]: {"detected": None} for e in TRUTH}
    ws = warnings(tool, label)
    for e in TRUTH:
        hits[e["id"]] = {"detected": any(k and k in w for k in e["tokens"] for w in ws)}
    return hits


def footprint(label, tool):
    raw = (read(label, tool, "footprint.txt") or "").split()
    kept = [p for p in raw if not any(re.search(n, p) for n in NOISE)]
    return {"raw": len(raw), "attributable": len(kept), "files": kept[:40]}


def tool_row(tool):
    row = {"tool": tool}
    for label in ["e1-clean", "e1-attacked"]:
        sec = read(label, tool, "seconds")
        row[label] = {
            "seconds": float(sec) if sec else None,
            "exit": (read(label, tool, "exit") or "").strip(),
            "output_bytes": int(read(label, tool, "output_bytes") or 0),
            "footprint": footprint(label, tool),
        }
    det = detect(tool, "e1-attacked")
    row["detected"] = sum(1 for v in det.values() if v.get("detected"))
    row["per_element"] = det
    if tool == "triage":
        row["verdict_ok"] = sum(1 for v in det.values() if v.get("verdict_ok"))
        clean = indicators("e1-clean")
        row["clean_false_positives"] = {
            "compromise": [i["id"] for i in clean if i["verdict"] == "compromise"],
            "suspicious": [i["id"] for i in clean if i["verdict"] == "suspicious"],
            "attempt": [i["id"] for i in clean if i["verdict"] == "attempt"],
        }
        row["attacked_counts"] = {v: sum(1 for i in indicators("e1-attacked") if i["verdict"] == v)
                                  for v in ["compromise", "suspicious", "attempt"]}
    elif tool != "uac":
        row["clean_warnings"] = warnings(tool, "e1-clean")
        attacked = warnings(tool, "e1-attacked")
        tied = [w for w in attacked if any(k and k in w for e in TRUTH for k in e["tokens"])]
        row["attacked_warnings"] = len(attacked)
        row["attacked_untied_warnings"] = len(attacked) - len(tied)
    return row


def verify_bundles():
    """Re-hash each fetched bundle with the host binary, then tamper with a
    copy and check verify notices."""
    hv = os.path.join(HERE, ".bin", "hostveil")
    out = {}
    for label in ["e1-clean", "e1-attacked", "e2-default", "e2-ready"]:
        b = os.path.join(RES, label, "triage", "bundle")
        if not os.path.isdir(b):
            continue
        r = subprocess.run([hv, "triage", "verify", b], capture_output=True, text=True)
        out[label] = {"exit": r.returncode, "summary": r.stdout.strip().splitlines()[0] if r.stdout else ""}
    b = os.path.join(RES, "e1-attacked", "triage", "bundle")
    if os.path.isdir(b):
        t = os.path.join(RES, "tamper-copy")
        subprocess.run(["rm", "-rf", t])
        subprocess.run(["cp", "-a", b, t], check=True)
        victim = os.path.join(t, "artifacts", "files", "var", "log", "auth.log")
        os.chmod(victim, 0o600)
        with open(victim, "a") as f:
            f.write("x")
        r = subprocess.run([hv, "triage", "verify", t], capture_output=True, text=True)
        out["tampered"] = {"exit": r.returncode, "output": r.stdout.strip()}
        subprocess.run(["rm", "-rf", t])
    return out


# --- experiment 2 --------------------------------------------------------

def e2(label):
    base = os.path.join(RES, label, "triage", "bundle")
    if not os.path.isdir(base):
        return None
    res = json.load(open(os.path.join(base, "indicators.json")))
    ids = {i["id"] for i in res["indicators"]}
    gaps = {g.get("finding", "") for g in res["gaps"]}
    man = json.load(open(os.path.join(base, "manifest.json")))

    def art(name):
        return [a for a in man["artifacts"] if a["name"] == name]

    def text(a):
        p = os.path.join(base, a["path"])
        return open(p, errors="replace").read() if os.path.exists(p) else ""

    weblines = "".join(text(a) for a in art("web-log"))
    journal = "".join(text(a) for a in art("journal-sshd"))
    boots = "".join(text(a) for a in art("journal-boots"))
    q = {
        "Q1 Were there SSH password-guessing attempts?": "triage.login.guessing" in ids,
        "Q2 Did a login succeed from the guessing address?": "triage.login.after-guessing" in ids,
        "Q3 What did the web server's account execute?": "triage.audit.webuser-exec" in ids,
        "Q4 Was a script in the upload directory run?": "triage.web.script-in-upload-dir" in ids,
        "Q5 How large was each request (body size recorded)?": bool(re.search(r'" \d+ \d+\s*$', weblines, re.M)),
        "Q6 Does the journal still hold the pre-reboot SSH events?": "203.0.113.50" in journal,
        "Q7 Does the journal span more than one boot?": len([l for l in boots.splitlines() if l.strip()]) >= 2,
        "Q8 Are logs kept for 90 days?": not ({"forensic.logrotate-short", "forensic.journald-retention"} & gaps),
        "Q9 Can the log times be trusted (clock synchronised)?": "forensic.time-unsynced" not in gaps,
        "Q10 Is there a copy of the logs off the host?": "forensic.no-remote-log" not in gaps,
    }
    return {"answered": sum(q.values()), "questions": q, "gaps": sorted(g for g in gaps if g),
            "indicators": sorted(ids)}


def main():
    if not os.path.isdir(RES):
        sys.exit("no results/ yet")
    summary = {"tools": [tool_row(t) for t in TOOLS], "elements": TRUTH, "verify": verify_bundles(),
               "e2": {"default": e2("e2-default"), "ready": e2("e2-ready")}, "noise_excluded": NOISE}
    json.dump(summary, open(os.path.join(RES, "summary.json"), "w"), indent=2, ensure_ascii=False)

    md = ["# Forensics testbed results", "", "## Experiment 1: detection (18 planted traces)", "",
          "| Tool | Detected | Clean-host warnings | Seconds (attacked) | Output | Host files changed |", "|---|---|---|---|---|---|"]
    for r in summary["tools"]:
        a = r["e1-attacked"]
        if r["tool"] == "triage":
            fp = r["clean_false_positives"]
            clean = f'{len(fp["compromise"])} compromise, {len(fp["suspicious"])} suspicious'
        elif r["tool"] == "uac":
            clean = "n/a (collector)"
        else:
            clean = str(len(r["clean_warnings"]))
        det = "n/a" if r["tool"] == "uac" else f'{r["detected"]}/{len(TRUTH)}'
        md.append(f'| {r["tool"]} | {det} | {clean} | {a["seconds"]} | {a["output_bytes"]:,} B | {a["footprint"]["attributable"]} |')
    md += ["", "| Element | " + " | ".join(t for t in TOOLS if t != "uac") + " |", "|---" * 5 + "|"]
    for e in TRUTH:
        cells = []
        for r in summary["tools"]:
            if r["tool"] == "uac":
                continue
            v = r["per_element"][e["id"]]
            cells.append(("✓" if v["detected"] else "–") + ("" if r["tool"] != "triage" or v.get("verdict_ok") or not v["detected"] else " (verdict)"))
        md.append(f'| {e["id"]} {e["what"]} | ' + " | ".join(cells) + " |")
    md += ["", "## Bundle verification", "", "```", json.dumps(summary["verify"], indent=2, ensure_ascii=False), "```", "",
           "## Experiment 2: questions answerable from the bundle after a reboot", "",
           "| Question | Stock | Readied |", "|---|---|---|"]
    d, r = summary["e2"]["default"], summary["e2"]["ready"]
    if d and r:
        for k in d["questions"]:
            md.append(f'| {k} | {"✓" if d["questions"][k] else "–"} | {"✓" if r["questions"][k] else "–"} |')
        md.append(f'| **Answered** | **{d["answered"]}/10** | **{r["answered"]}/10** |')
    open(os.path.join(RES, "summary.md"), "w").write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
