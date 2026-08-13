#!/usr/bin/env python3
"""Assemble one measurement run into the JSON that gets committed.

run.sh leaves every phase and every hash table in a working directory; this
turns that pile into a document. It is a separate file rather than a heredoc
because the rollback comparison is the part of the harness most easily got
subtly wrong, and a heredoc cannot be read on its own or tested.

Usage: report.py <workdir> <profile>
"""
import datetime
import json
import os
import subprocess
import sys

ABSENT = "ABSENT"


def read_json(path):
    """A phase file that is missing or unparseable is reported, not dropped."""
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError) as err:
        return {"error": str(err)}


def read_hashes(path):
    """path -> sha256 hex, or ABSENT for a path that does not exist."""
    out = {}
    try:
        with open(path) as fh:
            for line in fh:
                digest, _, name = line.strip().partition("  ")
                if name:
                    out[name] = digest
    except OSError:
        pass
    return out


def read_lines(path):
    try:
        with open(path) as fh:
            return [ln.strip() for ln in fh if ln.strip()]
    except OSError:
        return []


def first_int(path):
    """The single number a counting subcommand printed, or 0."""
    lines = read_lines(path)
    try:
        return int(lines[0])
    except (IndexError, ValueError):
        return 0


def host():
    out = {}
    try:
        with open("/etc/os-release") as fh:
            for line in fh:
                key, _, value = line.strip().partition("=")
                if key in ("ID", "VERSION_ID", "PRETTY_NAME"):
                    out[key.lower()] = value.strip('"')
    except OSError:
        pass
    out["kernel"] = os.uname().release
    return out


def rollback_verdict(work):
    """Did undoing every fix put the watched paths back byte for byte?

    Three tables: before the fixes, after them, and after the rollback. The
    before table is the authority — it was taken off the live filesystem
    before hostveil wrote anything, which is the only reading a checkpoint
    cannot influence.

    A path that only appears after the fixes ran is a file a fix created.
    Whether its absence beforehand is *known* depends on where it lives: the
    directories run.sh enumerates whole were listed entry by entry, so a name
    missing from that listing was genuinely not there. Anywhere else, the
    before-state was never observed, and the run says so instead of assuming
    it.
    """
    before = read_hashes(os.path.join(work, "hash.before"))
    after = read_hashes(os.path.join(work, "hash.after"))
    restored = read_hashes(os.path.join(work, "hash.restored"))
    enumerated = tuple(read_lines(os.path.join(work, "dirs")))

    changed, restored_ok, not_restored, unknown_before = [], [], [], []
    for path in sorted(after):
        if path in before:
            was = before[path]
        elif enumerated and path.startswith(tuple(d.rstrip("/") + "/" for d in enumerated)):
            was = ABSENT  # the directory was listed whole; it was not there
        else:
            unknown_before.append(path)
            continue
        if after[path] == was:
            continue  # the fixes did not touch this one
        changed.append(path)
        (restored_ok if restored.get(path, ABSENT) == was else not_restored).append(path)

    return {
        "paths_watched": len(set(before) | set(after)),
        "paths_changed_by_fixes": len(changed),
        "paths_restored_exactly": len(restored_ok),
        "paths_not_restored": not_restored,
        "paths_with_unobserved_before_state": unknown_before,
        "fidelity": (round(100 * len(restored_ok) / len(changed)) if changed else None),
        "checkpoints_before": first_int(os.path.join(work, "checkpoints.before")),
        "checkpoints_rolled_back": first_int(os.path.join(work, "undone")),
        "changed": changed,
    }


# The identifier sets each instrument reports, and where to find them.
#
# A count is not evidence — one check clearing while another appears leaves
# the total where it was — so the report diffs the sets and says which
# identifiers left and which arrived.
#
# The labels carry no dots. The documentation test addresses a figure in this
# document by dotted path, so a key containing one would be unreachable from
# the page that publishes it.
SETS = [
    ("lynis_suggestions", "lynis", "suggestion_ids"),
    ("lynis_warnings", "lynis", "warning_ids"),
    ("docker_bench_warnings", "docker_bench", "warn_ids"),
    ("external_scan_reachable_tcp", "external_scan", "reachable_tcp"),
    ("listeners_public_tcp", "listeners", "wildcard_or_routable_tcp"),
]


def deltas(phases):
    """What moved, per instrument, against the before-state.

    Both comparisons are reported because they answer different questions.
    `after` is the host with the files changed and nothing restarted, which
    is exactly what `hostveil fix --all` leaves behind. `restarted` is the
    same host once the services have read those files. An instrument that
    moves only in the second column is not a fix that failed — it is a fix
    that is not in force yet, and the difference is the single most useful
    thing this harness has to say.
    """
    out = {}
    for label, instrument, field in SETS:
        base = phases["before"].get(instrument, {})
        if not isinstance(base.get(field), list):
            continue
        before = set(base[field])
        row = {"before": len(before)}
        for phase in ("after", "restarted", "reviewed"):
            values = phases[phase].get(instrument, {}).get(field)
            if not isinstance(values, list):
                continue
            now = set(values)
            row[phase] = {
                "cleared": sorted(before - now),
                "appeared": sorted(now - before),
                "total": len(now),
            }
        out[label] = row
    return out


def fix_phase(work):
    """What `fix --all --yes` said it did.

    Read out of the CLI's own output rather than counted from checkpoints,
    because a fix that failed leaves no checkpoint and would otherwise not
    appear anywhere in the report at all.
    """
    lines = read_lines(os.path.join(work, "fix.log"))
    attempted, failed = 0, []
    for line in lines:
        if line.startswith("Will apply ") and "fixes" in line:
            try:
                attempted = int(line.split()[2])
            except (IndexError, ValueError):
                pass
        elif line.startswith("✗ "):
            failed.append(line[2:])
    return {"attempted": attempted, "failed": failed}


def version():
    try:
        return subprocess.run(
            ["hostveil", "version"], capture_output=True, text=True, check=False
        ).stdout.strip()
    except OSError:
        return ""


# Where seed.sh records what it was able to make true of this host.
SEED_MANIFEST = os.environ.get(
    "SEED_MANIFEST", "/var/lib/hostveil-measure/seeded.json"
)


def seeded_manifest():
    """What the fixture managed to seed, and what this distribution could not.

    The measurement is only comparable across distributions if the host means
    the same thing on each, and it cannot always: Alpine ships no
    unattended-upgrade mechanism, so there is no "automatic updates are off"
    weakness there to find. The updates axis then reads better on Alpine for a
    reason that has nothing to do with hostveil.

    Publishing the score without saying so would be the same mistake the
    scanner itself is built against — an absence read as an all-clear — so the
    manifest travels with the numbers rather than living in somebody's memory
    of how the host was built.

    A run on a host seeded by an older copy of seed.sh has no manifest, and
    that is reported as absent rather than as an empty one: "nothing was
    recorded" and "nothing was missing" are the two readings this whole
    harness exists to keep apart.
    """
    if not os.path.exists(SEED_MANIFEST):
        return {"error": "no seed manifest at " + SEED_MANIFEST}
    return read_json(SEED_MANIFEST)


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    work, profile = sys.argv[1], sys.argv[2]

    phases = {}
    for phase in ("before", "after", "restarted", "reviewed", "restored"):
        phases[phase] = {
            "hostveil": read_json(os.path.join(work, phase + ".hostveil.json")),
            "lynis": read_json(os.path.join(work, phase + ".lynis.json")),
            "docker_bench": read_json(os.path.join(work, phase + ".dockerbench.json")),
            "external_scan": read_json(os.path.join(work, phase + ".extscan.json")),
            "listeners": read_json(os.path.join(work, phase + ".listeners.json")),
        }

    doc = {
        "profile": profile,
        "seeded": seeded_manifest(),
        "measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "host": host(),
        "hostveil_version": version(),
        "phases": phases,
        "fixes": fix_phase(work),
        "reviewed": read_json(os.path.join(work, "reviewed.json")),
        "deltas": deltas(phases),
        "rollback": rollback_verdict(work),
    }
    json.dump(doc, sys.stdout, indent=2, sort_keys=False)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
