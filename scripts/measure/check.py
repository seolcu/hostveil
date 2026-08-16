#!/usr/bin/env python3
"""Fail on the two claims in a measurement that are promises, not observations.

Everything else the harness records is an observation: Lynis publishes a new
release, a distribution changes a default, an image gets a new base, and the
number moves without any diff being responsible. A check that turns red for
those is a check somebody turns off within a month, and then the two claims
below stop being checked either.

So exactly two things fail here.

  Rollback restored every file the fixes changed. This is what makes editing
  an operator's server a reasonable thing to ask for, and it either holds or
  the feature is not what it says it is.

  hostveil's own score moved at all. Not by how much — that is a judgement
  about weighting and it is allowed to change. A run where nothing moved
  means the fixes did not apply, or the scan is no longer reading what the
  fixes wrote, and either way the harness measured nothing.

There is a third, quieter one: the fixes have to have changed a file. Without
it "every changed file was restored" is a statement about the empty set and
passes on a host where `fix --all` did nothing at all.

A control run has neither promise to make about rollback, because hostveil
changed nothing to roll back. It keeps exactly one, and it is the sharper of
the two: the score has to move when the host is hardened by somebody else's
standard. A score that only responds to hostveil's own fixes is measuring
hostveil, not the host, and that is the failure the control group exists to
detect.

Usage: check.py <measurement.json>
"""
import json
import sys


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    try:
        with open(sys.argv[1]) as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as err:
        print("measure: cannot read the measurement:", err, file=sys.stderr)
        return 2

    rollback = doc.get("rollback") or {}
    phases = doc.get("phases") or {}
    before = (phases.get("before") or {}).get("hostveil") or {}

    # Which phase the score is read from is the whole difference between the
    # two runs. "after" is the host with hostveil's own fixes on disk;
    # "controlled" is the host somebody else hardened. Keyed off the phase
    # that exists rather than off the profile string, so a run mislabelled
    # with -p cannot be checked against the wrong claim.
    control = "controlled" in phases
    later = "controlled" if control else "after"
    after = (phases.get(later) or {}).get("hostveil") or {}

    failures = []

    # Every rollback claim below belongs to a run that applied fixes. A
    # control run has none of them to make, and asserting them would fail it
    # for the thing that defines it.
    if not control:
        if not rollback.get("paths_changed_by_fixes"):
            failures.append(
                "fix --all changed none of the watched files, so nothing here was measured"
            )
        if rollback.get("paths_not_restored"):
            failures.append(
                "rollback did not restore: %s" % ", ".join(rollback["paths_not_restored"])
            )
        if rollback.get("paths_with_unobserved_before_state"):
            failures.append(
                "no before-state was recorded for: %s"
                % ", ".join(rollback["paths_with_unobserved_before_state"])
            )
        if failed := (doc.get("fixes") or {}).get("failed"):
            failures.append("fixes failed: %s" % ", ".join(failed))

    b, a = before.get("overall"), after.get("overall")
    if not isinstance(b, int) or not isinstance(a, int):
        failures.append("hostveil did not report a score in both phases: %r -> %r" % (b, a))
    elif a <= b:
        if control:
            failures.append(
                "hostveil's score did not respond to hardening it had no part in: %d -> %d"
                % (b, a)
            )
        else:
            failures.append("hostveil's own score did not improve: %d -> %d" % (b, a))

    summary = {"profile": "control" if control else "fixes", "score": [b, a]}
    if not control:
        summary.update(
            {
                "changed": rollback.get("paths_changed_by_fixes"),
                "restored": rollback.get("paths_restored_exactly"),
                "fidelity": rollback.get("fidelity"),
            }
        )
    print(json.dumps(summary))
    for line in failures:
        print("FAIL:", line, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
