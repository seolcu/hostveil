# Forensics testbed

Measures the forensic-readiness domain (`forensic.*`) and `hostveil triage`
against tools that already exist, on a throwaway Ubuntu 24.04 web server.

```bash
./run.sh up      # cross-compile hostveil, boot + provision the VM, snapshot "clean"
./run.sh e1      # experiment 1: detection, false positives, time, footprint
./run.sh e2      # experiment 2: what a stock vs. a readied host can still answer after a reboot
./run.sh score   # results/summary.json and results/summary.md
./run.sh destroy
```

Needs Vagrant with vagrant-libvirt and the `cloud-image/ubuntu-24.04` box,
and Go on the host.

## Experiment 1

`seed.sh all` plants the traces of six scenarios, eighteen elements in all,
listed with what each should be detected as in `truth.json`:

| | Scenario | Modelled on |
|---|---|---|
| S1 | Web scanning, one probe answered | ~36k 404 probes for `/.env`, `/.git/config` on a public wiki |
| S2 | A PHP file in the upload directory runs a command as www-data | a PHP remote-code-execution disclosure the same wiki was exposed to for six days |
| S3 | SSH password guessing, then a success; a key added, used, removed | ~13.6k guesses against a forwarded SSH port |
| S4 | Persistence: cron, a systemd unit, ld.so.preload, a setuid file, a second UID 0 account, a program in /dev/shm | standard post-exploitation persistence |
| S5 | One client bulk-downloading every export | a register-then-export probe against the wiki |
| S6 | Anti-forensics: history to /dev/null, wtmp emptied, a backdated file, a modified package file | covering tracks |

The traces are inert. Log lines are written with `logger` exactly as sshd
writes them; the cron file's name has a dot, which cron ignores; the unit is
never enabled; the preloaded library is an ordinary system one; the setuid
file is a copy of `/bin/true`; the extra UID 0 account is locked with no
shell. What is measured is whether each tool *finds the trace*, which does
not need the attack to have worked.

Every tool runs on the clean VM (false positives) and on the seeded one
(detection). rkhunter's file-property baseline is recorded on the clean VM
first, as it is meant to be. UAC is a collector and makes no judgement; it
is in the comparison for time, output size and footprint.

**Footprint** is the set of host files whose content or inode changed while
a tool ran, from `find -newer/-cnewer` against a marker, minus the system's
own logging and timers (the `NOISE` list in `score.py`, which prints what it
excluded).

## Experiment 2

Two arms from the same clean snapshot: the stock VM, and the VM after
`readiness.sh` applies every forensic.* fix hostveil offers plus the two
Manual steps one host can carry out (installing auditd, adding `%I %D` to
the Apache log format). Each arm gets the S2 + S3 scenarios, is rebooted,
and is triaged. `score.py` asks ten investigation questions of each bundle
and counts how many the evidence answers.
