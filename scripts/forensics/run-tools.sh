#!/usr/bin/env bash
# Run every tool under comparison on the testbed VM, one at a time, and
# record for each: its output, how long it took, and which host files
# changed while it ran (its footprint). Run as root.
#
#   run-tools.sh LABEL [TOOLS...]      default tools: triage rkhunter chkrootkit lynis uac
#
# Results go to /root/results/LABEL/<tool>/.
set -Euo pipefail
label=$1; shift
tools=("$@")
[[ ${#tools[@]} -gt 0 ]] || tools=(triage rkhunter chkrootkit lynis uac)
base=/root/results/$label
mkdir -p "$base"
HV=/fx/.bin/hostveil

footprint() {
  # Files under the host's own trees whose content or inode changed after
  # the marker. The tool's output directory is outside these trees.
  find /etc /usr /var /home /root /opt /srv -xdev \( -newer "$1" -o -cnewer "$1" \) -type f \
       -not -path '/root/results/*' -not -path '/root/marker-*' 2>/dev/null | sort
}

for t in "${tools[@]}"; do
  out=$base/$t
  rm -rf "$out"; mkdir -p "$out"
  marker=/root/marker-$t
  touch "$marker"; sleep 1.1
  start=$(date +%s.%N)
  case $t in
    triage)
      HOSTVEIL_NO_SUDO=1 "$HV" triage --out "$out/bundle" --since 30d >"$out/stdout.txt" 2>"$out/stderr.txt"
      echo $? > "$out/exit" ;;
    rkhunter)
      rkhunter --check --sk --rwo --nocolors >"$out/stdout.txt" 2>"$out/stderr.txt"
      echo $? > "$out/exit" ;;
    chkrootkit)
      chkrootkit -q >"$out/stdout.txt" 2>"$out/stderr.txt"
      echo $? > "$out/exit" ;;
    lynis)
      lynis audit system --quick --no-colors --quiet >"$out/stdout.txt" 2>"$out/stderr.txt"
      echo $? > "$out/exit"
      cp /var/log/lynis-report.dat "$out/report.dat" 2>/dev/null ;;
    uac)
      mkdir -p "$out/collection"
      (cd /opt/uac && ./uac -p ir_triage "$out/collection") >"$out/stdout.txt" 2>"$out/stderr.txt"
      echo $? > "$out/exit" ;;
  esac
  end=$(date +%s.%N)
  footprint "$marker" > "$out/footprint.txt"
  du -sb "$out" | cut -f1 > "$out/output_bytes"
  python3 -c "print(round($end - $start, 2))" > "$out/seconds"
  echo "tool_done label=$label tool=$t seconds=$(cat "$out/seconds") exit=$(cat "$out/exit") changed=$(wc -l < "$out/footprint.txt")"
done
