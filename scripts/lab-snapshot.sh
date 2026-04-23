#!/usr/bin/env bash
# scripts/lab-snapshot.sh
# Capture a textual snapshot of Hostveil TUI running in the lab

docker exec hostveil-lab-1 bash -c "cd src && cargo test generate_lab_snapshots -- --nocapture"
docker cp hostveil-lab-1:/workspace/src/lab_snapshots .
