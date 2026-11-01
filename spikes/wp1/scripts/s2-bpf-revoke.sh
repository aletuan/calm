#!/usr/bin/env bash
# Reverts s2-bpf-grant.sh.
source "$(dirname "$0")/lib.sh"; require_macos
GROUP=calm_spike_bpf
sudo chown root:wheel /dev/bpf*
sudo chmod 600 /dev/bpf*
if dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then sudo dseditgroup -o delete "$GROUP"; fi
log "Reverted:"; ls -l /dev/bpf* | head -3
