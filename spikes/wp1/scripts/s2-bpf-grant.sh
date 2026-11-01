#!/usr/bin/env bash
# Temporary ChmodBPF-style grant (what Wireshark's ChmodBPF daemon does at boot):
# group calm_spike_bpf gets rw on /dev/bpf*. Not persistent — /dev resets on reboot.
# Revert with s2-bpf-revoke.sh. Requires admin password.
source "$(dirname "$0")/lib.sh"; require_macos
GROUP=calm_spike_bpf
log "Before:"; ls -l /dev/bpf* | head -3
if ! dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
  sudo dseditgroup -o create -r "Calm WP1 spike BPF access" "$GROUP"
fi
sudo dseditgroup -o edit -a "$USER" -t user "$GROUP"
sudo chgrp "$GROUP" /dev/bpf*
sudo chmod g+rw /dev/bpf*
log "After:"; ls -l /dev/bpf* | head -3
log "Membership check (if your shell does not list $GROUP, open a NEW Terminal window — record whether that was needed):"
id -Gn
