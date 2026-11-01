#!/usr/bin/env bash
# Grants the current user read access to /dev/bpf* through the group `calm_bpf`,
# so Calm can capture packet headers WITHOUT running as root (WP1 S2, ADR-005).
# Same approach as Wireshark's ChmodBPF. Needs an admin password once.
#
#   scripts/bpf-access.sh install     create group, add you, install boot-time daemon, apply now
#   scripts/bpf-access.sh status      show group membership, daemon and device permissions
#   scripts/bpf-access.sh uninstall   remove daemon and group, restore root:wheel 600
#
# Security note: while installed, ANY process you run can read network traffic
# on any interface. Uninstall when you no longer need capture. A narrower
# SMAppService helper is planned before a distributed release.
set -euo pipefail

GROUP="calm_bpf"
LABEL="com.aletuan.calm.bpf-access"
SUPPORT="/Library/Application Support/Calm"
APPLY="$SUPPORT/bpf-access-apply.sh"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
TARGET_USER="${SUDO_USER:-$USER}"

[[ "$(uname -s)" == "Darwin" ]] || { echo "macOS only" >&2; exit 1; }

say() { printf '==> %s\n' "$*"; }

status() {
  say "Group $GROUP"
  if dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
    echo "   exists; members: $(dscl . -read "/Groups/$GROUP" GroupMembership 2>/dev/null | cut -d: -f2- | xargs || echo none)"
  else
    echo "   missing"
  fi
  say "User $TARGET_USER in $GROUP: $(id -Gn "$TARGET_USER" | tr ' ' '\n' | grep -qx "$GROUP" && echo yes || echo no)"
  say "Daemon $LABEL: $([[ -f "$PLIST" ]] && echo installed || echo not installed)"
  say "Devices"
  ls -l /dev/bpf* | head -6
  echo "   ($(ls /dev/bpf* | wc -l | tr -d ' ') devices)"
}

install() {
  say "Creating group $GROUP (if missing) and adding $TARGET_USER"
  if ! dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
    sudo dseditgroup -o create -r "Calm packet capture (BPF read access)" "$GROUP"
  fi
  sudo dseditgroup -o edit -a "$TARGET_USER" -t user "$GROUP"

  say "Installing boot-time apply script and LaunchDaemon"
  sudo mkdir -p "$SUPPORT"
  sudo tee "$APPLY" >/dev/null <<EOF
#!/bin/sh
# Installed by Calm scripts/bpf-access.sh — re-applies BPF group read access.
# /dev is rebuilt at boot and new BPF devices are cloned as root:wheel 600,
# so this runs at load and every 5 minutes.
/usr/bin/chgrp $GROUP /dev/bpf* 2>/dev/null
/bin/chmod g+rw /dev/bpf* 2>/dev/null
exit 0
EOF
  sudo chown root:wheel "$APPLY"
  sudo chmod 755 "$APPLY"

  sudo tee "$PLIST" >/dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$APPLY</string></array>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>300</integer>
</dict></plist>
EOF
  sudo chown root:wheel "$PLIST"
  sudo chmod 644 "$PLIST"
  sudo launchctl bootout system "$PLIST" 2>/dev/null || true
  sudo launchctl bootstrap system "$PLIST"

  say "Applying now"
  sudo "$APPLY"
  status
  echo
  echo "Done. If Calm is open, press Retry on the Traffic screen (restart Calm if it still says permission denied)."
  echo "macOS may show a 'Background Items Added' notification for $LABEL."
}

uninstall() {
  say "Removing daemon"
  sudo launchctl bootout system "$PLIST" 2>/dev/null || true
  sudo rm -f "$PLIST" "$APPLY"
  sudo rmdir "$SUPPORT" 2>/dev/null || true
  say "Restoring /dev/bpf* to root:wheel 600"
  sudo chown root:wheel /dev/bpf*
  sudo chmod 600 /dev/bpf*
  if dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
    say "Deleting group $GROUP"
    sudo dseditgroup -o delete "$GROUP"
  fi
  status
}

case "${1:-status}" in
  install) install ;;
  uninstall) uninstall ;;
  status) status ;;
  *) echo "usage: $0 install|status|uninstall" >&2; exit 2 ;;
esac
