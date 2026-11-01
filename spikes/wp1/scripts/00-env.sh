#!/usr/bin/env bash
# Collects environment facts that change spike conclusions. No network identifiers.
source "$(dirname "$0")/lib.sh"; require_macos
{
  log "macOS";            sw_vers
  log "Hardware";         uname -m; sysctl -n machdep.cpu.brand_string 2>/dev/null || true
  log "Toolchains";       xcode-select -p || true; swift --version 2>&1 | head -2 || true
                          rustc --version 2>/dev/null || echo "rustc: missing"; node --version 2>/dev/null || echo "node: missing"
  log "Code-signing identities (names only)"
  security find-identity -v -p codesigning 2>/dev/null | sed -E 's/^ *[0-9]+\) [0-9A-F]{40} //' || true
  log "SIP";              csrutil status 2>/dev/null || true
  log "BPF devices";      ls -l /dev/bpf* 2>/dev/null | head -5; echo "count: $(ls /dev/bpf* 2>/dev/null | wc -l | tr -d ' ')"
  sysctl debug.bpf_maxdevices 2>/dev/null || true
  log "Groups of $USER";  id -Gn
} 2>&1 | tee "$RESULTS/00-env.txt"
