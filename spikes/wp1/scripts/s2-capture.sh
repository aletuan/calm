#!/usr/bin/env bash
# S2 capture matrix. Each run: 30 s, headers only (snaplen 96), payload never stored.
#   STEP=unpriv  -> as you, before any grant      (expect: open fails, permission denied)
#   STEP=sudo    -> via sudo                       (baseline: what root gets)
#   STEP=group   -> as you, after s2-bpf-grant.sh  (ChmodBPF-style group access)
# LOAD=1 adds a ~200 MB download in parallel so pps/drops are measured under load.
source "$(dirname "$0")/lib.sh"; require_macos
STEP="${STEP:?set STEP=unpriv|sudo|group}"
WIFI_IF="$(networksetup -listallhardwareports | awk '/Hardware Port: (Wi-Fi|AirPort)/{getline; print $2; exit}')"
WIFI_IF="${WIFI_IF:-en0}"
BIN="$SPIKE_DIR/bpf-probe/target/release/bpf-probe"
[[ -x "$BIN" ]] || { log "cargo build --release (bpf-probe)"; cargo build --release --manifest-path "$SPIKE_DIR/bpf-probe/Cargo.toml"; }

LABEL="$STEP$([[ ${LOAD:-0} == 1 ]] && echo -load)"
if [[ "${LOAD:-0}" == "1" ]]; then
  # Repeat 25 MB downloads for the whole capture window and record what was actually
  # transferred, so a silently failing load cannot masquerade as a load test.
  LOADLOG="$RESULTS/s2-load-$LABEL.txt"; : > "$LOADLOG"
  log "Background load: repeated 25 MB downloads for 30 s -> $LOADLOG"
  (
    end=$((SECONDS + 30))
    while (( SECONDS < end )); do
      curl -sS -m 30 -o /dev/null -w '%{http_code} %{size_download} %{speed_download}\n' \
        "https://speed.cloudflare.com/__down?bytes=25000000" >> "$LOADLOG" 2>&1 || echo "curl_failed" >> "$LOADLOG"
    done
  ) &
fi

log "STEP=$STEP iface=$WIFI_IF groups=$(id -Gn | tr ' ' ',')"
log "BPF perms: $(ls -l /dev/bpf0 2>/dev/null)"
case "$STEP" in
  sudo) sudo "$BIN" --iface "$WIFI_IF" --secs 30 --label "$LABEL" ;;
  *)         "$BIN" --iface "$WIFI_IF" --secs 30 --label "$LABEL" ;;
esac 2>&1 | tee -a "$RESULTS/s2-capture.jsonl" || true
wait 2>/dev/null || true
if [[ "${LOAD:-0}" == "1" ]]; then
  total=$(awk '$1 ~ /^[0-9]+$/ {s+=$2} END {print s+0}' "$LOADLOG")
  log "Load transferred: $total bytes ($(awk -v b="$total" 'BEGIN{printf "%.1f", b*8/30/1e6}') Mbps avg)"
  echo "{\"label\":\"$LABEL-loadcheck\",\"downloaded_bytes\":$total}" >> "$RESULTS/s2-capture.jsonl"
  (( total > 10000000 )) || warn "Load < 10 MB — this run does NOT count as a load test. See $LOADLOG"
fi
