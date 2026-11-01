#!/usr/bin/env bash
# Runs the S1 matrix. You will see up to two Location prompts: answer "Allow" (or "Don't Allow"
# to test the denied path — say which in your report).
source "$(dirname "$0")/lib.sh"; require_macos
OUT="$SPIKE_DIR/build"; EXTRA=(); [[ "${RAW:-0}" == "1" ]] && EXTRA=(--raw)
rm -f "$RESULTS"/s1-*.json "$RESULTS"/s1-*-finish.txt

log "1/3 Terminal-launched CLI (responsible process = Terminal)"
"$OUT/probe-cli" --variant terminal-cli --out-dir "$RESULTS" ${EXTRA[@]+"${EXTRA[@]}"} >/dev/null || true

log "2/3 ProbeApp via open (regular GUI app) — answer the Location prompt"
open -W -n "$OUT/ProbeApp.app" --args --variant app --out-dir "$RESULTS" ${EXTRA[@]+"${EXTRA[@]}"}

log "3/3 ProbeAgent via open (LSUIElement, no Dock icon) — answer the prompt if it appears"
open -W -n "$OUT/ProbeAgent.app" --args --variant agent --out-dir "$RESULTS" ${EXTRA[@]+"${EXTRA[@]}"}

log "Summary"
for f in "$RESULTS"/s1-*.json; do
  python3 - "$f" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
print(f"{r['variant']:<26} auth={r['authorization']:<20} iface={str(r['interfaceName']):<5} ssid={'YES' if r['ssid']['present'] else 'no ':<3} bssid={'YES' if r['bssid']['present'] else 'no ':<3} sec={r['security']} ch={r['channel']} rssi={r['rssi']}")
PY
done | tee "$RESULTS/s1-summary.txt"
cat "$RESULTS"/s1-*-finish.txt 2>/dev/null || true
