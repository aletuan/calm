#!/usr/bin/env bash
# S1b: Tauri app requests Location and reads CoreWLAN in its own Rust process.
#   (a) bundled .app signed by the Tauri CLI   -> how a built Calm behaves
#   (b) same binary run unbundled from Terminal -> how `pnpm dev` / `tauri dev` behaves
source "$(dirname "$0")/lib.sh"; require_macos
APP_DIR="$SPIKE_DIR/tauri-wifi"
TAURI="$SPIKE_DIR/../../apps/desktop/node_modules/.bin/tauri"
[[ -x "$TAURI" ]] || { echo "Tauri CLI not found at $TAURI — run 'pnpm install' at the repo root first." >&2; exit 1; }
EXTRA=(); [[ "${RAW:-0}" == "1" ]] && EXTRA=(--raw)
rm -f "$RESULTS"/s1b-*

SIGN="$(pick_sign_id)"
log "Build bundle with Tauri CLI (debug), APPLE_SIGNING_IDENTITY=$SIGN"
( cd "$APP_DIR" && APPLE_SIGNING_IDENTITY="$SIGN" "$TAURI" build --debug --bundles app ) 2>&1 | tail -15
APP="$APP_DIR/target/debug/bundle/macos/CalmWifiSpike.app"
BIN="$APP_DIR/target/debug/calm-wifi-spike"
[[ -d "$APP" ]] || { echo "Bundle not produced: $APP" >&2; exit 1; }

{
  log "Signature as produced by Tauri"
  codesign -dv --verbose=2 "$APP" 2>&1 | grep -E 'Identifier|TeamIdentifier|flags|Authority=' | head -6
  log "Entitlements as produced by Tauri"
  codesign -d --entitlements - --xml "$APP" 2>/dev/null | plutil -convert xml1 -o - - 2>/dev/null | grep -A1 location || echo "(no location entitlement!)"
  log "Info.plist location keys"
  /usr/libexec/PlistBuddy -c "Print :NSLocationWhenInUseUsageDescription" "$APP/Contents/Info.plist" 2>&1
} | tee "$RESULTS/s1b-bundle-signature.txt"

log "(a) Bundled app via open — answer the Location prompt for 'CalmWifiSpike' with Allow"
open -W -n "$APP" --args --variant bundle --out-dir "$RESULTS" ${EXTRA[@]+"${EXTRA[@]}"}

log "(b) Same binary, unbundled, launched from this terminal (like 'tauri dev')"
log "    If a prompt appears naming your TERMINAL app, choose Don't Allow and note it. May wait up to 90 s."
"$BIN" --variant unbundled --out-dir "$RESULTS" ${EXTRA[@]+"${EXTRA[@]}"} >/dev/null 2>"$RESULTS/s1b-unbundled-stderr.txt" || true

log "Summary"
for f in "$RESULTS"/s1b-*.json; do
  python3 - "$f" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
print(f"{r['variant']:<24} auth={str(r['authorization']):<20} ssid={'YES' if r['ssid']['present'] else 'no ':<3} bssid={'YES' if r['bssid']['present'] else 'no ':<3} rssi={r['rssi']} finish={r.get('finish_reason','-')}")
PY
done | tee "$RESULTS/s1b-summary.txt"
grep -i -E 'location|usage|authoriz' "$RESULTS/s1b-unbundled-stderr.txt" | head -5 || true
