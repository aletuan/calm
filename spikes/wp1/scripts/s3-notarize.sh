#!/usr/bin/env bash
# S3: Developer ID sign + notarize + staple ProbeApp, then check Gatekeeper.
# One-time prerequisites (the script checks and stops if missing):
#   1. "Developer ID Application: <name> (<TEAMID>)" certificate in login keychain
#      (Xcode > Settings > Accounts > Manage Certificates, Account Holder/Admin role).
#   2. Notary credentials stored as keychain profile "calm-notary", e.g. with an
#      App Store Connect API key:
#        xcrun notarytool store-credentials calm-notary --key AuthKey_XXXX.p8 --key-id XXXX --issuer <uuid>
source "$(dirname "$0")/lib.sh"; require_macos
DEVID="$(security find-identity -v -p codesigning | awk '/"Developer ID Application:/{print $2; exit}')"
[[ -n "$DEVID" ]] || { echo "MISSING: Developer ID Application certificate. Stop here and report." | tee "$RESULTS/s3-notarize.txt"; exit 1; }
xcrun notarytool history --keychain-profile calm-notary >/dev/null 2>&1 \
  || { echo "MISSING: notarytool keychain profile 'calm-notary'. Stop here and report." | tee "$RESULTS/s3-notarize.txt"; exit 1; }

{
  log "Rebuild ProbeApp with Developer ID + secure timestamp"
  SIGN_ID="$DEVID" NOTARIZE=1 "$SPIKE_DIR/scripts/s1-build-probe.sh" >/dev/null
  APP="$SPIKE_DIR/build/ProbeApp.app"; ZIP="$SPIKE_DIR/build/ProbeApp.zip"
  rm -f "$ZIP"; ditto -c -k --keepParent "$APP" "$ZIP"

  log "Submit (waits; typically a few minutes)"
  START=$(date +%s)
  OUT="$(xcrun notarytool submit "$ZIP" --keychain-profile calm-notary --wait 2>&1 || true)"; echo "$OUT"
  echo "elapsed_seconds=$(( $(date +%s) - START ))"
  SUBID="$(echo "$OUT" | awk '/^ *id:/{print $2; exit}')"
  if ! echo "$OUT" | grep -q "status: Accepted"; then
    log "Notary log"; xcrun notarytool log "$SUBID" --keychain-profile calm-notary || true
    exit 1
  fi

  log "Staple + validate";       xcrun stapler staple "$APP" && xcrun stapler validate "$APP"
  log "Gatekeeper assessment";   spctl -a -vvv -t exec "$APP" 2>&1 || true
  log "Signature summary";       codesign -dv --verbose=2 "$APP" 2>&1 | grep -E 'Identifier|Authority|TeamIdentifier|Runtime|Timestamp' | sed -E 's/(Developer ID Application: ).*/\1<redacted>/'
  log "Nested helper";           codesign -dv "$APP/Contents/Helpers/probe-cli" 2>&1 | grep -E 'Identifier|flags' || true
} 2>&1 | tee "$RESULTS/s3-notarize.txt"
