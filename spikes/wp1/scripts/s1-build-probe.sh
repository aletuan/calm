#!/usr/bin/env bash
# Builds two app bundles from the same code:
#   build/ProbeApp.app        (regular app, Dock icon)      bundle id com.aletuan.calm.spike.wifiprobe
#   build/ProbeAgent.app      (LSUIElement=1, no Dock icon) bundle id com.aletuan.calm.spike.wifiprobe.agent
# Each embeds probe-cli in Contents/Helpers. Signed with hardened runtime + location entitlement.
source "$(dirname "$0")/lib.sh"; require_macos
PKG="$SPIKE_DIR/wifi-probe"; OUT="$SPIKE_DIR/build"
SIGN="$(pick_sign_id)"
TS_FLAG="--timestamp=none"; [[ "${NOTARIZE:-0}" == "1" ]] && TS_FLAG="--timestamp"
[[ "$SIGN" == "-" ]] && warn "No 'Apple Development' identity found — ad-hoc signing. TCC grants will NOT survive rebuilds; results may be misleading. Set SIGN_ID to override."
log "Signing identity: $SIGN"

log "swift build (release)"
swift build --package-path "$PKG" -c release
BIN="$(swift build --package-path "$PKG" -c release --show-bin-path)"

ENT="$OUT/probe.entitlements"; mkdir -p "$OUT"
cat > "$ENT" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.personal-information.location</key><true/>
</dict></plist>
PLIST

make_bundle() { # name bundle_id lsuielement
  local name="$1" bid="$2" agent="$3" app="$OUT/$1.app"
  rm -rf "$app"; mkdir -p "$app/Contents/MacOS" "$app/Contents/Helpers"
  cp "$BIN/ProbeApp" "$app/Contents/MacOS/$name"
  cp "$BIN/probe-cli" "$app/Contents/Helpers/probe-cli"
  cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>$bid</string>
  <key>CFBundleName</key><string>$name</string>
  <key>CFBundleExecutable</key><string>$name</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.0.1</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><$agent/>
  <key>NSLocationUsageDescription</key><string>Calm spike: reading the connected Wi-Fi SSID/BSSID requires Location access on macOS.</string>
  <key>NSLocationWhenInUseUsageDescription</key><string>Calm spike: reading the connected Wi-Fi SSID/BSSID requires Location access on macOS.</string>
</dict></plist>
PLIST
  # Inside-out signing: nested helper first, then the bundle. Never --deep.
  codesign --force --options runtime $TS_FLAG --entitlements "$ENT" \
    --identifier "$bid.cli" --sign "$SIGN" "$app/Contents/Helpers/probe-cli"
  codesign --force --options runtime $TS_FLAG --entitlements "$ENT" --sign "$SIGN" "$app"
  codesign --verify --strict --verbose=2 "$app"
  log "Built $app"
}

make_bundle ProbeApp   com.aletuan.calm.spike.wifiprobe       false
make_bundle ProbeAgent com.aletuan.calm.spike.wifiprobe.agent true
cp "$BIN/probe-cli" "$OUT/probe-cli"
codesign --force --options runtime $TS_FLAG --entitlements "$ENT" \
  --identifier com.aletuan.calm.spike.wifiprobe.terminalcli --sign "$SIGN" "$OUT/probe-cli"
log "Done. Next: scripts/s1-run-probe.sh"
