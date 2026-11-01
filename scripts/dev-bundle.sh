#!/usr/bin/env bash
# Builds a signed debug .app and opens it. Needed for anything that depends on
# macOS permissions (Location for SSID/BSSID): `pnpm dev` runs an unbundled
# binary that never gets the Location prompt (WP1 S1b, ADR-008).
#
# Signing: APPLE_SIGNING_IDENTITY if set, else the first "Apple Development"
# identity by SHA-1 (names can be duplicated). A stable identity keeps the
# Location grant across rebuilds.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ "$(uname -s)" == "Darwin" ]] || { echo "macOS only" >&2; exit 1; }

SIGN="${APPLE_SIGNING_IDENTITY:-$(security find-identity -v -p codesigning | awk '/"Apple Development:/{print $2; exit}')}"
if [[ -z "$SIGN" ]]; then
  echo "WARN: no Apple Development identity — Tauri will ad-hoc sign; Location grants will reset on every build." >&2
fi

APP="$ROOT/target/debug/bundle/macos/Calm.app"
pkill -f "$APP/Contents/MacOS/" 2>/dev/null || true

cd "$ROOT"
APPLE_SIGNING_IDENTITY="$SIGN" pnpm --filter @calm/desktop tauri build --debug --bundles app
open "$APP"
