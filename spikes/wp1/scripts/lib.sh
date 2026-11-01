# shellcheck shell=bash
# Shared helpers for WP1 spike scripts. Sourced, not executed.
set -euo pipefail
SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$SPIKE_DIR/results"
mkdir -p "$RESULTS"
log() { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
require_macos() { [[ "$(uname -s)" == "Darwin" ]] || { echo "Run this on the Mac, not Linux." >&2; exit 1; }; }

# Prefer an explicit SIGN_ID, else first "Apple Development" identity, else ad-hoc.
pick_sign_id() {
  if [[ -n "${SIGN_ID:-}" ]]; then echo "$SIGN_ID"; return; fi
  local id
  # Use the SHA-1 hash: several certificates can share the same display name,
  # which makes `codesign --sign "<name>"` fail as ambiguous.
  id="$(security find-identity -v -p codesigning 2>/dev/null | awk '/"Apple Development:/{print $2; exit}')"
  if [[ -n "$id" ]]; then echo "$id"; else echo "-"; fi
}

# Mask SSID/BSSID-like values in free text unless RAW=1.
mask_stream() {
  if [[ "${RAW:-0}" == "1" ]]; then cat; return; fi
  sed -E \
    -e 's/(([0-9a-fA-F]{1,2}:){2})([0-9a-fA-F]{1,2}:){3}[0-9a-fA-F]{1,2}/\1**:**:**:**/g' \
    -e 's/((SSID|Network Name|Current Wi-Fi Network)[^:=]*[:=] *)(.{0,2})[^ ,"]*/\1\3***/g'
}
