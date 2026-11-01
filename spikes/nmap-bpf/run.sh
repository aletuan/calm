#!/usr/bin/env bash
# Spike: can Nmap send raw packets (-sS, -O, ARP discovery) on macOS as a
# normal user, using only the calm_bpf group's access to /dev/bpf*?
# Decides whether ADR-011's L2 capabilities need a root helper (ADR-005).
#
#   spikes/nmap-bpf/run.sh <private-ip-of-a-device-you-own>
#   spikes/nmap-bpf/run.sh <ip> --with-sudo     also run one -sS as root, as a baseline
#
# Sends at most 5 packets/s to ONE address you name, on 4 ports. No scripts,
# no DNS lookups, no other hosts. Output stays in spikes/nmap-bpf/results/
# (gitignored: it contains real addresses).
set -uo pipefail

[[ "$(uname -s)" == "Darwin" ]] || { echo "macOS only" >&2; exit 1; }
TARGET="${1:-}"
WITH_SUDO="${2:-}"
PORTS="22,53,80,443"

is_private_v4() {
  local ip="$1" a b
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  a=${BASH_REMATCH[1]} b=${BASH_REMATCH[2]}
  [[ $a == 10 ]] || [[ $a == 192 && $b == 168 ]] || [[ $a == 172 && $b -ge 16 && $b -le 31 ]]
}
if ! is_private_v4 "$TARGET"; then
  echo "Give one private IPv4 address of a device you own or may test (10/8, 172.16/12, 192.168/16)." >&2
  exit 2
fi
if ! command -v nmap >/dev/null; then
  echo "Nmap is not installed. Install it with:  brew install nmap   then run this again." >&2
  exit 3
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
IFACE="$(route -n get "$TARGET" 2>/dev/null | awk '/interface:/ {print $2}')"
COMMON=(-Pn -n -p "$PORTS" --max-rate 5 --host-timeout 60s --max-retries 1)

{
  echo "# environment"
  sw_vers
  uname -m
  echo "user: $(id -un)  groups: $(id -Gn)"
  echo "in calm_bpf: $(id -Gn | tr ' ' '\n' | grep -qx calm_bpf && echo yes || echo no)"
  echo "route interface to target: ${IFACE:-unknown}"
  ls -l /dev/bpf0 /dev/bpf1 /dev/bpf2 2>&1
  echo "bpf devices: $(find /dev -maxdepth 1 -name 'bpf*' 2>/dev/null | wc -l | tr -d ' ')"
  nmap --version | head -3
} >"$OUT/environment.txt" 2>&1

# name | extra nmap arguments
TESTS=(
  "T1-connect-baseline|-sT"
  "T2-syn-send-eth|--privileged -sS --send-eth -e ${IFACE:-en0}"
  "T3-syn-send-ip|--privileged -sS --send-ip"
  "T4-os-detect-send-eth|--privileged -O --send-eth -e ${IFACE:-en0}"
  "T5-arp-discovery|--privileged -sn --send-eth -e ${IFACE:-en0}"
)

run() {
  local name="$1"; shift
  local log="$OUT/$name.log"
  echo "\$ nmap $* ${COMMON[*]} -oX $name.xml $TARGET" >"$log"
  if [[ "$name" == T5-* ]]; then
    # Discovery takes no port list.
    nmap "$@" -n --max-rate 5 --host-timeout 60s -oX "$OUT/$name.xml" "$TARGET" >>"$log" 2>&1
  else
    nmap "$@" "${COMMON[@]}" -oX "$OUT/$name.xml" "$TARGET" >>"$log" 2>&1
  fi
  local code=$?
  echo "exit: $code" >>"$log"
  printf '%-24s exit=%-3s %s\n' "$name" "$code" \
    "$(grep -m3 -E 'QUITTING|Failed|raw socket|dnet|ermission|not permitted|requires root|Host is up|OS details|Aggressive OS|No exact OS|Too many fingerprints|/tcp ' "$log" | tr '\n' ';' | cut -c1-220)"
}

{
  echo "# summary (target and addresses are in the per-test logs only)"
  for t in "${TESTS[@]}"; do
    # shellcheck disable=SC2086 # the argument string is split on purpose
    run "${t%%|*}" ${t#*|}
  done
  if [[ "$WITH_SUDO" == "--with-sudo" ]]; then
    echo "# baseline as root (asks for your password)"
    log="$OUT/T6-syn-as-root.log"
    # shellcheck disable=SC2024 # the log is meant to stay owned by you, not root
    sudo nmap -sS "${COMMON[@]}" -oX "$OUT/T6-syn-as-root.xml" "$TARGET" >"$log" 2>&1
    printf '%-24s exit=%-3s %s\n' "T6-syn-as-root" "$?" "$(grep -m3 -E 'QUITTING|Host is up|/tcp ' "$log" | tr '\n' ';' | cut -c1-220)"
  fi
} | tee "$OUT/summary.txt"

echo
echo "Results: $OUT"
