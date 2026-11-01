#!/usr/bin/env bash
# S1(c): which built-in commands still expose SSID/BSSID on this macOS? Masked unless RAW=1.
source "$(dirname "$0")/lib.sh"; require_macos
WIFI_IF="$(networksetup -listallhardwareports | awk '/Hardware Port: (Wi-Fi|AirPort)/{getline; print $2; exit}')"
WIFI_IF="${WIFI_IF:-en0}"
{
  log "Wi-Fi interface: $WIFI_IF"
  log "networksetup -getairportnetwork";   networksetup -getairportnetwork "$WIFI_IF" 2>&1 || true
  log "ipconfig getsummary (SSID/BSSID/Security lines)"
  ipconfig getsummary "$WIFI_IF" 2>&1 | grep -Ei '^\s*(SSID|BSSID|Security|InterfaceType|LinkStatusActive)' || echo "(no matching lines)"
  log "system_profiler SPAirPortDataType (current network block)"
  system_profiler SPAirPortDataType 2>/dev/null \
    | awk '/Current Network Information:/{f=1;n=0} f{n++; if(n==2 && ENVIRON["RAW"]!="1"){sub(/[^ ].*/,"<ssid-line masked>")} print} /Other Local Wi-Fi Networks:/{exit}' | head -25
  log "scutil --nwi";                      scutil --nwi 2>&1 | head -20
  log "route -n get default";              route -n get default 2>&1 | grep -E 'gateway|interface|flags' || true
  log "scutil --dns (resolvers)";          scutil --dns 2>&1 | grep -E 'resolver #|nameserver|if_index' | head -12
  log "IPv6 addresses on $WIFI_IF";        ifconfig "$WIFI_IF" | grep -E 'inet6|ether' | sed -E 's/(ether ([0-9a-f]{2}:){2})[0-9a-f:]+/\1**:**:**:**/'
} 2>&1 | mask_stream | tee "$RESULTS/s1-baseline-cli.txt"
echo; echo "Look for '<redacted>' or missing SSID above — that is the finding."
