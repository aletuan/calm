# Spike: Nmap raw packets without root, through calm_bpf

**Status:** Done, 2026-11-01. One run. Raw logs stay in `spikes/nmap-bpf/results/` (gitignored: real addresses). **Runbook:** `spikes/nmap-bpf/run.sh <private-ip> [--with-sudo]`

## Question
ADR-011 (draft) lets a scope grant L2 capabilities: SYN scan (`-sS`), OS detection (`-O`) and ARP host discovery. They need raw packets. Does Calm need a root helper for them (against ADR-005), or is the existing `calm_bpf` group enough?

## Setup
- macOS 26.6.2 (25G83), Apple Silicon. Nmap 7.993 from Homebrew (built with libpcap, libdnet, Lua, OpenSSL).
- User `andy` in group `calm_bpf`. `/dev/bpf*` are `root:calm_bpf crw-rw----` (4 devices).
- One target the tester owns: the home router, on the same Wi-Fi segment (`en0`, 1 hop).
- Ports 22, 53, 80, 443. `--max-rate 5`, `--max-retries 1`, `-Pn -n`. No scripts, no DNS lookups.

## Results

| Test | Run as | Result |
|---|---|---|
| T1 `-sT` (TCP connect) | user | 53, 80, 443 open; **22 filtered** (no reply) |
| T2 `--privileged -sS --send-eth -e en0` | user | 53, 80, 443 open (syn-ack); 22 closed (reset). Identical to T6 |
| T3 `--privileged -sS --send-ip` | user | **Fails**: "Couldn't open a raw socket. Error: (1) Operation not permitted" |
| T4 `--privileged -O --send-eth -e en0` | user | Runs to the end; fingerprint collected; "No exact OS matches" |
| T5 `--privileged -sn --send-eth -e en0` | user | Host up, by ARP response |
| T6 `-sS` | root (sudo) | Same ports, states and reasons as T2 |

## Findings
1. **F1: No root is needed for raw scans on the local segment.** With `calm_bpf` read/write, `--privileged --send-eth` gives a SYN scan identical to root (same state and reason on every port).
2. **F2: Raw IP sockets still need root.** `--send-ip` fails. Calm must always pass `--send-eth -e <interface>`. Untested: targets outside the subnet, reached through the gateway's MAC (Nmap should handle it with `--send-eth`); IPv6.
3. **F3: OS detection sends more than the port list.** The fingerprint shows ICMP echo probes (`IE`) and a UDP probe to a random closed port (`CU=…`), on top of the TCP probes. An `os_detection` capability must say so in the scope form and in Preflight. The result was "No exact OS matches": OS identity is at best **inferred**, often unknown.
4. **F4: ARP discovery works without root** on the local segment.
5. **F5: `calm_bpf` grants read AND write, not read only.** `scripts/bpf-access.sh` runs `chmod g+rw`. Its comments, the group description and the Traffic setup text said "read access". So since install, any process of this user can capture **and inject** raw packets on every interface. Fixed in this change: script comments, group description and the setup text (`traffic.perm.*`) now say read and send.
6. **F6: Connect scan and SYN scan disagree on port 22.** `-sT` saw no reply (filtered); `-sS` seconds later saw a reset (closed). One sample only. Possible causes: the router rate-limits resets, or the connect attempt timed out with `--max-retries 1`. For Calm's current TCP-connect checks this errs on the safe side: silence is "inconclusive", never "pass". Re-run T1 a few times before relying on reset-vs-silence for a decision.

## Consequences for ADR-011 and ADR-005
- L2 capabilities (`syn_scan`, `os_detection`, `host_discovery`) can run as the user, **no root helper**, as long as `calm_bpf` keeps write access. That write access becomes a deliberate requirement, recorded in ADR-005, not an accident of the script.
- Calm always builds `--privileged --send-eth -e <interface>`; `--send-ip` is never used.
- The `os_detection` capability text names its extra ICMP and UDP probes.
- The bundled Nmap must be built with libpcap and libdnet (the Homebrew build is).

## Open
- Off-link targets (outside the subnet) with `--send-eth`.
- IPv6 raw scans.
- Repeat T1 to explain F6.
- A narrower helper (SMAppService) instead of group-wide BPF write access before a public release (already planned in `bpf-access.sh`).
