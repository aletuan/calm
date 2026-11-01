# Authorized Guest Wi-Fi Assessment Methodology

## Ethical/operational baseline
Assess only a network you own or have explicit written permission to test. The user is an external assessor connected to Guest Wi-Fi; connection by itself **does not authorize scanning** arbitrary devices. Maintain rules of engagement (ROE): owner, contact, time window, assets, permitted protocols, exclusions, test rates, emergency stop, escalation, retention, legal review.

## Test levels
| Level | Allowed by default? | Content |
|---|---|---|
| L0 Passive | Yes after local collection consent | Local Wi-Fi/route/DNS configuration, first-party capture |
| L1 Safe | No, separate authorization | Target-specific reachability, selected low-impact checks |
| L2 Active | No, per-check approval | Reviewed templates with impact analysis, short maintenance window |
| L3 Exploit validation | No, prefer lab | Controlled proof of impact with separate signed engagement; never auto-run |

## Assessment phases
1. Preflight: verify interface/SSID/BSSID, signed ROE, explicit allowlist, privilege/capture capability, business criticality.
2. Passive profile: IPv4/IPv6, routes, DNS, negotiated Wi-Fi connection, visible traffic.
3. Authorized asset discovery: approved hosts only, low rate, bounded concurrency and timeout.
4. Reachability & exposure: approved service/port tests, no brute force or bypass.
5. Isolation: use cooperative known-good devices in Guest/Staff/POS test zones where provided; don't attack actual POS.
6. Vulnerability intelligence: match tool evidence to vulnerability references; distinguish candidate from confirmed.
7. Validation: reviewed safe checks only; classify uncertain results honestly.
8. Report and remediation review: include unassessed paths, tests not run, improvement steps and recheck plan.

## Test catalog
| ID | Check | Evidence | Prerequisite | Failure/limit |
|---|---|---|---|---|
| W01 | Encryption/association properties | OS interface metadata | Wi-Fi connected | APIs may not expose all radio parameters |
| W02 | PMF capability visibility | OS/available management metadata | Supported hardware/OS | Unknown if hidden |
| W03 | DHCP/IP/DNS/routes | OS config snapshot | Active association | Config != security guarantee |
| N01 | Guest client isolation | Approved cooperative receiver and test | Second endpoint | Missing -> Inconclusive |
| N02 | Mgmt endpoint isolation | Approved mgmt test endpoint | Owner-defined target | Reached != auth bypass |
| N03 | POS isolation | Simulated/test POS endpoint | Owner-defined target | No production POS disruption |
| N04 | Exposed services | Approved host/port list | Explicit scope | Missing reply != absent service |
| N05 | IPv6 path rules | IPv6 approved targets | IPv6 present | Might differ from IPv4 |
| S01 | Web admin interface reachability | Approved TCP/HTTP(S) test | Owner-defined admin target | Reached != login/auth bypass |
| S02 | TLS/config controls | Low-impact handshake/config metadata | Approved endpoint | Version guesses uncertain |

## Evidence policy
Collect timestamps, method, target scope, tool/adapter version, protocol response and raw trace where approved. Distinguish **observed**, **inferred**, **unverified**. No pass from absence of response alone. No CVE confirmation solely from matching a banner/CPE.

## Stop conditions
- Target behaves abnormally, latency/errors breach agreed threshold, POS/service impact, complaints from owner.
- Scope or authorization expires.
- Tool attempts to exceed approved targets/budgets.
- Helper permissions/network conditions unexpectedly change.
Stop jobs, notify owner, preserve limited diagnostic evidence and document action.

## Reporting limitations
Explicitly declare vantage point, no infrastructure admin, no guaranteed full traffic visibility, no full physical topology, blind spots/unknown networks and effects of firewall/client isolation. See [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final).
