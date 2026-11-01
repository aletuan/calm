# Acceptance Criteria & Test Strategy

## P0 test matrix
| Test ID | Given | When | Expected |
|---|---|---|---|
| AT-01 | Connected Mac Guest Wi-Fi | Passive session created | Accurate SSID/BSSID/route/DNS snapshot with sources |
| AT-02 | No authorization granted | User starts app | No active target scan launched |
| AT-03 | Scope allows only test IP A | Plugin asks for IP B | Job denied and logged |
| AT-04 | Local PCAP fixture | Import/replay | Protocol/time/direction data matches golden fixture |
| AT-05 | Captured unicast only from Mac | Show topology | No invented peer-to-peer links |
| AT-06 | Gateway route only | Create graph | Gateway and AP remain distinct/unverified identities |
| AT-07 | Ref endpoint unavailable | Client isolation check | `Inconclusive`, not `Pass` |
| AT-08 | TCP connect success | Generate finding | Does not claim auth bypass/compromise |
| AT-09 | Banner hints vulnerable version | Intel enrichment | `Candidate`, not verified |
| AT-10 | Finding selected | Basic/technical/deep UI | Each level links to same evidence and caveats |
| AT-11 | Long-running tool | Stop button clicked | Process stops; scope/audit record retained |
| AT-12 | Plugin emits invalid schema | Ingest output | Quarantine/reject gracefully, no graph corruption |
| AT-13 | Offline laptop | Run passive, replay, report | No mandatory cloud dependency |
| AT-14 | Export to SARIF | Schema validation | SARIF 2.1.0 valid + limitations preserved |
| AT-15 | Raw capture disabled | Run observation | Packet payload not persisted by app by default |
| AT-16 | Corrupted PCAP/XML | Import | Parse failure safely contained |

## Integration environments
1. Simple single-AP Guest Wi-Fi with permissive test endpoints.
2. Guest client isolation active and a cooperative receiver.
3. Guest/Staff/POS *test* VLAN segmentation with firewall allow/deny cases.
4. Dual-stack IPv4/IPv6 network.
5. Captive portal and roaming/multi-BSSID scenario.
6. Offline, stale intel feed and restricted macOS privileges.

## Test types
Unit (parsers, scoring), property/fuzz (PCAP/XML/JSON), schema contract (plugin/adapters), integration (OS Wi-Fi/capture), E2E (UI flows), performance (large PCAP), security (privileges/out-of-scope), usability (comprehension), recovery (crash/cancel).

## Definition of Done
Every feature has documented limits and acceptance tests, evidence lineage, error states, safe default, docs, privacy review if collecting new fields, regression fixture and release notes. Every plugin requires additional license/trust/permission assessment.
