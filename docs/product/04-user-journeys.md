# User Journeys & Key Scenarios

## Journey 1: First-time café audit (one MacBook)
1. Assessor receives written authorization and approved targets.
2. Connects MacBook to Guest Wi-Fi and opens app.
3. App shows SSID/BSSID/interface, gateway, route/DNS, permissions and vantage point.
4. Passive collection begins; topology shows Mac, Wi-Fi association, gateway from routing and first-party flow destinations.
5. Assessor reviews network visibility; sees observed vs inferred connectors.
6. Enables approved safe scan, chooses exact allowlist, rate limit, time window.
7. Assessment populates reachable test endpoints and findings with evidence/confidence.
8. Opens a finding, reads concept-level explanation and remediation.
9. Exports report containing unknowns and non-tested areas.

## Journey 2: Understand suspicious exposure
- User clicks `Gateway → management HTTPS endpoint` graph edge.
- UI shows successful TCP test, timestamp, target, tool output, scope ID.
- User selects **Why risky?**: management service generally should not be reachable from guest.
- UI clarifies: TCP connection ≠ admin credential bypass.
- User adds remediation recommendation and follow-up recheck.

## Journey 3: Traffic-first troubleshooting
- Start local traffic capture and open dashboard charts.
- Click spike at t=31s → flow table filtered by interval.
- Click destination → highlight related graph node and DNS/TLS metadata.
- Open protocol concept tutor; replay PCAP locally for retrospective analysis.

## Journey 4: Unverifiable client isolation
- No cooperative device available.
- UI labels `Client isolation: Inconclusive (missing reference endpoint)`.
- Explain why another receiver is needed and offer non-invasive follow-up plan.
- Report does not score this as pass.

## Journey 5: Plugin vulnerability matching
- Import approved Nmap XML and safe Nuclei result fixtures.
- Adapter normalizes services/findings, links raw output; intel plugin matches candidate CVEs.
- User checks software identification accuracy; confirms or rejects match.
- AI explains exploit preconditions and which details are *not* established.

## Screen inventory
1. Session Setup / Authorization
2. Network Overview
3. Interactive Topology
4. Traffic Explorer & Replay
5. Assessment Runner & Safety Console
6. Findings / Vulnerability Explorer
7. Evidence Detail & Concept Tutor
8. Plugin Registry & Permissions
9. Reports / Compare Sessions
10. Settings / Privacy / Retention

## Empty/error states
- No Wi-Fi connected; missing capture permission; no host responses; no second endpoint; plugin timeout; NVD offline/cache stale; unsupported parser version; inconsistent node identity; expired authorization. Every state needs an actionable explanation, not a blank graph.
