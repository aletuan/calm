# Feature Specifications

## A. Session & scope setup
- New assessment: session name, site, operator, authorization reference, expiry, allowed SSIDs/BSSIDs and explicit IP/CIDR/port target list.
- Start passive observation without active probes; button to unlock scoped validation after explicit approval.
- Preflight shows interface, connected SSID, gateway, IPv4/IPv6, scope, privileges and active probe budget.
- Emergency Stop cancels subprocesses, pending jobs and capture, with audit record.

## B. Wi-Fi and network profiler
- Managed mode collect SSID, BSSID, channel, RSSI, Wi-Fi capabilities if available; DHCP-provided addresses, route table and DNS.
- State source and constraints; availability varies with macOS privacy permissions/driver/API.
- Avoid claims about radio coverage, other clients or actual VLAN IDs without evidence.

## C. Network Explorer / Topology
- Views: Logical, Communication, Security Exposure.
- Graph elements: asset, interface, subnet (hypothesis), AP/BSSID, gateway, service, destination, finding, vulnerability, evidence.
- Edge semantics: ASSOCIATED_WITH, DEFAULT_ROUTE_VIA, RESOLVES_VIA, CONNECTIVITY_CONFIRMED, FLOW_OBSERVED, POSSIBLE_MEMBERSHIP, AFFECTED_BY (confidence aware).
- Solid edge = observed/validated; dashed = inference; unknown relation not drawn as physical cable.
- Select node -> details (identifiers, seen time, sources, confidence), flows, findings, explanations.
- Filter by time, subnet, protocol, severity, confidence, source, observed vs inferred; export graph JSON/GraphML.

## D. Traffic Explorer
- Local capture start/stop, interface selection, packet and flow counters; timeline, direction, protocol mix, top endpoint, ports, DNS, connection events.
- Preserve separation of first-party laptop traffic, observed broadcast/multicast, and imported external sensor traffic.
- PCAPNG replay; timeline scrubbing updates graph and findings; size/time retention policy.
- Do not promise decryption of TLS or capture of peer-to-peer traffic not delivered to interface.

## E. Assessment checks
- W01 encryption/network properties; W02 PMF capability visibility; W03 IPv4/IPv6/DNS profile; N01 cooperative client isolation; N02 management network reachability; N03 POS test endpoint reachability; N04 service exposure; N05 IPv6 policy gaps; S01 web admin interface reachability; S02 safe TLS/configuration checks.
- Every check includes prereqs, authorized target(s), expected result, evidence, limitations, status, confidence and action.
- No coercive packet injection/deauth/auth attacks in default workflow.

## F. Vulnerability Explorer
- Sources: CVE/NVD, CWE, CPE, CVSS, KEV, EPSS; plugin-provided advisories; source update timestamps.
- Candidate → likely affected → verified vulnerable → exploit validated are *different* evidence levels; no automatic promotion.
- CVE correlations include software version uncertainty and conditions (configuration, backports).
- Priority matrix uses exposure + criticality + confidence + impact, not arbitrary sum of CVSS and EPSS.

## G. Explainability
- Inline concept cards, three depths (basic/technical/deep), Why it matters / How it works / Show evidence.
- Select packet/flow -> layered walkthrough (link, IP, TCP/UDP, TLS etc.) using actual observed fields; learning illustration clearly labeled.
- For every claim display verified facts, hypotheses, unknowns, data source and remediation.
- AI assistant P1 read-only by default; answers cite local evidence IDs/source documents.

## H. Reporting
- Executive summary, scope & vantage point, methodology, topology snapshot, local traffic summary, prioritized findings, evidence/references, limitations, untested assets and remediation plan.
- Machine-readable exports (canonical JSON, SARIF findings when representable) plus Markdown/HTML/PDF.
- Baseline and recheck comparison P1.

## I. Plugins
- Registry lists name/version/signature/dependencies/capabilities/permission tiers.
- Install/uninstall via review; adapters use CLI/API and typed messages; immutable job request with enforced scope.
- Tool-specific failures isolated; imported results remain linked to source artifact and parser version.

## Interaction details
- No auto-scanning when user clicks topology; safe exploratory actions may preview targets and ask approval.
- On selection of node: retain context across topology/traffic/security views.
- Risk badge applies to actual finding, not automatically to entire adjacent subnet.
- Tooltips explain 'Inconclusive', 'Reachable' and confidence.

## J. UI/UX visual baseline (V2)
- Follow [Calm Technical UI guidelines](../design/01-calm-technical-ui-guidelines.md): muted dark palette, one primary focus, comfortable density, progressive disclosure, restrained semantic color and evidence-aware topology.
- Topology V2 inspector is closed by default; traffic and security overlays optional.
- All statuses remain understandable without color alone; retain context across deep links.
