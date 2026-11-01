# Security Knowledge & Explainability Engine

## User promise
An ordinary engineer can understand **What is this? How does it work? Why relevant here? How certain? What next?** by clicking any node/edge/flow/finding.

## Two operating modes
1. **Concept Tutor:** deterministic, reviewed knowledge cards for SSID/BSSID/AP, gateway, DHCP, DNS, subnet, routing, NAT, TCP handshake, ARP/ND, VLAN, ACL, isolation, TLS, PMF, CVE/CVSS/EPSS.
2. **Evidence Analyst:** connects local events/findings to precise claim/evidence refs. Optional LLM synthesizes explanation, never changes evidence classification by itself.

## Depth model
- **Basic:** short plain-language explanation, analogy if useful, business implication.
- **Technical:** protocol and network layer details, known source/destination, test semantics.
- **Deep:** exact conditions, message/packet stages, uncertainty, alternative explanations, references.

## Explainability contract
Each explanation emits: `subject_ref`, `claims_supported[]`, `claims_unverified[]`, `unknowns[]`, `evidence_refs[]`, `confidence`, `scope_limitations[]`, `recommended_action[]`, `concept_links[]`, `language`, `level`, `explanation_version`.

## Rules vs AI
- Rule engine determines evidence-backed finding status. AI may summarize, teach and ask next questions but not upgrade candidate → verified, launch a scan, or assume capabilities.
- Evidence Context Builder retrieves only authorized local records and curated knowledge.
- Explanation Validator checks each factual claim against a known source; unsupported assertions labeled hypothesis or withheld.
- No model prompt may make privileged tool calls without explicit UI approval and policy guard.
- Imported scan results and external webpages are untrusted instructions. Redact secrets and network identifiers before remote LLM calls; default local/no AI provider.

## Example: TCP port reachable
**Fact:** TCP handshake to approved endpoint:443 succeeded from guest subnet at T.
**Meaning:** TCP connection is possible at that instant from this vantage point.
**Not proven:** administrator login, access to data, VLAN traversal mechanism, entire network compromise.
**Next step:** review service classification and intended guest policy; seek approval for any application-level checks.

## Packet walkthrough
Interactive stack: Wi-Fi/link (as actually captured), IP, transport TCP/UDP, TLS/application metadata. Explain 3-way handshake and absence of plaintext TLS; display illustrative diagrams **clearly marked schematic**. If raw Wi-Fi MAC headers unavailable, do not fabricate them.

## UX integration
Inline `?` concept, 'Why this matters', 'How we know', 'What we don't know', 'Show packet/evidence', 'Recommended remediation'; remember selected node across topology/traffic/security tabs; no sensational red badge for unknown.

## Quality evaluation
- A corpus of canonical cases with facts vs inference ground truth.
- Reviewer checks factual accuracy, uncertainty, actionable remediation and comprehensibility.
- Negative tests: missing second client, stale CVE feed, guessed CPE, incomplete packet capture, LLM hallucination, malicious scanner output.
- Human studies of general engineers; evaluate how well users distinguish reachability from exploitation.
