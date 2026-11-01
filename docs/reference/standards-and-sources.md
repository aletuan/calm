# Standards, Public References & Verification Notes

**Checked against public reference pages on 2026-10-31.** These are background/implementation references; exact tool versions and compatibility require independent engineering validation during implementation.

## Assessment & wireless
- [NIST SP 800-115 – Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final) — methodology, planning, authorized scope and reporting.
- [NIST SP 800-153 – Guidelines for Securing Wireless Local Area Networks](https://csrc.nist.gov/pubs/sp/800/153/final) — WLAN security context.

## Security interchange and intelligence
- [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html) — findings interchange; not full packet/graph format.
- [OASIS STIX/TAXII resources](https://oasis-open.github.io/cti-documentation/resources.html) — CTI structure and exchange.
- [NVD developers](https://nvd.nist.gov/developers) — vulnerability info APIs.
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — exploited-in-wild catalogue.
- [FIRST EPSS](https://www.first.org/epss/) — exploit probability estimate.
- [OSV.dev](https://osv.dev/) — open-source vulnerability ecosystem.
- [CycloneDX](https://cyclonedx.org/) / [SPDX](https://spdx.dev/) — SBOM formats.
- [CSAF](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) / [OpenVEX](https://github.com/openvex/spec) — advisories and affected/not-affected status.

## OSS integration tools
- [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html)
- [Wireshark / TShark documentation](https://www.wireshark.org/docs/)
- [Zeek documentation](https://docs.zeek.org/)
- [Suricata EVE JSON](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)
- [Nuclei](https://docs.projectdiscovery.io/tools/nuclei/overview)
- [Greenbone community documentation](https://greenbone.github.io/docs/latest/)
- [OWASP ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [DefectDojo docs](https://docs.defectdojo.com/)

## Platform and API
- [Apple CoreWLAN documentation](https://developer.apple.com/documentation/corewlan)
- [Tauri documentation](https://v2.tauri.app/)
- [Cytoscape.js](https://js.cytoscape.org/)
- [JSON Schema](https://json-schema.org/)
- [OpenAPI](https://spec.openapis.org/oas/)
- [JSON-RPC 2.0](https://www.jsonrpc.org/specification)
- [Model Context Protocol](https://modelcontextprotocol.io/specification/)

## Cautions
- These links do not prove full macOS compatibility of every scanner/adapter. Audit versions, licenses, platform support and security behavior before packaging.
- Prefer pinned released standards and avoid silently treating drafts as stable contracts.
- Do not equate presence of a CPE/CVE reference with verified vulnerability.
