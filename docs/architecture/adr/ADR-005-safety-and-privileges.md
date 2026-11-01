# ADR-005: Safety-by-default and privilege separation

**Status:** Accepted baseline  
**Date:** 2026-10-31

## Context
Guest networks can include business-critical POS and unknown devices.

## Decision
Passive default, explicitly scoped active jobs, approval, budgets, kill switch; isolated capture helper.

## Reasons
Reduces harm and legal/operational risk.

## Consequences & trade-offs
Absolute egress confinement of arbitrary third-party programs is hard on macOS.

## Alternatives considered
Automatic blanket scan/exploit execution rejected.

## Validation / revisit trigger
Review during MVP architectural spike and again after field testing. Capture decision owner, performance measurement and accepted risk before marking Proposed ADR accepted.

## Revision 2026-11-01 — raw packets through calm_bpf (ADR-011, accepted)
- `scripts/bpf-access.sh` grants the `calm_bpf` group **read and write** on `/dev/bpf*`, not read only as its comments said (fixed). Spike `docs/spikes/nmap-bpf-findings.md`: with that access, Nmap runs `-sS`, `-O` and ARP discovery as the user, identical to root; raw IP sockets still need root.
- Decision (ADR-011): write access is a deliberate requirement for L2 capabilities. No root helper; Nmap never runs as root.
- Trade-off: any process of the user can capture and inject on every interface while `calm_bpf` is installed. A narrower SMAppService helper remains required before a public release.
