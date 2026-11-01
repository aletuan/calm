# ADR-003: Evidence-based graph

**Status:** Accepted baseline  
**Date:** 2026-10-31

## Context
A connected Guest Wi-Fi laptop cannot know physical LAN topology.

## Decision
Observed/validated/inferred/unverified semantics (vocabulary per ADR-008), every node/edge linked to provenance.

## Reasons
Prevents fabricated network maps and supports audit trails.

## Consequences & trade-offs
Graph may initially be sparse and less visually dramatic.

## Alternatives considered
Pretend IP subnet implies VLAN/physical adjacency rejected.

## Validation / revisit trigger
Review during MVP architectural spike and again after field testing. Capture decision owner, performance measurement and accepted risk before marking Proposed ADR accepted.
