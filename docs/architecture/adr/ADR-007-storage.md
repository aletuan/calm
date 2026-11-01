# ADR-007: Local-first storage

**Status:** Proposed  
**Date:** 2026-10-31

## Context
Sensitive network metadata, potentially large packet captures, offline use.

## Decision
SQLite metadata/evidence indices; optional PCAPNG outside DB; explicit retention/encryption.

## Reasons
Portability, easy backup/inspection, low operational footprint.

## Consequences & trade-offs
Disk budgeting and sync later require design.

## Alternatives considered
Mandatory cloud ingestion rejected.

## Validation / revisit trigger
Review during MVP architectural spike and again after field testing. Capture decision owner, performance measurement and accepted risk before marking Proposed ADR accepted.
