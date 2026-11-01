# ADR-004: Standards-first adapters

**Status:** Proposed  
**Date:** 2026-10-31

## Context
OSS security tools vary in API, output and installation.

## Decision
Ports/adapters with versioned canonical JSON, JSON Schema, JSON-RPC subprocess, native tool formats and standard exports.

## Reasons
Replaceability, interoperability, minimal vendor lock-in.

## Consequences & trade-offs
SDK itself is app-specific; mapping may be lossy.

## Alternatives considered
Single proprietary output schema with no raw formats rejected.

## Validation / revisit trigger
Review during MVP architectural spike and again after field testing. Capture decision owner, performance measurement and accepted risk before marking Proposed ADR accepted.
