# ADR-006: Deterministic conclusions, AI explanations

**Status:** Accepted baseline  
**Date:** 2026-10-31

## Context
LLM may confuse observations with confirmed vulnerabilities.

## Decision
Rule engine produces statuses; explanatory model consumes grounded claims and evidence.

## Reasons
Auditable results and accessible learning.

## Consequences & trade-offs
Needs curated knowledge base, validators and reviewer workflow.

## Alternatives considered
AI as autonomous vulnerability authority rejected.

## Validation / revisit trigger
Review during MVP architectural spike and again after field testing. Capture decision owner, performance measurement and accepted risk before marking Proposed ADR accepted.
