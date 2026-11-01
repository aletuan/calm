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
