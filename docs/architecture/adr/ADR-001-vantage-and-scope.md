# ADR-001: One authorized Guest Wi-Fi vantage

**Status:** Accepted baseline  
**Date:** 2026-10-31

## Context
Assume one connected MacBook, no AP/router credentials or mirror port.

## Decision
Make limitations explicit; verify only accessible resources; second cooperative endpoint optional.

## Reasons
Single-vantage truthfulness; simplest field deployment.

## Consequences & trade-offs
Full topology/network-wide traffic unavailable.

## Alternatives considered
Require complete coverage by instrumenting infrastructure, rejected as baseline.

## Validation / revisit trigger
Review during MVP architectural spike and again after field testing. Capture decision owner, performance measurement and accepted risk before marking Proposed ADR accepted.
