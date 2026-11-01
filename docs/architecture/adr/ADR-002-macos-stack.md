# ADR-002: macOS-first desktop architecture

**Status:** Proposed  
**Date:** 2026-10-31

## Context
Mac compatibility + topology/traffic high-performance visualization + extensible core.

## Decision
Tauri 2 + React/TypeScript UI, Rust core, Swift/CoreWLAN bridge and minimal capture helper.

## Reasons
Separation of native integration from UI; local-first, efficient processing.

## Consequences & trade-offs
OS API availability, permissions, signing, Intel/ARM support to validate.

## Alternatives considered
Electron-only or Python-only backend not chosen; trade-offs reviewable.

## Validation / revisit trigger
Review during MVP architectural spike and again after field testing. Capture decision owner, performance measurement and accepted risk before marking Proposed ADR accepted.
