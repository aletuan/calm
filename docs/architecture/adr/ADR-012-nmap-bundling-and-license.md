# ADR-012: Bundle Nmap, release Calm under the NPSL

**Status:** Proposed
**Date:** 2026-11-01
**Related:** ADR-011 (capability scopes and Nmap runs), ADR-004 (standards-first adapters)

## Context
ADR-011 lets Calm run Nmap inside a scope grant. Two ways exist: call a copy the user installed (Homebrew), or ship Nmap inside `Calm.app`. The maintainer chose to ship it, so the result works without a separate install and the Nmap version is known.

Nmap is licensed under the Nmap Public Source License (NPSL) 0.95, based on GPLv2. It treats as a derivative work any software "designed specifically to execute Covered Software and parse the results", and any software that "includes Covered Software in a proprietary executable installer". Derivative works must be distributed under the NPSL; proprietary distribution needs a paid Nmap OEM license. Calm is free of charge, but the repository is currently `license = "UNLICENSED"` (closed source). Free of charge is not enough: the NPSL is about source availability, not price.

## Decision
- **Ship Nmap in the bundle** and call it by its fixed path inside `Calm.app`, never through `PATH`.
- **Release Calm under the NPSL 0.95.** The repository licence changes from `UNLICENSED` to NPSL; source is public.
- **Every release carries:** the Nmap source (or a written offer for it), Nmap's licence text, and a credit line for Nmap in Settings › About.
- **Build Nmap from source in CI** for arm64, with libpcap, libdnet, Lua and OpenSSL; install names rewritten to `@rpath`; every nested binary signed with hardened runtime and notarized with the app.
- **Ship only the NSE scripts on the ADR-011 allowlist**, not the whole `scripts/` folder.
- **Nmap security fixes ship as Calm releases.** The bundled version is recorded in every run's evidence.

## Reasons
- A known Nmap version gives stable XML, reproducible evidence and no binary swapped through `PATH`.
- Open source under the NPSL is the only lawful way to bundle and parse Nmap without buying an OEM licence.

## Consequences & trade-offs
- Calm's source becomes public. Returning to closed source later requires an OEM licence (and removing NPSL-bound code from releases).
- The bundle grows by roughly 20–30 MB. Building and notarizing Nmap and its libraries adds CI work.
- Calm is responsible for patching the bundled Nmap; a delayed release leaves users on a vulnerable version.

## Alternatives considered
- **Use the user's own Nmap install:** often outside the NPSL's derivative-work definition ("depending on the specific circumstances"), smaller bundle, no build work. Rejected by the maintainer for setup friction and an unknown Nmap version.
- **Buy an Nmap OEM licence and stay closed source:** possible, cost unknown. Not pursued for a free product.
- **Import Nmap XML only:** no licence question, but no scans from Calm. Kept as an extra input (FR-014).

## Validation / revisit trigger
Legal review before the first public release (the maintainer is not relying on this ADR as legal advice). Revisit if Calm becomes paid, or if the NPSL version changes.

Sources: [NPSL annotated text](https://nmap.org/npsl/npsl-annotated.html), [LWN: A license change for Nmap](https://lwn.net/Articles/842714/).
