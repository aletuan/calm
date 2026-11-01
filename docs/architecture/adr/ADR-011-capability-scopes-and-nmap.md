# ADR-011: Capability scopes and Nmap runs inside a grant

**Status:** Accepted for beta (2026-11-01)
**Date:** 2026-11-01
**Revises:** ADR-010 (scope grants and L1 probes), ADR-005 (privileges)
**Related:** ADR-012 (bundling Nmap), spike `docs/spikes/nmap-bpf-findings.md`

## Context
ADR-010 allows one kind of traffic: a TCP connect to literal private addresses, authorized per probe. N04 (exposed services), service identity and host discovery need more. Nmap does this well, but it sends its own packets: Calm cannot authorize each one. The spike showed that with the `calm_bpf` group (read and write on `/dev/bpf*`), Nmap sends raw packets for `-sS`, `-O` and ARP discovery **without root**, with results identical to a root run; raw IP sockets (`--send-ip`) still need root. It also showed that `-O` sends ICMP and a UDP probe to a random closed port, outside the port list.

## Decision

### 1. A scope lists capabilities, not only addresses
The scope keeps targets, rate, validity and network binding (ADR-010), and adds:
- `ranges`: private CIDR blocks, at most /24 each. With ranges, the owner either lists `exclusions` (production POS, guests' devices) or confirms `nothing_to_exclude`; leaving both empty is refused, and both at once is a contradiction (refused). The confirmation is recorded instead of a made-up address.
- `capabilities`, each off by default and ticked by the owner:

| Capability | Level | Nmap | What it sends beyond a TCP connect |
|---|---|---|---|
| `tcp_connect` | L1 | `-sT` (or Calm's own runner) | Nothing (as ADR-010) |
| `host_discovery` | L1 | `-sn` | ARP or ping inside `ranges` |
| `reverse_dns` | L1 | no `-n`, `--dns-servers <resolver>` | DNS PTR queries, only to the network's own resolver and only when it has a private address |
| `syn_scan` | L2 | `-sS` | Half-open TCP |
| `service_detection` | L2 | `-sV` | Probe strings into open ports |
| `os_detection` | L2 | `-O` | Extra TCP, ICMP echo, one UDP probe to a random closed port |
| `nse` | L2 | `--script <id>` | Whatever each allowlisted script sends (named per script) |

The approval sentence the user ticks lists the capabilities enabled.

### 2. Authorization moves from each probe to each run plan
`authorize` receives the whole plan: every target, port, flag and script. It refuses if a target is outside `targets ∪ ranges` or inside `exclusions`, if a flag has no granted capability, or if a script is not on the allowlist. The Nmap command line is **built only from an authorized plan**; nothing the user types reaches it. Preflight shows the exact command and an estimate of packets to send. Calm's own TCP-connect runner keeps per-probe authorization.

### 3. Flags always present
`--max-rate <scope rate>`, `--host-timeout`, `-oX -` (XML on stdout, no temp files), `-n` unless `reverse_dns` is granted, `-Pn` unless `host_discovery` is granted. With any L2 capability: `--privileged --send-eth -e <interface>`. Never `--send-ip`.

### 4. Never allowed
- Public IP addresses.
- Free-form Nmap arguments, target files (`-iL`), user-typed `--script-args`.
- NSE categories `brute`, `dos`, `exploit`, `intrusive`, `malware`, `fuzzer`, `external` (sends data to Internet services) and `broadcast` (reaches the whole segment, beyond the target list). Scripts are allowlisted one by one, pinned by hash.
- Running Nmap as root.

### 5. Privileges
Raw packets go through the `calm_bpf` group's read/write access to `/dev/bpf*`. No root helper. Write access is now a deliberate requirement (see the ADR-005 revision).

### 6. During a run
Calm kills Nmap's whole process group (SIGTERM, then SIGKILL) on Stop everything, a network change, or a scope revoked or expired. Targets and ports without a result are recorded as Not tested.

### 7. Evidence
The XML is sealed in the encrypted session (ADR-009) with the Nmap version and the exact command line. Audit events carry ids only. An open or closed port is **observed**; service names, OS guesses and NSE output are **inferred**. No pass from silence (unchanged).

### 8. Wording follows the capabilities
UI text that describes what is sent is chosen from the enabled capabilities. "Nothing is sent over the connection" stays true only with `tcp_connect` alone.

## Reasons
- Owners can still picture the scope: it is enumerable (addresses, ranges, exclusions, capabilities, time, rate).
- Authorizing the whole plan keeps deny-by-default where per-probe checks are impossible.
- No root: the spike showed root adds nothing for scans on the local segment, while running Nmap and its Lua engine as root would turn any bug into root access.

## Consequences & trade-offs
- The last line of defence is the correctness of the command builder; its tests are mutation-checked like the decision table.
- Nmap packets are not re-checked one by one. Network changes are caught by the run monitor within its polling interval, not before each packet.
- `calm_bpf` write access lets any process of the user inject packets; a narrower SMAppService helper is still needed before a public release.
- ADR-004 planned Nmap as a signed JSON-RPC plugin (M4). It ships first as a built-in adapter (`calm-nmap` crate) and moves behind the plugin contract later.

## Alternatives considered
- Root helper running Nmap: rejected (risk, no extra information for this use).
- Free-form arguments or a manual Nmap mode: not now; it would break every guarantee a scoped finding gives.
- Import Nmap XML only: kept as an extra input; not enough for N04.

## Validation / revisit trigger
- Implemented (first step, 2026-11-01): `calm_domain::Capability` and the new `Scope` fields (older scopes read as TCP connect only); `approve` rules for capabilities, ranges, exclusions and scripts; `calm_orchestrator::authorize_plan` and `PlanGrant`; `authorize` now requires `tcp_connect`; crate `calm-nmap` (`build_args`, `runner::run` with process-group stop).
- Tests: `orchestrator::plan` (11), new `scope` rules (9), `calm-nmap` command and runner (9), and the out-of-scope suite: all 128 capability subsets × 9 plan shapes, run against a fake `nmap`, arguments checked by rules independent of the builder. Mutation-checked: dropping `-n`, `-Pn`, `--exclude`, adding `-O`, using `--send-ip`, killing only the Nmap process, and removing each `authorize_plan` rule all fail a test.
- Scope form (2026-11-01): capabilities grouped by impact, each saying what it sends; ranges with their ports; exclusions (required with a range); allowlisted NSE scripts; the approval sentence names the capabilities ticked; the scope card shows them. The browser preview mirrors the new `approve` rules and the `tcp_connect` requirement. The form offers this network's router and range as one-tap suggestions (never filled in silently: the scope is an attestation), uses real addresses as placeholders, and flags any target or range outside the Mac's subnet as it is typed.
- Next: Nmap XML into findings (N04, services); bundling (ADR-012).
- Spikes still open: targets outside the subnet with `--send-eth`, IPv6, repeat of the connect-vs-SYN discrepancy (spike F6).
- Revisit when plugins (M4) need grants.
