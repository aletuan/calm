# CLAUDE.md: development rules for Calm

These rules apply to every change, whether a person or a coding agent makes it. Read `README.md` for what Calm is. When a rule here conflicts with older text elsewhere, the ADRs in `docs/architecture/adr/` win, then this file.

## 1. Non-negotiable invariants

Never trade these for speed or convenience.

1. **Claim only what was observed or validated.** Everything else is `inferred`, `unverified`, `inconclusive` or `not_tested`. Silence is never a `pass` unless the user confirmed the listener was running (AT-07). A reachable port never means a login is possible (AT-08).
2. **Passive by default; active only by scope.** Nothing leaves the Mac towards a target unless:
   - a scope was approved, is unexpired and unrevoked, and is bound to the current network;
   - and, for Calm's own probes, `calm_orchestrator::authorize` allowed that exact address, port and capability just before sending;
   - or, for an Nmap run, `calm_orchestrator::authorize_plan` allowed the whole plan (every target, range, port, capability and script), and `calm_nmap` built the command from that `PlanGrant` alone (ADR-011).

   These are the only two paths that send. Do not add a third. Never pass user-typed text to Nmap, and never run it as root.
3. **Deny by default.** New checks, adapters and plugins get a `Grant` or `PlanGrant` from the scope engine or they do not run. A scope allows only the capabilities the owner ticked. Unknown network ⇒ deny. Store error ⇒ treat the scope as revoked.
4. **Privacy.**
   - Capture headers only (snaplen 96) and keep them in memory.
   - Never store packet payloads or the imported file itself (store only its SHA-256).
   - Everything that describes a network is sealed in the encrypted store.
   - Audit events carry ids, never IP addresses.
5. **Status, severity and confidence are independent fields.** Do not derive one from another. `Not tested` has no confidence (`None`).
6. **Secrets.** Never commit keys, certificates, `.p8` files or tokens. They live outside the repo, in `~/.private_keys`.
7. **Real network data stays local.**
   - Fixtures use documentation ranges only (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32).
   - Screenshots or docs that leave the machine have SSIDs and real IPs masked.

## 2. Workflow: test-driven, small steps

1. **Red.** Write a failing test that states the behaviour in its name (`a_stop_before_the_run_sends_nothing`, `silence_without_a_receiver_is_inconclusive`).
2. **Green.** Write the simplest code that passes.
3. **Refactor.** Clean up while every test stays green, then run `pnpm check`.

- One behaviour per test. Prefer table-driven tests for decision tables, with every row covered.
- **Mutation check for rules.** After a rule is green, break it on purpose (flip a comparison, drop a branch) and confirm a test fails. If none fails, the test is missing.
- Bug fix = first a test that reproduces the bug, then the fix. Keep the test.
- Tests must be deterministic. Inject time (`Clock`), network (`Connector`) and storage. No sleeps, no real network in unit tests.

## 3. Design principles (SOLID, applied here)

- **Single responsibility.** One reason to change per unit:
  - **crates** hold domain logic and know nothing about UI or Tauri;
  - **`src-tauri`** wires commands, state and threads, with no business rules;
  - **`src/lib`** holds UI decisions as pure, tested functions;
  - **`src/screens`** render and call `src/lib`.
  
  If a component computes something, move the computation to `src/lib`.
- **Open/closed.** Extend by adding data, not flags.
  - A new check is a new `CheckId`, a row in the decision table, i18n keys and tests.
  - Do not add `if special_case` parameters to existing functions.
- **Liskov substitution.** Every implementation of a trait (`Connector`, `Clock`, key provider) keeps the same contract. Test fakes must behave like the real thing (same errors, same ordering).
- **Interface segregation.** Small traits and narrow props. Pass a function `authorize(req)` rather than the whole store. Pass `ScopeView` rather than global state.
- **Dependency inversion.** Core logic depends on traits that are injected (clock, connector, store, network reader), never directly on OS calls. That injection is what makes it testable.

Also:
- **KISS.** The simplest design that satisfies the invariants.
- **YAGNI.** No speculative options.
- **DRY with judgment.** Extract on the third repetition, not the second.

## 4. Code clarity

- **Names say what, comments say why.** A comment explains a reason, a constraint or a reference (ADR, AT-xx), never a restatement of the code. Every module starts with a short doc comment stating its purpose.
- **Make invalid states unrepresentable.**
  - Use enums over strings and booleans.
  - Use private fields with constructors for safety tokens (`Grant`).
  - Use `Option` for "not known".
- **Errors are typed.** Use `thiserror` enums in Rust and discriminated unions (`{ kind: ... }`) in TS. No `unwrap`/`expect` outside tests unless an invariant guarantees it; then add a comment saying which.
- **Small functions, early returns, no deep nesting.** If a function needs a section comment, split it.
- **Stored data stays readable.** New fields on persisted types get `#[serde(default)]` (or `Option`) plus a test that an older JSON still deserializes.
- **Rust:**
  - `unsafe_code = "forbid"` (workspace lint);
  - clippy with `-D warnings` on Linux and the `aarch64-apple-darwin` target;
  - `rustfmt` defaults.
- **TypeScript:**
  - `strict`, `noUncheckedIndexedAccess`, no `any`;
  - types mirror the Rust structs (`src/lib/assess.ts` ↔ `calm_orchestrator`, `calm_domain`).
- **Browser preview mirrors.** `src/lib/demo*.ts` port Rust rules (address policy, decision table, subnet check) for the browser preview. Change both sides together and keep the mirrored tests in step.

## 5. UI rules

- **Every user-facing string goes through i18n.**
  - `en.ts` is the source and `vi.ts` must have every key (a test enforces it).
  - Keys built at runtime are listed in `i18n.test.ts`.
  - Text that depends on where the Mac stands uses the `{from}` placeholder with `fromText()`; never hard-code "Guest Wi-Fi".
  - Wording follows `docs/design/02-voice-and-terminology.md`: one calm voice, "you"/"bạn", sentence case, the patterns per kind of text, and the EN/VI term list. The "voice rules" tests in `i18n.test.ts` enforce the mechanical part.
- **Design tokens only.** Do not use raw colors or pixel spacing in components. Use the spacing roles in `tokens.css`:
  - `--gap-tight` 4px · `--gap-related` 8px · `--gap-field` 12px · `--gap-block` 16px · `--gap-section` 32px;
  - `--control-height` for inputs, selects and primary buttons; `--control-height-sm` for chips.
- **WebKit is the target, not Chromium.**
  - Selects are drawn with `appearance: none`, because WebKit ignores height on native selects.
  - Blocks inside the scrolling `.main` column need `flex-shrink: 0`, or scroll containers (tables, tab bars) collapse.
  - Check with a long page, not only an empty one.
- **Explain, never imply success.** Empty states say why they are empty and what to do. Not-tested items are shown, not hidden.
- **Accessibility.**
  - State is never shown by color alone.
  - Use real `button` elements, `role="tab"` with `aria-selected`, and `aria-live` for progress.
  - Keep keyboard focus visible.

## 6. Commands

```sh
pnpm check                         # the gate: typecheck + vitest + fmt + clippy + cargo test
pnpm test                          # tests only
cargo test -p calm-orchestrator    # one crate
pnpm --filter @calm/desktop test -- src/lib/journey.test.ts   # one UI test file
pnpm web:dev                       # browser preview with simulated data
pnpm dev:bundle                    # signed debug app (Wi-Fi identity needs it)
cargo test -p calm-store -- --ignored keychain   # real Keychain, Mac only
```

## 7. Definition of done

- [ ] Behaviour is covered by tests written first; rule changes pass a mutation check.
- [ ] `pnpm check` is green; clippy is clean for macOS too when platform code changed.
- [ ] Invariants in §1 still hold. Anything that sends, stores or displays network data was reviewed against them.
- [ ] Strings exist in EN and VI. The UI was checked in the browser preview, with a long page as well as an empty one.
- [ ] Docs updated where behaviour or a decision changed: an ADR (or a revision section) for decisions, the README status table for milestones.
- [ ] Persisted types stay backward compatible.

## 8. Working agreements

- **Commits and pushes are made by the maintainer.** Agents prepare changes and propose a commit message; they do not commit, push, revoke certificates or delete keys.
- Prefer one clarifying question at a time. When working unattended, take the safest reading and say which one you took.
- Do not delete files, sessions or scopes the user did not ask to delete.
- Big or irreversible changes (schema, bundle ID, crypto, scope rules) need an ADR first.
