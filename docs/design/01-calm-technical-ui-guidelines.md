# Calm Technical UI — Visual & Interaction Guidelines

**Status:** Proposed baseline for UI V2 | **Date:** 2026-10-31 | **Scope:** macOS WiFi Security Auditor, all screens.

## 1. Intent and principles
Previous dark cybersecurity dashboard mockups were too saturated and dense. V2 MUST shift from a neon SOC dashboard aesthetic toward **Calm Technical UI**: quiet, legible, evidence-first and comfortable for prolonged engineering work. Preserve technical depth without displaying everything simultaneously. Visual inspiration: Minimal Dark + Quiet Observability with native macOS conventions; not a clone of any product.

### Governing principles
1. **One Primary Focus:** each screen has one dominant working surface, e.g. network graph, time-series, or finding list.
2. **Quiet by Default:** inactive/normal states remain mostly neutral; bright accents are earned by importance.
3. **Details on Demand:** progressive disclosure via selection, tabs, popover or collapsible inspector; avoid permanent multi-panel overload.
4. **Semantic Color:** reserve saturated red/amber/green for meaningful severity/state. No brightly colored device icon solely to decorate.
5. **Comfortable Density:** comfortable mode default; compact density optional for expert users.
6. **Evidence Integrity:** observed vs inferred vs unverified MUST remain visible by label + edge treatment, never by color alone.
7. **Context Preservation:** selecting asset/flow/finding and time window survives switching among topology, traffic and findings.
8. **Explain Anywhere:** context-sensitive explanation and evidence links at node/edge/flow/finding without losing current context.

## 2. Design tokens (initial proposal)

| Token | Hex | Usage |
|---|---|---|
| `color.bg.canvas` | `#14191E` | Main background |
| `color.bg.surface` | `#20272D` | Inspector, grouped surfaces |
| `color.bg.elevated` | `#2C353D` | Active control/popover |
| `color.accent.primary` | `#82A6AF` | Selection, principal action; subdued teal |
| `color.text.primary` | `#E5E9E8` | Primary content |
| `color.text.secondary` | `#929EA3` | Hints, metadata |
| `color.semantic.warning` | `#D2A66B` | Warning |
| `color.semantic.critical` | `#CB7775` | High/critical risk |
| `color.semantic.success` | `#79A995` | Confirmed success |

- Aim for approximately **90% neutral visual area** and <=10% accent/semantic emphasis, as a design heuristic rather than a hard pixel-level test.
- Avoid glow, gradients, intense icon tiles, and saturated chart fills. Prefer low-opacity strokes and calm line graphs.
- Borders only where needed to convey grouping; group by spacing first. Use neutral separators rather than boxes around every metric.
- Text and controls MUST meet WCAG 2.2 AA contrast targets (normal text >=4.5:1; large text >=3:1; relevant non-text UI >=3:1). Proposed palette requires checking final foreground/background pairings; hex values are not automatic accessibility compliance.

## 3. Typography and spacing
- Prefer macOS SF Pro, then Inter/system fallback; no gratuitous font-size variation.
- Screen heading 22–26px; section heading 16–18px; body 13–14px minimum (14px preferred); metadata 12–13px where legible; monospace for IP, ports, hashes, timestamps and packet fields.
- 8px base spacing grid. Working-area padding 20–24px. Standard table row height 40–44px in Comfortable; optionally 32–36px in Compact.
- Strong hierarchy from font weight/spacing before color. Keep numeric alignment tabular and consistent.

### Spacing roles (implemented in `apps/desktop/src/styles/tokens.css`)
Components use these roles, never raw pixel values. Each role answers "how related are these two things?":

| Token | Value (Comfortable) | Between |
|---|---|---|
| `--gap-tight` | 4px | a title and its own subtitle; a label and its control; a control and its hint |
| `--gap-related` | 8px | items of one group: chips in a toolbar, list items, a hint and the group it explains |
| `--gap-field` | 12px | fields or lines of one form (target rows, binding line, confirmation line) |
| `--gap-block` | 16px | blocks inside a section: text → table, toolbar → table, actions → the next block |
| `--gap-section` | 32px (24px Compact) | sections and numbered steps |

Controls: every text field, select and primary button is `--control-height` (32px; 28px Compact); chips are `--control-height-sm` (28px). Selects are drawn with `appearance: none` because WebKit ignores height and padding on native selects.

Rules: a row of action buttons (`.form-actions`) always sits one `--gap-block` away from what is above and below. Blocks inside the scrolling main column must not shrink (`flex-shrink: 0`), or WebKit collapses scroll containers such as tab bars to zero height.

## 4. Information-density controls

| Old UI pattern | V2 pattern |
|---|---|
| 5–6 large KPI tiles | Single subdued text summary row; only 2–3 meaningful metrics |
| Every section enclosed in a bordered card | Open layout, subtle dividers, purposeful sections |
| Always-on traffic charts and donut charts | Conditional `Traffic overlay` and secondary analysis view |
| Oversized detail panel always displayed | Inspector closed by default, opens upon selection; resizable |
| Repeated colored severity badges | Text labels with restrained semantic markers only on significant items |
| Large tables, alerts and graph simultaneously | Primary surface + on-demand drill-down |
| Bright colored icons for every device | Neutral outline icons; semantic color only for actual status |

- Show summary first; reveal details through filters, selection, tabs, and progressive inspection.
- Default to 1 primary visualization plus at most one secondary contextual panel.
- Empty/inconclusive states MUST be explanatory, not visual blanks or implicit success.
- Advanced filters and raw data live behind `Filters`, `Details` or `Raw evidence`, not permanently expanded.

## 5. Network Topology V2 screen contract
**Primary surface:** spacious logical evidence-based graph. **Secondary surface:** asset inspector, hidden until a node is selected. **Auxiliary:** optional traffic/security overlays, both off by default.

### Layout
- Slim macOS navigation sidebar with monochrome icons; only selected nav item gets accent.
- Quiet title + connected Guest Wi-Fi context, then terse inline summary: observed assets / observed flows / findings.
- Large graph canvas (roughly 65–80% main width when inspector closed), no wall of charts underneath.
- Context toolbar: `Search`, `Layout`, `Observed/Inferred/Unverified`, `Show traffic`, `Show findings`, `Time window`.
- When user selects a node, right inspector appears with `Overview`, `Services`, `Traffic`, `Findings`, `Evidence`, `Explain`; otherwise canvas has full width.
- Device class conveyed by restrained shape/icon; observed relation = solid, inferred = dashed, unverified = dotted/unknown; explanation available for each edge.
- A single subdued warning marker can highlight an important finding; no red glowing node/large risk halos.
- Legend collapsible; prefer short label plus tooltip; avoid drawing unsupported physical infrastructure.

### Interaction states
1. Default calm map: minimal labels, no overlays, no inspector.
2. Hover/focus: subtle border and tooltip with name/IP, observed status, evidence count.
3. Select node: selected outline and right inspector, relevant edges emphasized; other graph remains visible.
4. Toggle traffic: show flows observed by **this laptop** only, with source/scope note; temporal controls appear.
5. Toggle findings: overlay verified or candidate severity markers with tooltip; separate severity from confidence.
6. `Explain this`: describe what node/edge is, why present, provenance, uncertainty and remediation.
7. Keyboard navigation, visible focus rings, zoom/pan/reset; respect Reduce Motion; no animations that obscure packet evidence.

## 6. Data truthfulness and semantics
- This is a **macOS laptop on an authorized Guest Wi-Fi**, no router/AP admin, no mirror port. Never imply visibility over all LAN/WLAN traffic or complete physical topology.
- `Observed`: directly measured traffic/network facts; `Validated`: confirmed by an authorized bounded test (rendered like Observed); `Inferred`: reasonable interpretation with provenance and confidence; `Unverified`: unknown or unsupported. Keep statuses independent from health/severity.
- Do not claim gateway == AP or DNS == an internal asset unless confirmed.
- Device image, vendor, firmware, CVE and score remain unknown when source data is inadequate.
- Traffic graph denotes local interface observation; imported remote capture must carry explicit provenance.
- All illustrated data in prototypes marked `Demo / sample data`.

## 7. System-wide patterns
- Dashboard: summary and top 3 actionable issues; advanced analytics in dedicated screens.
- Vulnerabilities: findings table is primary; inspector is opt-in; confidence, verification, CVE association are distinct fields.
- Traffic: time-series primary; protocol and flow details via tabs/selection; avoid charts with many competing colors.
- Assessment: stage-based wizard; show only active task and essential logs; full logs on demand.
- Extensions: list-first; only selected plugin reveals detailed permissions/trust metadata.
- Assistant: default concise explanation, reveal deeper protocol/evidence breakdown when requested.
- Reports: readable document preview primary, selection/build options collapsible.

## 8. Implementation acceptance criteria
- No screen defaults to more than one dominant data visualization plus one optional inspector.
- Semantic red/amber/green never used as decoration; risk state also present in text/icon.
- Topology makes observed/inferred/unverified distinguishable without relying on hue.
- New users can identify network identity, observed scope, most important finding and next action within ~10 seconds in usability testing (validation target, not measured claim).
- Comfortable/Compact density can be toggled without breaking layout, and default is Comfortable.
- Standard full-HD and MacBook-width layouts remain legible; right inspector can be dismissed/resized.
- Accessibility checklist covers contrast, keyboard, focus, semantics, Reduce Motion and readable charts.
- Context survives Topology -> Device -> Traffic -> Findings -> Back navigation.

## 9. Non-goals
- Do not remove security details or hide critical risk without accessible escalation.
- Do not use minimalism to conceal evidence, permissions or assessment scope.
- Do not present synthetic physical network links as observed.

## 10. V2 review checklist
Before approving each screen: Is the primary task obvious? Can any panel be removed or collapsed? Does every color have meaning? Is each conclusion evidence-backed? Can the user inspect a finding without losing context? Does the current viewpoint's visibility limit remain obvious?
