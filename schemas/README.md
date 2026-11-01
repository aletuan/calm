# schemas

Versioned JSON Schema (draft 2020-12) for the canonical model. Schema-first: change here and in `crates/domain` together.

| File | Mirrors |
|---|---|
| `common.v1.schema.json` | `semantics.rs` enums |
| `finding.v1.schema.json` | `Finding` |
| `topology-edge.v1.schema.json` | `TopologyEdge` |
| `evidence.v1.schema.json` | `Evidence` + `Lineage` |

Pending (WP2): session, scope, asset, service, flow, plugin-execution, explanation, plugin manifest.
`$id` uses `calm.aletuan.com` as a stable namespace; it does not need to resolve.
