# rules

Versioned, deterministic checks (W01–W03, N01–N05, S01–S02). Rules decide finding status; AI never does (ADR-006).
Each rule declares: prerequisites, test level, authorized target type, evidence produced, limitations, and the status it emits when prerequisites are missing (`not_tested` / `inconclusive`, never `pass`).
