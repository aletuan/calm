/** Columns of the flow table, in display order. The viewer may hide any but the last one. */
export const FLOW_COLUMNS = ["proto", "purpose", "remote", "local", "direction", "packets", "bytes", "last"] as const;
export type FlowColumn = (typeof FLOW_COLUMNS)[number];

export function visibleColumns(hidden: readonly FlowColumn[]): FlowColumn[] {
  return FLOW_COLUMNS.filter((c) => !hidden.includes(c));
}

export function toggleColumn(hidden: readonly FlowColumn[], c: FlowColumn): FlowColumn[] {
  if (hidden.includes(c)) return hidden.filter((x) => x !== c);
  const next = [...hidden, c];
  return visibleColumns(next).length === 0 ? [...hidden] : FLOW_COLUMNS.filter((x) => next.includes(x));
}

/** Stored choice → hidden columns; anything unexpected means "show all". */
export function parseHidden(raw: string | null): FlowColumn[] {
  if (!raw) return [];
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(v)) return [];
  const hidden = FLOW_COLUMNS.filter((c) => v.includes(c));
  return visibleColumns(hidden).length === 0 ? [] : hidden;
}
