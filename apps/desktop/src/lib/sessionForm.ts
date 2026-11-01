import type { SessionInput } from "./ipc";

export const RETENTION_CHOICES = ["7", "30", "90", "keep"] as const;
export type Retention = (typeof RETENTION_CHOICES)[number];

export interface SessionForm {
  name: string;
  site: string;
  operator: string;
  authorization_ref: string;
  notes: string;
  retention: string;
}

export type FormError = "name_required" | "name_too_long" | "field_too_long" | "notes_too_long" | "retention_invalid";

export const emptyForm = (): SessionForm => ({
  name: "",
  site: "",
  operator: "",
  authorization_ref: "",
  notes: "",
  retention: "30",
});

const MAX = { name: 120, field: 200, notes: 2000 };

/** Validates and normalises the new-session form (trimmed, bounded). */
export function parseSessionForm(f: SessionForm): { ok: true; input: SessionInput } | { ok: false; errors: FormError[] } {
  const v = {
    name: f.name.trim(),
    site: f.site.trim(),
    operator: f.operator.trim(),
    authorization_ref: f.authorization_ref.trim(),
    notes: f.notes.trim(),
  };
  const errors: FormError[] = [];
  if (!v.name) errors.push("name_required");
  if (v.name.length > MAX.name) errors.push("name_too_long");
  if ([v.site, v.operator, v.authorization_ref].some((x) => x.length > MAX.field)) errors.push("field_too_long");
  if (v.notes.length > MAX.notes) errors.push("notes_too_long");
  if (!(RETENTION_CHOICES as readonly string[]).includes(f.retention)) errors.push("retention_invalid");
  if (errors.length) return { ok: false, errors };
  return { ok: true, input: { meta: v, retention_days: f.retention === "keep" ? null : Number(f.retention) } };
}
